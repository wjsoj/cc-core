# quotaestimate —— 订阅窗口额度反推

> [← Wiki 首页](Home) · [auth 调度与健康](Auth-Pool) · [requestlog](Requestlog)

> 本页对应 `github.com/wjsoj/cc-core` 的 `quotaestimate/` 包，以及 `auth/types.go` 里为它增加的 `Auth.LastQuotaHit`。标识符一律保留英文。

## 要回答的问题

Anthropic 的订阅账号有 5h 和 7d 两个额度窗口。`api/oauth/usage` 会告诉你窗口**用了百分之几**、**什么时候重置**，但从不说 100% 是多少。运维真正想知道的是"这个 Max 账号一周能跑掉多少钱的 API 等价用量"——这个数只能从我们自己的账本反推。

反推依据两个事实：

1. **窗口是固定的，不是滚动的**。账号在窗口内第一次请求时窗口打开，恰好 `Length` 后关闭，`resets_at` 就是关闭时刻。所以窗口起点 = `resets_at − Length`，不需要知道账号那一周第一次开口是什么时候。
2. **账本有时间戳**。`requestlog` 里这个凭据在 `[起点, 现在]` 之间的行，就是产生了上游所报 utilization 的那部分消费。

于是：

```
full window ≈ observed spend / utilization
```

最干净的测量是**被拒绝那一刻**：上游在时刻 T 返回 usage-limit 429，那么 `[resets_at − Length, T]` 内的消费**按定义**就是 100% 的额度，无需按百分比放大。这就是这个功能最初被描述的场景：已经 quota 了 2 小时、显示 reset in 106h、窗口是 168h，所以账号在满额前跑了 60h，这 60h 的账本行就是整周额度（`quotaestimate_test.go` `TestProjectQuotaHitMeasuresTheWholeWindow`）。utilization 路径是同一套算术、分母小于 1，它对从未被拒绝过的凭据也成立。

## 数据流

```
proxy 收到 usage-limit 429
  Anthropic：unified-ratelimit rejected / "Claude AI usage limit reached|ts"
  Codex：   {"error":{"type":"usage_limit_reached","resets_at":…}}
            （{"detail":"Rate limit exceeded"} 是每账号请求频率限制，不是测量，不记）
  └─ a.MarkUsageLimitReached(resetAt)        auth/types.go
       ├─ QuotaExceededAt / QuotaResetAt      （冷却，过期即清空——routing 用）
       ├─ LastQuotaHit{At, ResetAt}           （测量，过期/手动清除都不清——本包用）
       └─ go saveAuth(a)                      （落盘到凭据文件 last_quota_hit，重启不丢）

fork 的 anthropic-usage 接口
  ├─ fetch api/oauth/usage → body
  └─ quotaestimate.ForCredential(body, info.LastQuotaHit, RequestLogSpend(dir, id), now)
       ├─ FromUsageBody(body)   → []Window   五小时 / 七天，各带 resets_at + utilization
       │    （body 为空时退回 FromHit(hit)：只凭上次拒绝重建窗口）
       └─ Project(w, hit, spend, now) → Estimate

fork 的 codex-usage 接口
  ├─ a.FetchCodexUsage → *CodexUsageInfo（wham/usage）
  └─ quotaestimate.ForCodexCredential(info, hit, spend, now)
       └─ FromCodexUsage(info, now) → []Window  primary / secondary，长度取自 limit_window_seconds
            （ChatGPT 2026-07 起 primary 已是 7 天，长度只信 payload，不假设）
```

窗口模型在生产上得到过逐秒级验证：codex-627466459 于 2026-09-02 15:37 收到 `usage_limit_reached`，`resets_in_seconds = 413590`，倒推的窗口起点 2026-08-31 10:30:11，而账本里该凭据在本窗口的第一条请求恰是 10:30:11.095。

`Project` 的规则（`quotaestimate.go`）：

| 情形 | Basis | Utilization | ObservedTo | Confidence |
|---|---|---|---|---|
| `hit` 落在窗口内且 `hit.ResetAt` 与窗口 `resets_at` 相差 ≤ 5 分钟 | `quota_hit` | 强制 1 | `hit.At` | `high` |
| 上游 utilization > 0 | `utilization` | 上报值 | `now`（不超过 `resets_at`） | ≥25% 且观测 ≥1h → `medium`，否则 `low` |
| utilization = 0 / 账本读取失败 | `observed_only` | — | — | `low`，只报 Observed，不投影 |

`FullWindow = Observed / Utilization`，`Remaining = FullWindow − Observed`（窗口已满时为 nil）。`Spend` 同时给 USD（目录价 `Record.CostUSD`）和加权 token（`usage.Counts.WeightedTotal / 100`，即 input-equivalent），两者和负载均衡、定价共用同一套 1/1.25/0.1/5 权重。

## 三个不能省的判断

- **hit 必须命名同一个窗口才能当锚**（`hitAnchors`）。7d 窗口期间发生的一次 5h 拒绝，测的是 5h 窗口而不是 7d；上一周的拒绝哪怕是最近一次，也不是本周的测量。判断依据是 reset 戳是否一致（±5 分钟吸收 header 秒级取整 vs body 原始戳），不是"最近一次"。
- **同一窗口只取第一次拒绝**（`auth.MarkUsageLimitReached` + `sameQuotaWindow`）。凭据被停后一次误入的在途请求、或运维点了"clear quota"后下一次弹回，都会给同一个窗口打第二个 429；取后者会把观测跨度缩短。同一窗口 == reset 戳相差 ≤1 分钟。
- **`LastQuotaHit` 不进 routing，但会落盘**。`MarkUsageLimitReached` 记录后异步 `saveAuth`，写进凭据文件的 `last_quota_hit`（append-only 字段，老文件读作"从未满额"，坏值忽略），重启后 `parseFile` 读回。它是测量而非冷却：读回的凭据**不会**因此被停用。这个数是运维事后才来看的，所以进程内存不够。

## 估算不是什么

- **只算经过本代理的流量**。同一账号如果还在别处用，上游的 utilization 包含我们没见过的消费，投影是**下限**而非额度。
- **用我们的目录价计价**，不是上游自己的计量单位（未公开）。这正是运维要的单位，但不要拿它和 Anthropic 官方的"消息数"对表。
- **不是 routing 输入，不碰健康状态**。探针失败与账本错误都只体现在 `Estimate.SpendError` 上。

## `HitCache`

凭据列表每次轮询都要给每个 Anthropic OAuth 行一个"上次满额时的周额度"，而这个数在拒绝发生 10 分钟后就不会再变（`settleAfter`：在途请求在 429 之后才结束、才写账本，行的时间戳却在 hit 之前）。`HitCache.Weekly(authID, hit, spend, now)` 按 `(authID, hit.At)` 缓存已沉降的估算，未沉降的每次重算，账本读取失败的不缓存。只服务 7d 窗口的 hit——5h 的拒绝不是周额度测量。

## `History`：最近几次满额的持久记录

运维要的是"最近几次 100% 周限额各跑了多少钱"，不是当前投影。`History`（`history.go`）按凭据保留最近 `keep` 条（默认 8）**已沉降的拒绝锚定**测量 `Measurement{Window, WindowStart, ResetAt, HitAt, ObservedHours, Spend}`，写到 fork 指定的 JSON 文件（原子写；坏文件报错而不是静默清空——它存在的意义就是不丢这条记录）。`Record` 只接受 `Basis == quota_hit` 且无账本错误的估算，同一窗口（reset 戳 ±1 分钟）覆盖而不重复；`For` 返回最新在前的副本。fork 在列表轮询里由 `HitCache.Weekly` 得到估算、满 10 分钟后 `Record`，所以凭据文件里持久化的 `last_quota_hit` 重启后会自动补进历史。

## `HealthReport.UsageLimit`：限流冷却 ≠ 配额耗尽

`ReportUpstreamError` 的 429/401/403 冷却和真正的 usage-limit 都走 `MarkQuotaExceeded` 同一组字段，所以 `HealthQuota` 状态本身分不出"30 秒限流暂停"和"这周额度跑完了"——生产上两个 wham/usage 报 `limit_reached:false`、用量 11%/13% 的号曾被面板标成"配额耗尽"。`HealthReport.UsageLimit`（`AuthInfo.QuotaUsageLimit`）在 `State == quota` 时为真当且仅当当前 `QuotaResetAt` 与 `LastQuotaHit.ResetAt` 是同一窗口；手动清除后再次弹回同一窗口仍算 usage-limit。面板据此分两种徽章（`TestQuotaStateDistinguishesUsageLimitFromThrottlePause`）。

## 消费方

| fork | 接口 | 展示 |
|---|---|---|
| CPA-Claude | `POST /admin/api/auths/:id/anthropic-usage` 与 `/codex-usage` → `allotment_estimates[]`；`GET /admin/api/summary` 的 `weekly_allotment`（两种 OAuth 都有） | `upstream-quota.tsx` 两个面板窗口表下方的估算块；`auth-card.tsx` 的"Weekly allotment · measured"行 |
| hypitoken | `POST /admin/credentials/:id/anthropic-usage` 与 `/codex-usage` → `allotment_estimates[]`；凭据列表的 `weekly_allotment` | `upstream-usage-dialog.tsx` 两个 body；`credential-card.tsx` |

fork 侧记录 Codex 满额的位置是 `codex_oauth_proxy.go` 的 429 分支：仅当 body 是 `usage_limit_reached`（`isCodexUsageLimitBody`）且带 reset 才调 `MarkUsageLimitReached`，然后照旧 `ReportUpstreamError`。WS 握手路径的 429 拿不到 body，暂不记录。

## 规则 → 测试

| 规则 | 测试 |
|---|---|
| 拒绝锚定：观测到 `hit.At` 而非 now，不放大，Remaining 为 nil | `TestProjectQuotaHitMeasuresTheWholeWindow` |
| utilization 放大与 Remaining | `TestProjectUtilizationScalesUp` |
| 低 utilization 仍投影但标 low | `TestProjectLowUtilizationIsLowConfidence` |
| utilization 0 / 账本失败 → observed_only | `TestProjectZeroUtilizationIsObservedOnly`、`TestProjectLedgerErrorIsReportedNotFatal` |
| 5h 拒绝不锚 7d；上周拒绝不锚本周 | `TestHitForAnotherWindowDoesNotAnchor`、`TestStaleHitOutsideWindowDoesNotAnchor` |
| 观测跨度永不为负、不超过 reset | `TestProjectClampsObservedSpan` |
| 0..1 与 0..100 两种编码 | `TestNormalizeUtilization` |
| 无探针时凭 hit 重建窗口长度 | `TestFromHitInfersWindowLength`、`TestForCredentialFallsBackToHitWhenProbeIsEmpty` |
| 顶层窗口优先于 `limits[]`；无 `resets_at` 的窗口丢弃 | `TestFromUsageBodyTopLevelWindows`、`TestFromUsageBodyLimitsFallback`、`TestFromUsageBodyDropsWindowsWithoutReset` |
| 账本只读窗口内、只读本凭据、忽略 attempt_only | `TestRequestLogSpendReadsOnlyTheWindow` |
| `LastQuotaHit` 不随过期/清除消失；同窗口取首拒；通用冷却不算 hit | `auth/quota_hit_test.go` |
| `LastQuotaHit` 落盘并在三种凭据文件上读回；老文件读作未满额；坏值忽略 | `auth/quota_hit_persist_test.go` |
| `History` 只记 quota_hit、同窗口覆盖、保留 keep 条、重启读回、坏文件报错 | `TestHistoryRecordsOnlySettledHitsAndPersists` |
| `UsageLimit` 区分限流冷却与配额耗尽 | `auth/quota_hit_test.go` `TestQuotaStateDistinguishesUsageLimitFromThrottlePause` |
| Codex 窗口长度取自 payload；仅凭 `usage_limit_reached` 的 hit 也能重建周窗口 | `TestFromCodexUsageReadsLengthFromThePayload`、`TestForCodexCredentialAnchorsOnUsageLimitHit` |
| 缓存沉降与失效 | `TestHitCacheServesWeeklyAndSettles`、`TestHitCacheDoesNotCacheLedgerErrors` |
