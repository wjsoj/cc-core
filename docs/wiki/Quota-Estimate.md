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
  └─ a.MarkUsageLimitReached(resetAt)        auth/types.go
       ├─ QuotaExceededAt / QuotaResetAt      （冷却，过期即清空——routing 用）
       └─ LastQuotaHit{At, ResetAt}           （测量，过期/手动清除都不清——本包用）

fork 的 anthropic-usage 接口
  ├─ fetch api/oauth/usage → body
  └─ quotaestimate.ForCredential(body, info.LastQuotaHit, RequestLogSpend(dir, id), now)
       ├─ FromUsageBody(body)   → []Window   五小时 / 七天，各带 resets_at + utilization
       │    （body 为空时退回 FromHit(hit)：只凭上次拒绝重建窗口）
       └─ Project(w, hit, spend, now) → Estimate
```

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
- **`LastQuotaHit` 不进 routing，也不落盘**。它只在内存里；重启即忘。这不影响主路径：活探针路径靠 utilization + `resets_at` 就能算，被拒绝的凭据探针会报 100%，得到的就是同一个数。只有"探针也失败、又重启过"才无法给出估算。

## 估算不是什么

- **只算经过本代理的流量**。同一账号如果还在别处用，上游的 utilization 包含我们没见过的消费，投影是**下限**而非额度。
- **用我们的目录价计价**，不是上游自己的计量单位（未公开）。这正是运维要的单位，但不要拿它和 Anthropic 官方的"消息数"对表。
- **不是 routing 输入，不碰健康状态**。探针失败与账本错误都只体现在 `Estimate.SpendError` 上。

## `HitCache`

凭据列表每次轮询都要给每个 Anthropic OAuth 行一个"上次满额时的周额度"，而这个数在拒绝发生 10 分钟后就不会再变（`settleAfter`：在途请求在 429 之后才结束、才写账本，行的时间戳却在 hit 之前）。`HitCache.Weekly(authID, hit, spend, now)` 按 `(authID, hit.At)` 缓存已沉降的估算，未沉降的每次重算，账本读取失败的不缓存。只服务 7d 窗口的 hit——5h 的拒绝不是周额度测量。

## 消费方

| fork | 接口 | 展示 |
|---|---|---|
| CPA-Claude | `POST /admin/api/auths/:id/anthropic-usage` → `allotment_estimates[]`；`GET /admin/api/summary` 的 `weekly_allotment` | `upstream-quota.tsx` 窗口表下方的估算块；`auth-card.tsx` 的"est. weekly allotment"行 |
| hypitoken | `POST /admin/credentials/:id/anthropic-usage` → `allotment_estimates[]`；凭据列表的 `weekly_allotment` | `upstream-usage-dialog.tsx`；`credential-card.tsx` |

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
| 缓存沉降与失效 | `TestHitCacheServesWeeklyAndSettles`、`TestHitCacheDoesNotCacheLedgerErrors` |
