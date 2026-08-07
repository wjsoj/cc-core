# 约定与维护指南

> [← Wiki 首页](Home) · [架构总览](Architecture)

这一页收集**跨包生效**的规矩。每一条背后都有一次真实事故或一次真实返工。

---

## 1. 身份派生一律内容寻址

除了 `X-Client-Request-Id` 和内部 `event_id`，**代码里不允许出现随机 UUID**。

所有稳定标识符都从 `accountKey` 派生（当它应该随下游用户不同时，从 `accountKey + clientToken` 派生），这样它们能**跨凭据文件轮转存活**：换一次 refresh token、重登一次账号，设备 ID 和会话 ID 都不变 —— 真实客户端就是这个行为，随机化才是 tell。

新增标识符时问自己：**这个值在凭据文件被重写之后还应该一样吗？** 答"是"就必须是 `sha256(accountKey + …)` 之类的确定性派生。

详见 [Mimicry](Mimicry) → 身份派生。

---

## 2. OAuth 凭据文件字段只增不改

`parseFile`（`auth/oauth.go`）读取字段一律用容错写法：

```go
_ = raw["new_field"].(string)   // 缺字段 → 零值，老文件照样加载
```

**不得**在解析时对新字段做强制校验，也不得改名或改语义 —— 生产环境里躺着一堆老版本写出的凭据文件。要淘汰一个字段，走"读时忽略 + 写时移除"的两步（`claude_identity_mode` 就是这么退役的，见 `auth/claude_account_policy_test.go`）。

详见 [Auth-Login-Codex](Auth-Login-Codex) → 凭据文件格式。

---

## 3. 行为常量的改动纪律

下面这些不是"配置"，是**行为常量**：改一个数字，两个分叉的生产行为同时改变。

| 常量 | 位置 | 改了会怎样 |
|---|---|---|
| `hardFailureThreshold = 5` | `auth/types.go:238` | OAuth 自动退休的灵敏度 |
| `degradedProbeAfter = 5m` | `auth/types.go:233` | 调小 → 对坏凭据反复试探；调大 → 恢复变慢；**去掉 → 凭据池永久变黑** |
| `rateLimit429HardFailureThreshold = 15` | `auth/types.go:244` | 隐形封禁判定 |
| `auth401HardFailureThreshold = 8` | `auth/types.go:307` | token 轮转竞态的容忍度 |
| `apiKeyQuarantineThreshold = 3` | `auth/types.go:261` | API-key 熔断灵敏度 |
| `transientErrFragments` 每一条 | `auth/retry.go:35` | 少一条 → 一次 h2 连接死亡打黑整池 |
| pricing 权重（1× / 1.25× / 0.1× / 5×） | `usage` | 同时改变账单**和**负载均衡信号 |
| `groupNewIdleHoursPerDay = 10` | `auth/schedule.go:24` | `new` 组每日休眠时长 |

**规矩：每一次这类改动都必须配一个测试。** 新增 `transientErrFragments` 条目时，把**逐字的**生产错误串加进 `auth/retry_test.go`。

---

## 4. 指纹常量必须有 capture 背书

`mimicry` / `sidecar` / `auth/codex_*` 里的 User-Agent、beta 列表、body 结构、bootstrap 步骤，**不允许凭直觉手改**。流程是：

抓一份真实客户端流量 → `crack/scripts/extract_live.py` 脱敏 → 写 `crack/cc<ver>/SPEC.md` 记录 diff → 再改常量。

版本相关的常量是**一套**，必须一起动：`CLICurrentVersion`、`ClaudeCLIUserAgent`、`ClaudeAnthropicBetaFull`、`ClaudeAnthropicBeta1M`、`ClaudeAnthropicBetaCountTokens`、`ClaudeReportedBetas`、以及 sidecar 各步骤的 UA。任何一个落下，User-Agent 就会和 body 里的 `cc_version=` 计费块自相矛盾。

**原始 dump 永远不进 git。** 详见 [Crack](Crack) 与 [Mimicry](Mimicry) → 升级 checklist。

---

## 5. 探针失败不得影响凭据健康

`FetchCodexUsage` / `FetchCodexSubscription` / `FetchCodexResetCredits` 这些**主动探针**打的是 ChatGPT 门户，跟 `/responses` 能不能用是两回事。门户抖一下不代表凭据坏了 —— 探针路径上**不允许**出现 `MarkFailure`。

同理，`MarkClientCancel` 只记时间戳：客户端自己断开，凭据没做错任何事。

---

## 6. 本地准备失败 ≠ 凭据失败

`PrepareClaudeCodeRequest` 系列的 fail-closed 是**本进程的**判断（拿到了无法安全重建的 `cch` / 缺少 beta 向量 / 绑定校验不过）。它**不得**触发凭据 failover —— 换一个凭据重试，同样会失败，只是白白把整池凭据加进 exclude 列表。

---

## 7. 构建与测试

```bash
go build ./...                              # 全量编译
go test ./...                               # 全部测试
go vet ./...
go test ./auth/ -run TestSessionsHeld -v    # 单个测试
go test ./sidecar/ -timeout 60s             # sidecar 用真实时序，跑约 23s
```

仓内没有 CI，`go build` + `go test` 是唯一的守门员 —— 提交前请自己跑。

---

## 8. 这份 Wiki 的维护

- 页面源文件在 **`docs/wiki/*.md`**，跟代码一起 review；Wiki 站点只是镜像。
- 同步命令：`bash docs/wiki/sync-wiki.sh "docs(wiki): …"`。
- 代码引用一律写成 `路径:行号`（例如 `auth/pool.go:504`）。行号会漂移 —— **改动对应代码时顺手更新引用**。
- 页面之间用 `[标题](页面名)` 相互链接（GitHub Wiki 的相对链接语法）。

---

## 9. 已知的注释 / 文档漂移

建立这份 Wiki 时的调研发现。**已在本次同步中修掉的注释漂移**（仅改注释，无行为变化）：`requestlog/store_ingest.go` 与 `store_query.go` 的 `agg_day` 残留、`sidecar/sidecar.go` 的去重键描述、`codexws/dial.go` 的 codex-tui 版本号、`backup/backup.go` 的 `.tar.gz.age` 后缀、`mimicry/body.go` 三处指向已不存在的 `crack/claude` 路径。

**仍待处理**（改到附近代码时顺手看一眼）：

| 位置 | 问题 |
|---|---|
| `pricing/pricing.go:374` | ⚠️ **`claude-sonnet-5` 引导价 2026-08-31 到期**，逾期不改每笔少收约 33% |
| `requestlog/store_query.go:327` | `scanAggregateRow` 全包无调用点，是 `agg_day` 时代遗留 |
| `mimicry/fingerprint.go:50` | `ClaudeStainlessOS = "Linux"` 与 cc2220 capture 的 `MacOS` 不同是**刻意**的，但常量处没有注释说明，只写在 SPEC 里 —— 下次升级容易被"照抄 capture"改错 |
| `auth/codex_login.go:145` | Codex 登录落盘直接 `os.WriteFile`，既不持 `saveMu` 也不做账号比对，与 Anthropic 侧 `writeAnthropicLoginCredential` 不对称 |
| `auth/oauth.go` | `organization_uuid` 登录时写入，但 `parseFile` 从不读取 |
| `auth/pool.go:399-400` | `AcquireMulti` 的注释描述了 `tried` 集合的累积，但循环体内从不往里加元素 |
| `auth/pool.go:504` | `oauthUsableLocked` 不调用 `IsHealthy()`；`IsHealthy` 在池内只被 `ResetUnhealthyAnthropicAPIKeys` 使用。是有意还是历史遗留待确认 |

---

## 相关页面

[Architecture](Architecture) · [Release](Release) · [Auth-Pool](Auth-Pool) · [Mimicry](Mimicry) · [Crack](Crack)
