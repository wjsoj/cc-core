# sidecar —— 辅助流量仿真

> [← Wiki 首页](Home) · [架构总览](Architecture)

## 概览

`sidecar` 包模拟真实 Claude Code **2.1.220** 客户端在 `/v1/messages` 业务流量之外发出的**辅助流量**：进程启动时的 bootstrap 突发（9 步）、以及运行期的 `event_logging` 心跳。目的是消除"一个健康 OAuth 账号的请求流里一次 Haiku 配额探测都没有"这种最强的第三方客户端特征。

包注释（`sidecar/sidecar.go:34-62`）把它分成四个阶段：

| 阶段 | 内容 | 代码位置 |
|---|---|---|
| Phase A | 配额探测（Haiku `"quota"`），会话开始时必发 | 作为 bootstrap 的第 6 步 `sidecar/sidecar.go:450-473` |
| Phase B | bootstrap 突发，其余 8+1 个 GET/POST | `realBootstrapSteps` `sidecar/sidecar.go:397-538` |
| Phase C | `event_logging/v2/batch` 心跳 goroutine | `runHeartbeat` `sidecar/sidecar.go:817-844` |
| Phase D | Datadog 日志心跳——**已实现但故意不接线** | `runDatadogHeartbeat` `sidecar/sidecar.go:1172-1196` |

核心类型：

- `type Manager struct` — `sidecar/sidecar.go:185-201`，`sessions sync.Map`（accountKey → `*sidecarSession`）+ `anchors sync.Map`（accountKey → `*accountAnchor`）。
- `type Config struct { Enabled, UseUTLS bool; BaseURL string }` — `sidecar/sidecar.go:205-209`。
- `func New(cfg Config) *Manager` — `sidecar/sidecar.go:240-252`；仅在 `Enabled` 时启动 `gcLoop`。
- `func (m *Manager) Notify(a *auth.Auth, clientToken string) <-chan struct{}` — `sidecar/sidecar.go:265-336`。
- `func (m *Manager) Stop()` — `sidecar/sidecar.go:1338-1350`。
- `const BootstrapWaitCap = 5 * time.Second` — `sidecar/sidecar.go:86`，导出给调用方作为"首个业务请求等待 bootstrap"的共享上限。

`Manager.httpClient` 是**非导出**字段（`sidecar/sidecar.go:189`），仅测试内可注入；生产路径为 nil，回落到 `auth.ClientFor(a.ProxyURL, m.useUTLS)`（`sidecar/sidecar.go:672-675`、`911-914`）。

## 触发条件与去重键

`Notify` 的前置闸门（`sidecar/sidecar.go:266-268`）：

```go
if m == nil || !m.enabled || a == nil || a.Kind != auth.KindOAuth {
    return nil
}
```

- **去重键是 `a.AccountKey()`——只按 OAuth 账号，不含 clientToken**（`sidecar/sidecar.go:270`）。多个下游 `client_token` 走同一个 OAuth 账号时共用一个虚拟会话：上游只看到"一台机器、一次 bootstrap、一条心跳流"。注意这与包内注释开头"first touch of an `(account, clientToken)` pair"的旧描述不一致，**以代码为准：键只有 accountKey**（`TestBootstrapDeduplicatesAcrossClientTokens` `sidecar/sidecar_test.go:279-307` 正是锁死这一点）。
- 返回值是 `sess.bootstrapReady` channel：在 `quota_probe` 步骤派发后（或 bootstrap 提前中止 / 被冷却抑制时）关闭。已关闭的 channel 让后续 `Notify` 的等待变成 no-op。

时间闸门：

| 常量 | 值 | 作用 | 位置 |
|---|---|---|---|
| `sidecarSessionIdleTTL` | 30min | 超过则下次 `Notify` 视为新会话，整体替换 `sidecarSession` | `:68`, `:283-291` |
| `sidecarGCInterval` | 5min | 后台清扫空闲会话 | `:72`, `1354-1375` |
| `bootstrapCooldown` | **12h** | 同一账号距上次 bootstrap 不足 12h 则**完全抑制**突发（心跳照常起） | `:119`, `:317-325` |
| `bootstrapJitterFrac` | ±0.15 | 对每步的相对偏移抖动，避免逐比特重放捕获的时间阶梯 | `:124`, `:566` |
| `sidecarRequestTimeout` | 30s | 单个 sidecar HTTP 调用上限 | `:77` |

会话内还有 `bootstrapFired atomic.Bool` 的 CAS 闩锁（`sidecar/sidecar.go:295-297`），保证一个会话生命周期内只派发一次。

`bootstrapSessionID` 来自 `accountAnchor.sessionID`（`sidecar/sidecar.go:352-360`）：`sha256("cpa-claude-bootstrap/" + accountKey)` 前 16 字节 → `mimicry.UUIDFromBytes`。**anchor 跨会话淘汰而存活**，所以从空闲中唤醒会复用同一 session UUID，上游看到的是一个长期运行的 CLI 进程，而不是反复重启。

## bootstrap 步骤表

`realBootstrapSteps(baseURL)`（`sidecar/sidecar.go:397-538`）返回 **10 项**（其中最后一项在 `downloads.claude.ai`，不在 `baseURL` 上）。`delayFromStart` 是 `crack/oauth/rows/01..10` 捕获的相对时间戳。

| # | name | 方法 | 端点 | 时机 | User-Agent | Anthropic-Beta | 备注 |
|---|---|---|---|---|---|---|---|
| 1 | `growthbook_eval` | POST | `/api/eval/sdk-zAZezfDKGoZuXXKe` | T+0 | `Bun/1.4.0` | `oauth-2025-04-20` | body=`buildGrowthBookBody`；`Accept: */*`（Bun 特例，`:639-642`）；`Connection: keep-alive` |
| 2 | `oauth_account_settings` | GET | `/api/oauth/account/settings` | T+160ms | `claude-cli/…` | `oauth-2025-04-20` | **不是** claude-code/axios，2.1.191+2.1.214 双次捕获确认（`:415`） |
| 3 | `claude_code_grove` | GET | `/api/claude_code_grove` | T+160ms | `claude-cli/…` | `oauth-2025-04-20` | 同上（`:424`） |
| 4 | `claude_cli_bootstrap` | GET | `/api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8` | T+1250ms | `claude-code/2.1.220` | `oauth-2025-04-20` | 唯一带 `responseHandler`：`handleBootstrapResponse` |
| 5 | `claude_code_penguin_mode` | GET | `/api/claude_code_penguin_mode` | T+1250ms | `axios/1.15.2` | `oauth-2025-04-20` | |
| 6 | `quota_probe` | POST | `/v1/messages` | T+1270ms | `claude-cli/…` | `quotaProbeBeta`（6 项，`:145`） | body=`buildQuotaProbeBody`；额外 `X-App`、全套 `X-Stainless-*`、`Anthropic-Dangerous-Direct-Browser-Access: true`（`:461-472`），另加 `X-Claude-Code-Session-Id` + `X-Client-Request-Id`（`:659-663`）。**派发后关闭 `bootstrapReady`**（`:582-588`） |
| 7 | `mcp_registry` | GET | `/mcp-registry/v0/servers?version=latest&limit=100&visibility=commercial%2Cgsuite%2Centerprise%2Chealth` | T+1950ms | `claude-cli/…` | 无 | `noAuth: true` —— 公共目录端点，带 Bearer 本身就是破绽（`:480-484`） |
| 8 | `v1_mcp_servers` | GET | `/v1/mcp_servers?limit=1000` | T+1950ms | `axios/1.15.2` | `mcp-servers-2025-12-04` | `anthropic-mcp-client-capabilities: eyJyb290cyI6eyJsaXN0Q2hhbmdlZCI6dHJ1ZX0sImVsaWNpdGF0aW9uIjp7fX0=`（即 `{"roots":{"listChanged":true},"elicitation":{}}`）+ `MCP-Protocol-Version: 2025-11-25`（`:503-506`） |
| 9 | `code_triggers` | GET | `/v1/code/triggers` | T+1960ms | `claude-cli/…` | `ccr-triggers-2026-01-30` | `Anthropic-Client-Platform: claude_code_cli`；派发时若 `a.OrganizationUUID` 非空则加 `X-Organization-UUID`（`:666-670`） |
| 10 | `claude_code_releases` | GET | `https://downloads.claude.ai/claude-code-releases/latest` | T+2380ms | `axios/1.15.2` | 无 | `noAuth: true`（公共 CDN） |

四种 UA 常量定义在 `sidecar/sidecar.go:160-165`：`uaBun = "Bun/1.4.0"`、`uaAxios = "axios/1.15.2"`、`uaClaudeCode = "claude-code/" + mimicry.CLICurrentVersion`、`uaClaudeCLI = mimicry.ClaudeCLIUserAgent`。

所有步骤共同的头（`sendBootstrapStep` `sidecar/sidecar.go:612-698`）：`Authorization: Bearer <a.Credentials()>`（除 `noAuth`）、`Accept: application/json, text/plain, */*`、`Accept-Encoding: gzip, br`，以及各自的 `Anthropic-Version` / `Content-Type` / `Connection`。

派发顺序保序：`runBootstrap`（`sidecar/sidecar.go:549-593`）对每步偏移做 ±15% 抖动，若抖动后的 `due` 不晚于前一步则强制 `prevDue + 5ms`，保证相同 `delayFromStart` 的两步仍按捕获顺序落地。全部完成后写 `anchor.lastBootstrap`（`:590`）。

响应处理：只有 `claude_cli_bootstrap` 会读 body（先 `ccstream.Decompress(resp)`，再 `io.LimitReader` 1 MiB，`:688-689`）。`handleBootstrapResponse`（`:763-785`）解析 `oauth_account.organization_type` / `organization_rate_limit_tier` 并经 `a.UpdateSubscriptionInfo` 持久化，供下次 GrowthBook 用真实订阅属性（`subscriptionAttrsFor` `:745-755`，`claude_max → max` 去前缀，默认回落 `max` / `default_claude_max_20x`）。

## 心跳表

### event_logging 心跳（Phase C，已启用）

| 项 | 值 | 位置 |
|---|---|---|
| 端点 | `POST <baseURL>/api/event_logging/v2/batch` | `:896` |
| User-Agent | `claude-code/2.1.220`（`uaClaudeCode`） | `:907` |
| Anthropic-Beta | `oauth-2025-04-20` | `:906` |
| 其他头 | `X-Service-Name: claude-code`、`Content-Type: application/json`、`Accept: application/json, text/plain, */*`、`Accept-Encoding: gzip, br`、`Connection: close`、`Authorization: Bearer …` | `:901-909` |
| 首帧延迟 | 固定 8s（bootstrap 最后一步 T+2.4s 之后，真实 CC 首批 T+10s 之前） | `:822-826` |
| 热区间隔 | 距上次 `Notify` ≤ 30s → 18s ±40% | `heartbeatHotWindow/Interval` `:108-109`, `:859-860` |
| 温区间隔 | ≤ 90s → 45s ±40% | `heartbeatWarmWindow/Interval` `:110-111`, `:861-862` |
| 冷区 | > 90s → **停止**（`nextHeartbeatInterval` 返回 `ok=false`） | `:863-864` |

body 两种形态：

- **首批（startup dump）** `buildStartupHeartbeatBody`（`:997-1011`）：`startupEventNames` 共 **80** 条事件（`init()` `:950-985`，`tengu_skill_loaded` 35 条为主，`tengu_plugin_enabled_for_session` 9、`tengu_dir_search` 7、mcp 相关 3+3，其余多为单例，共 24 种事件名），时间戳按 `i*5ms` 铺开。**仅在 bootstrap 未被冷却抑制时才发**（`runHeartbeat(ctx, a, sess, !withinCooldown)` `:332`）。
- **稳态** `buildHeartbeatBody`（`:935-941`）：单条 `tengu_dir_search`。

单事件结构由 `buildHeartbeatEvent`（`:1017-1092`）构造：`event_type: "ClaudeCodeInternalEvent"`，`event_data` 含 `session_id`（= bootstrapSessionID）、`device_id`（`mimicry.DeviceIDFor(accountKey)`）、`betas`（`mimicry.ClaudeReportedBetas`）、`auth.{organization_uuid, account_uuid}`、`email`、`model: "claude-opus-4-8[1m]"`（`ccTelemetryModel` `:179`）、base64 编码的 `process` 与 `additional_metadata`，以及 `env` 块。

`env` 块的固定轴：`platform=linux`、`node_version=mimicry.ClaudeStainlessRuntimeV`（v26.3.0）、`arch=x64`、`version/version_base=2.1.220`、`build_time=ccBuildTime`（`"2026-07-24T22:17:45Z"`，`:178`）、`is_running_with_bun=true`、`is_claude_ai_auth=true`、`deployment_environment=unknown-linux`、`vcs=git`。**机器相关轴来自 HostProfile**（见下节）。

`process` 指标由 `buildProcessMetrics(accountKey)`（`:1105-1140`）生成：按账号 sha256 锚定 RAM/rss/heap 基线，每 tick 抖动；`heapUsed` 派生自已抖动的 `heapTotal`（74–93%），保证 `heapUsed ≤ heapTotal`。`uptime` 是进程真实运行秒数（`processStart` `:1097`），单调增长。

### Datadog 心跳（Phase D，定义但未接线）

| 项 | 值 | 位置 |
|---|---|---|
| 端点 | `POST https://http-intake.logs.us5.datadoghq.com/api/v2/logs` | `:131` |
| 认证 | `DD-API-KEY: pubea5604404508cdd34afb69e6f42a05bc`，**不带 Authorization** | `:132`, `:1223-1225` |
| User-Agent | `axios/1.15.2` | `:1229` |
| 首帧延迟 | 14s（与 event_logging 的 8s 错开） | `:1176-1180` |
| 间隔 | 25s ±40%（`datadogBaseInterval` / `datadogJitter`） | `:137-138`, `:1198-1202` |
| 空闲停止 | `isHeartbeatIdle`，5min（`heartbeatActiveWindow`） | `:100`, `:870-876` |
| body | **JSON 数组**，单条 `tengu_feature_ok`，字段全部平铺 + `ddtags` 逗号串 | `buildDatadogHeartbeatBody` `:1265-1332` |
| model | `claude-opus-4-8`（`ccDatadogModel`，**无 `[1m]` 后缀**，与 event_logging 不同） | `:180` |

## 与 auth.HostProfile 的关系

`auth.HostProfile`（`auth/hostprofile.go:32-37`）四个字段：`DistroID`、`Kernel`、`Terminal`、`Shell`。

- `Notify` 在首次触发时**异步**调用 `a.EnsureHostProfile()` 把账号的合成主机档案钉到凭据文件（幂等，`sidecar/sidecar.go:304-308`）。失败只记 debug 日志，不影响流程。
- body 构造侧读 `a.HostProfileOrDefault()`（`auth/hostprofile.go:113`），所以即使持久化还没完成也能拿到派生档案 —— 这就是可以把 `EnsureHostProfile` 放在热路径外的原因。
- 使用点：event_logging 的 `env.terminal/linux_distro_id/linux_kernel/shell`（`sidecar/sidecar.go:1044`、`1061-1065`）与 Datadog body 的同名字段（`:1308-1309`、`1334`附近的 `linux_kernel`/`linux_distro_id`）。
- 设计意图（`sidecar/sidecar.go:167-173`）：`platform/arch/node_version/is_running_with_bun` 是版本绑定的、全局固定；**机器轴按账号变化**，否则所有账号都宣称同一台机器。
- 测试 `auth.ProfileFor(a.AccountKey())`（`sidecar/sidecar_test.go:472`）验证 Datadog body 里的四个值确实来自该账号的档案。

## 陷阱

1. **API-key 凭据永不触发 sidecar**。判定在 `Notify` 第一行：`a.Kind != auth.KindOAuth` → 直接返回 `nil`（`sidecar/sidecar.go:266-268`）。回归测试 `TestSidecarSkipsAPIKey`（`sidecar/sidecar_test.go:310-325`）。理由：API-key 流量本来就不是 CLI 客户端形态，补发 CLI 遥测反而是破绽。
2. **`Notify` 返回 `nil` channel 时不要盲等**。Go 中对 nil channel 的接收会永久阻塞——调用方必须用 `select` 带 `BootstrapWaitCap` 超时分支，或先判 nil。
3. **Datadog 心跳定义了但故意不启动**。`Notify` 里显式注释（`sidecar/sidecar.go:333-334`）：硬编码的公共 intake key 本身是一个被钉死的指纹，Anthropic 可以随时轮换或监控它 —— 一旦密钥过期而我们还在发，就变成反向识别信号。`runDatadogHeartbeat` / `sendDatadogHeartbeat` / `isHeartbeatIdle` / `heartbeatActiveWindow` 全部保留，重新接线是一行改动。
4. **12h bootstrap 冷却同时门控 startup batch**。若只抑制 bootstrap 而仍发 80 事件的胖首批，等于在"安静的唤醒窗口"里喊"我刚重启了"，恰好抵消冷却的意义（`sidecar/sidecar.go:326-332`，测试 `TestStartupBatchSuppressedUnderCooldown` `sidecar/sidecar_test.go:429-464`）。
5. **冷却分支必须立刻 `close(bootstrapReady)`**（`sidecar/sidecar.go:322`），否则等待 bootstrap 的首个业务请求会白等到 `BootstrapWaitCap`。`TestBootstrapCooldownSuppressesBurst`（`sidecar/sidecar_test.go:402-409`）用 200ms 断言这一点。
6. **`mcp-registry` 不能带 Bearer，`/v1/mcp_servers` 必须带**。两者是成对的坑，`TestMCPProbeAuthAndCapabilities`（`sidecar/sidecar_test.go:194-234`）同时锁死 Authorization 与 base64 capability 值。capability 的旧编码 `{"roots":{}}` 解出的能力集是真实 CC 从不发送的。
7. **UA 归属曾经错过**：`account/settings` + `grove` + `mcp-registry` 三个端点都用 `claude-cli`，而不是 `claude-code`/`axios`。cc-core 从 2.1.191 一直发错，直到 2.1.214 bump 时才发现（`sidecar/sidecar.go:155-159`）。
8. **空闲唤醒必须整体替换 `sidecarSession`**，不能原地改 —— 原地改会与并发读 `bootstrapReady` 的 goroutine 竞态（`sidecar/sidecar.go:279-291`）。
9. **版本常量必须整体移动**：`ccBuildTime`、`ccTelemetryModel`、`ccDatadogModel`、`quotaProbeBeta`、以及 `mimicry` 的 UA/beta 常量，任一落后就会与其他项自相矛盾。

## 测试与时序

测试全部打真实 `httptest.Server`（`sidecar/sidecar_test.go:47-99` 的 `recorder.handler()` / `batchCapturingHandler()` 记录 path/UA/beta/Authorization/mcp-caps/body），并通过 `mgr.httpClient = srv.Client()` 注入客户端。**没有假时钟**——bootstrap 的 2.4s 阶梯与心跳的 8s 预热都是真实等待，整个包约 23s（`go test ./sidecar/ -timeout 60s`）。

| 测试 | 断言 | 位置 |
|---|---|---|
| `TestBootstrapFiresAllStepsWithCorrectUA` | 9 个 on-host 端点全中，UA 前缀 + beta 逐条匹配（5s 内） | `:118-187` |
| `TestMCPProbeAuthAndCapabilities` | mcp-registry 无 Authorization；`/v1/mcp_servers` 有 Authorization + 正确 capability base64 | `:194-234` |
| `TestBootstrapFiresOncePerSession` | 三次 `Notify` 只发一轮（非心跳命中 ≤ 10） | `:238-271` |
| `TestBootstrapDeduplicatesAcrossClientTokens` | 两个 client_token 共享一轮 bootstrap | `:279-307` |
| `TestSidecarSkipsAPIKey` | API-key 零调用 | `:310-325` |
| `TestSidecarDisabled` | `Enabled:false` 零调用 | `:328-342` |
| `TestSidecarRefiresAfterIdle` | 手动回拨 `lastSeen` 与 `lastBootstrap` 后重新触发 | `:346-381` |
| `TestBootstrapCooldownSuppressesBurst` | 冷却下 3s 内零非心跳命中，且 ready 立刻关闭 | `:387-423` |
| `TestStartupBatchSuppressedUnderCooldown` | 冷却下首批事件数 ≤ 5（最长等 15s） | `:429-464` |
| `TestDatadogHeartbeatBodyShape` | JSON 数组、`ddsource/message/service`、HostProfile 四轴、`ddtags` | `:470-505` |
| `TestProcessMetricsInvariants` | 4 账号 × 2000 次抽样，`heapUsed ≤ heapTotal ≤ rss`、`heapTotal+external ≤ rss` | `:511-533` |
| `TestUserBucketStability` | `user_bucket` 按账号稳定且落在 [0,99] | `:538-552` |
| `TestHeartbeatBodyShape` | 稳态 body 的结构不变量 | `:558-580` |
| `TestStartupHeartbeatBatchShape` | 60–100 事件、event_id 唯一、≥15 种事件名、`skill_loaded ≥ 20` | `:587-641` |
| `TestSubscriptionAttrsFor` / `TestHandleBootstrapResponse(Empty)` | 订阅属性映射与缓存不被空响应清零 | `:647-711` |

辅助函数 `waitForCallCount(r, want, timeout)`（`:713-722`）以 20ms 轮询等待，是所有时序测试的公共等待原语。

## 文件清单

| 文件 | 行数 | 内容 |
|---|---|---|
| `/home/wjs/Documents/project/Go/cc-core/sidecar/sidecar.go` | 1375 | 全部实现：常量、`Manager`/`Config`、`Notify`、bootstrap 步骤表与派发、body builders、event_logging 心跳、Datadog（未接线）、生命周期与 GC |
| `/home/wjs/Documents/project/Go/cc-core/sidecar/sidecar_test.go` | 725 | `httptest` 真实时序套件（约 23s） |

依赖包：`github.com/wjsoj/cc-core/auth`（`Auth`、`ClientFor`、`HostProfile`）、`github.com/wjsoj/cc-core/mimicry`（版本常量、`DeviceIDFor`、`BuildJSONUserID`、`UUIDFromBytes`、`NewRequestUUID`）、`github.com/wjsoj/cc-core/stream`（`Decompress`）。

---

## 相关页面

[Mimicry](Mimicry) · [Crack](Crack) · [Auth-Login-Codex](Auth-Login-Codex)
