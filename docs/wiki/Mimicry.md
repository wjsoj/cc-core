# mimicry —— Claude Code / Codex 客户端指纹

> [← Wiki 首页](Home) · [架构总览](Architecture)

> 本页所有行号对应 `cc-core` 仓库 `main` 分支当前源码（Claude 目标 `2.1.220`，Codex 目标 `0.144.4`）。

## 概览

`mimicry` 包负责把一个"任意来源"的 HTTP 请求改造成**看起来由真实客户端发出**的请求。它是纯函数库：不发请求、不管 TLS（TLS 指纹在 `auth/utls.go`）、不碰凭据健康状态。

两层指纹（`mimicry/fingerprint.go:1-19` 包注释）：

1. **请求头层** —— `User-Agent` / `X-Stainless-*` / `Anthropic-Beta` / `X-App` / `X-Claude-Code-Session-Id` / `x-client-request-id`，由 `ApplyClaudeCodeHeaders` 写入（`mimicry/headers.go:38`）。
2. **请求体层** —— `system[0]` 计费归因块、`system[1]` Claude Code 引导语、`cache_control` 断点、`metadata.user_id`，由 `ApplyClaudeCodeBodyMimicry` 写入（`mimicry/body.go:99`）。

任何一层缺失，OAuth 订阅凭据上的请求都会被降级为"第三方应用"计费。

包内四条相对独立的主线：

| 主线 | 文件 | 入口 |
|---|---|---|
| 常量与工具 | `fingerprint.go` | 版本/beta/UA 常量、`NewRequestUUID`、`UUIDFromBytes` |
| 通用改写路径（旧路径） | `headers.go` + `body.go` | `ApplyClaudeCodeHeaders`、`ApplyClaudeCodeBodyMimicry` |
| prepared-request 管线（新路径，fail-closed） | `request_policy.go` | `ClassifyClaudeCodeRequest` → `NewClaudeCodeRequestPolicy` → `PrepareClaudeCodeRequest` → `ApplyClaudeCodePreparedRequest` |
| 身份派生 | `identity.go` | `SimIdentity`、`DeviceIDFor`、`SessionIDFor`、`SessionIDForSource` |

另有两个横切件：`dateline.go`（抹除 Claude Code 在非官方 base URL 下埋入日期句的 3 bit 隐写信标）、`codex.go` + `codex_body.go`（Codex CLI 侧的头/体）。

---

## 指纹常量表

**核心纪律：同一次版本升级里，下表 `fingerprint.go` 的版本相关常量必须"一起改"。**`CLICurrentVersion` 与 `ClaudeCLIUserAgent` 里烘焙的版本号一旦漂移，请求体计费块中的 `cc_version=X.Y.Z.{fp}` 就会和 `User-Agent` 互相矛盾，直接触发 Anthropic 边缘的第三方检测（`fingerprint.go:36-38`）。

### Claude 侧（`mimicry/fingerprint.go`）

| 常量 | 值 | 出处 capture | 行号 |
|---|---|---|---|
| `CLICurrentVersion` | `2.1.220` | `crack/cc2220/SPEC.md`（2026-07-30 macOS + 2026-07-31 Linux） | `fingerprint.go:40` |
| `ClaudeCLIUserAgent` | `claude-cli/2.1.220 (external, cli)` | 同上，20/20 主请求一致 | `fingerprint.go:41` |
| `ClaudeStainlessLang` | `js` | cc2220 SPEC「Main /v1/messages request」 | `fingerprint.go:42` |
| `ClaudeStainlessRuntime` | `node` | 同上 | `fingerprint.go:43` |
| `ClaudeStainlessRuntimeV` | `v26.3.0` | 2.1.191 起（Node v24.3.0→v26.3.0），cc2220 复核未变；同时喂给 sidecar 遥测 `env.node_version` | `fingerprint.go:48` |
| `ClaudeStainlessPackageV` | `0.94.0` | cc2220 SPEC（@anthropic-ai/sdk 0.94.0） | `fingerprint.go:49` |
| `ClaudeStainlessOS` | `Linux` | **刻意不取自 capture**：cc2220 抓包主机是 `MacOS`，SPEC 明确要求不要把抓包主机属性写进合成 host profile | `fingerprint.go:50` |
| `ClaudeStainlessArch` | `x64` | cc2220 SPEC | `fingerprint.go:51` |
| `ClaudeStainlessTimeout` | `600` | cc2220 SPEC（main 有；`count_tokens` **无**） | `fingerprint.go:52` |
| `ClaudeStainlessRetryCnt` | `0` | cc2220 SPEC（两类都有） | `fingerprint.go:53` |
| `ClaudeAnthropicVersion` | `2023-06-01` | cc2220 / COMPARE.md（OAuth 与 apikey 相同） | `fingerprint.go:54` |
| `ClaudeAnthropicBetaFull` | 13 项，`claude-code-20250219,oauth-2025-04-20,interleaved-thinking-…,…,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07` | `crack/cc2220/SPEC.md` §1 + §1a 非 1M 列表（macOS Sonnet 5 20 条 + Linux opus-4-8 5 条，跨两主机两 OS） | `fingerprint.go:81` |
| `ClaudeAnthropicBeta1M` | 15 项（第 3 位插 `context-1m-2025-08-07`，`effort` 与 `extended-cache-ttl` 之间插 `fallback-credit-2026-06-01`） | `crack/cc2220/SPEC.md` §1a，`rows-2026-07-31/15-v1_messages_1m.json`，**单样本** | `fingerprint.go:94` |
| `ClaudeAnthropicBetaCountTokens` | 5 项，含独有的 `token-counting-2024-11-01` | `crack/cc2220/SPEC.md` §1b（4 个样本完全一致） | `fingerprint.go:100` |
| `ClaudeReportedBetas` | 9 项，止于 `mid-conversation-system-2026-04-07` | 遥测体（event_logging / datadog），`crack/cc2214/SPEC.md` §3 复核，2.1.156→2.1.214 未变 | `fingerprint.go:116` |
| `ClaudeAnthropicBetaApikey` | 8 项，无 `oauth-*` / `advanced-tool-use-*` / `cache-diagnosis-*`，含 `context-1m-2025-08-07` | `crack/apikey/rows/*-POST-…v1_messages`；差集分析见 `crack/COMPARE.md` §3.2 | `fingerprint.go:126` |
| `ClaudeDefaultCacheTTL` | `1h` | cc2220 主体 system 块 | `fingerprint.go:134` |
| `ClaudeDefaultCacheScope` | `global` | 同上（倒数第二块） | `fingerprint.go:135` |
| `ClaudeCodeSystemPrompt` | `You are Claude Code, Anthropic's official CLI for Claude.` | cc2220 system[1]（57B，无 cache_control） | `fingerprint.go:140` |
| `ClaudeCodePromptPrefixes` | 4 条前缀（Claude Code / Claude Agent SDK / file search specialist / summarizing conversations） | 官方各请求类前缀族 | `fingerprint.go:144-149` |
| `fingerprintSalt` | `59cf53e54c78`（非导出） | 2.1.198 bundle 静态提取的 `awo`，cc2220 静态分析再确认 | `body.go:49` |
| `cchSeed` | `0x6E52736AC806831E`（非导出） | **不是真实算法**：cc2220 37/37 样本 0 命中，legacy best-effort | `body.go:53` |
| `claudeBillingHeaderPrefix` | `x-anthropic-billing-header` | cc2220「Billing…」节 | `body.go:74` |
| `claudeEntrypointMarker` | `cc_entrypoint=` | 同上；值可为 `cli` / `sdk-cli` | `body.go:75` |

关于 beta 列表还有两条容易踩的规则：

- **1M 列表不会被自动选中。** 请求体里没有任何 1M 标记（`[1m]` 只出现在遥测的 `event_data.model`），所以 cc-core 无法推断上下文模式；导出 `ClaudeAnthropicBeta1M` 只是让 fork 在提供显式 "1M 模式" 时不必手搓（`fingerprint.go:88-93`）。
- **`ClaudeReportedBetas` 与 `ClaudeAnthropicBetaFull` 语义分离**，即便某个版本上前者恰好是后者的前缀，也不要合并——请求 beta 与遥测 beta 沿不同轴变化（`fingerprint.go:113-115`）。

### Codex 侧（`mimicry/codex.go`）

| 常量 | 值 | 出处 capture | 行号 |
|---|---|---|---|
| `CodexCLIVersion` | `0.144.4` | `crack/codex/SPEC.md`「2026-07-14」节：0.135.0 实抓 + 版本号提升（0.144.2/.3/.4 无 wire 变化） | `codex.go:35` |
| `CodexCLIUserAgent` | `codex-tui/0.144.4 (Arch Linux Rolling Release; x86_64) Konsole/260401 (codex-tui; 0.144.4)` | 模板取自 0.135.0 实抓；OS/终端段是我们自己的合成身份 | `codex.go:36` |
| `CodexOriginator` | `codex-tui` | `crack/codex/rows/01`（WS 握手头） | `codex.go:37` |
| `CodexOpenAIBeta` | `responses=experimental` | HTTP POST 路径；真实 TUI 的 WS 握手用 `responses_websockets=2026-02-06` | `codex.go:41` |
| `CodexUsageUserAgent` | `= CodexCLIUserAgent` | `crack/codex/SPEC.md`「GET /backend-api/wham/usage」：CLI 用自己的 UA，不是浏览器 UA | `codex.go:82` |

---

## 请求头构造

### `ApplyClaudeCodeHeaders`

```go
func ApplyClaudeCodeHeaders(req *http.Request, token, kind string, stream, isAnthropicBase bool, id SimIdentity, body []byte)
```
（`mimicry/headers.go:38`；`kind` 取 `KindOAuth = "oauth"` / `KindAPIKey = "apikey"`，`headers.go:11-14`）

总体规则：**客户端已带的值优先**（通过 `ensureHeader`，`fingerprint.go:180`），只有凭据头和少数几个是无条件覆盖。

实际写入的头，按代码顺序：

| Header | 值 | 覆盖策略 | 行号 |
|---|---|---|---|
| `Authorization` / `x-api-key` | `Bearer <token>` 或裸 token（互斥，另一个 `Del`） | **强制覆盖** | `headers.go:40-46` |
| `Content-Type` | `application/json` | **强制** | `headers.go:47` |
| `Anthropic-Version` | `ClaudeAnthropicVersion` | ensure | `headers.go:56` |
| `Anthropic-Beta` | 见下表 | 客户端已有则保留（OAuth 下若缺 `oauth` 则追加 `,oauth-2025-04-20`） | `headers.go:57-75` |
| `Anthropic-Dangerous-Direct-Browser-Access` | `true` | ensure，**仅 `isAnthropicBase`** | `headers.go:76-78` |
| `X-App` | `cli` | ensure | `headers.go:81` |
| `X-Stainless-Retry-Count` | `0` | ensure | `headers.go:82` |
| `X-Stainless-Lang` | `js` | ensure | `headers.go:83` |
| `X-Stainless-Runtime` | `node` | ensure | `headers.go:84` |
| `X-Stainless-Runtime-Version` | `v26.3.0` | ensure | `headers.go:85` |
| `X-Stainless-Package-Version` | `0.94.0` | ensure | `headers.go:86` |
| `X-Stainless-Os` | `Linux` | ensure | `headers.go:87` |
| `X-Stainless-Arch` | `x64` | ensure | `headers.go:88` |
| `X-Stainless-Timeout` | `600` | ensure，**`count_tokens` 上不写** | `headers.go:89-92` |
| `X-Claude-Code-Session-Id` | `SessionIDFor(id, body)` | ensure | `headers.go:96` |
| `x-client-request-id` | 每请求新 UUIDv4 | ensure，**仅 `isAnthropicBase`** | `headers.go:97-99` |
| `User-Agent` | `ClaudeCLIUserAgent` | 仅当现值不以 `claude-cli/` 开头时覆盖 | `headers.go:103-106` |
| `Connection` | `keep-alive` | **强制** | `headers.go:108` |
| `Accept-Encoding` | `gzip, br` | **强制**（有意偏离；需配 `cc-core/stream.Decompress`） | `headers.go:109` |
| `Accept` | `text/event-stream`（stream）/ `application/json` | stream 强制；非 stream ensure | `headers.go:110-114` |

`Anthropic-Beta` 的四路分支（`headers.go:57-75`）：

| 条件 | 使用的列表 |
|---|---|
| 客户端自带 beta | 保留客户端的；OAuth 且不含 `oauth` 时追加 `,oauth-2025-04-20` |
| `kind == KindAPIKey` | `ClaudeAnthropicBetaApikey` |
| 路径以 `/v1/messages/count_tokens` 结尾（`headers.go:52-53`） | `ClaudeAnthropicBetaCountTokens` |
| 其余（OAuth 主请求） | `ClaudeAnthropicBetaFull` |

> `count_tokens` 是独立请求类：短 beta 列表 **且** 无 `X-Stainless-Timeout`，两个差异必须同时复现（cc2220 SPEC §1b 称之为"最容易搞错的一处"）。apikey 路径不受此影响（没有 apikey 的 `count_tokens` capture）。

### `forcePinnedClaudeCodeProfile`

`request_policy.go:931-943`。prepared 管线在两条"必须抹掉下游身份"的路径上调用：把 `User-Agent`、`Anthropic-Version`、`X-App`、全部 7 个 `X-Stainless-*` 加 `X-Stainless-Timeout` 一律 `Set`（不是 ensure），彻底覆盖客户端值。

---

## 请求体构造

### `ApplyClaudeCodeBodyMimicry`

```go
func ApplyClaudeCodeBodyMimicry(body []byte, model string, id SimIdentity) []byte
```
（`mimicry/body.go:99`）尽力而为：任一步失败即原样返回。

**跳过条件（特例）：**

| 条件 | 行为 | 行号 |
|---|---|---|
| `len(body) == 0` | 原样返回 | `body.go:100` |
| `strings.Contains(strings.ToLower(model), "haiku")` | 原样返回（Anthropic 不对 Haiku 做第三方检测） | `body.go:100` |
| body 不是 JSON object（含 `null`） | 原样返回 | `body.go:103-106` |
| `system` 已含计费归因块，**或**已以某个 `ClaudeCodePromptPrefixes` 开头 | **只重签 cch**，不改写 —— 改写会毁掉客户端的 prompt-cache 前缀（`cache_read` 掉底、`cache_creation` 每轮增长、单请求成本涨 10–20×） | `body.go:115-117` |

计费块识别只认"存在"，不校验 `cc_entrypoint` 的具体值（值会在 `cli` / `claude-vscode` / `jetbrains` / `sdk` 间漂移，不是防伪边界），见 `body.go:184-199`。

**改写四步（`body.go:119-146`）：**

1. `rewriteSystemForOAuth`（`body.go:215`）重建 `system`：
   - `system[0]` = 计费块（`buildBillingBlock`，`body.go:320`），文本 `x-anthropic-billing-header: cc_version=2.1.220.{3hex}; cc_entrypoint=cli; cch=00000;`
   - `system[1]` = `ClaudeCodeSystemPrompt`，**裸块，无 cache_control**
   - `system[2..]` = 客户端原 system（先 `stripCacheControlFromBlocks`，再 `applySystemCacheBreakpoints`）。客户端 prompt **留在 system 里**，不搬进 messages —— 真实 CC 从不搬，`message[0..1]` 出现杂散 user/assistant 对本身就是第三方工具指纹（`body.go:212-214`）。
2. `stripMessageCacheControl`（`body.go:432`）+ `addMessageCacheBreakpoints`（`body.go:485`）：只在**最后一条 message 的最后一个 block** 打 `{ephemeral, ttl:1h}`；若客户端已设 ttl 则尊重客户端（`body.go:543-547`）。
3. `ensureMetadataUserID`（`body.go:566`）：写 JSON 字符串形态的 `metadata.user_id`；**已有非空 user_id 则拒绝覆盖**（`body.go:579-581`）。
4. `signBillingHeaderCCH`（`body.go:422`）：把 `cch=00000` 占位替换为 `xxhash64(seed=cchSeed, 最终 body)` 低 20 bit 的 5 位十六进制。**必须是最后一步**，之后任何改动都会让 hash 失效。

**system cache 断点布局**（`applySystemCacheBreakpoints`，`body.go:272-284`）：倒数第二块 `{ephemeral, ttl:1h, scope:global}`，最后一块 `{ephemeral, ttl:1h}`。早期代码把两者装反过。

**有意不注入的字段**（`body.go:132-142`）：`thinking`、`output_config`、`context_management`（beta 门控 + 改变响应语义，凭据 beta 列表不匹配时上游 400）、`diagnostics`（语义中性，但没有可信的 `previous_message_id` 可填，纯粹为了缩小注入面）。

### `cc_version` 三位指纹

`computeClaudeCodeFingerprint`（`body.go:351`）复刻真实 CLI 的 `xtf`/`awo`：

1. 取**第一条非 meta user 消息**的第一个 text（`extractFirstUserText`，`body.go:372`；以 `<system-reminder>` 开头的 block 被跳过，对应 CLI 的 `!isMeta`，`body.go:370`、`body.go:406-408`）。
2. 按 **JavaScript UTF-16 code unit** 取下标 `[4, 7, 20]`，不足补 `'0'`（`body.go:353-362`）。emoji 场景下 rune 索引会算错，cc2220 SPEC 明确验证过这点。
3. `sha256(fingerprintSalt + chars + version)`，取 hex 前 3 位。

### `cch` 的现状

cc2220 对 2.1.220 bundle 做了穷尽静态搜索：JS 层只发字面占位 `cch=00000`，全 bundle 里 `cc_version=` 和 `cc_prev_req` 各出现 **1** 次（同一个 builder `k7n`），没有任何替换代码，也没有对应的 native 符号——真正的替换发生在 JS 之下的私有请求栈。

结论落到代码上（`body.go:36-45`）：

- **不要**把实现"修正"成发 `00000`。43/43 真实样本全为非零且互不相同，占位值是真客户端永远不会上线的形态。`TestCCHIsNeverPlaceholder`（`body_test.go:375`）守着这条。
- 现有 seeded-xxhash 是 **legacy best-effort**：算法错、形状对（5 hex、非零、每请求唯一）。cc2220 上 0/37 命中。
- `cch` 与 `cc_prev_req` 只在 endpoint 解析为 `firstParty`/`vertex` 时出现——这正是 `crack/apikey/` 路径看不到 `cch` 的原因。

---

## 身份派生

全部内容寻址，无随机 UUID（唯一的随机来源是 `x-client-request-id` 与 sidecar 内部 `event_id`）。

```
SimIdentity{ AccountKey, AccountUUID, ClientToken }        // identity.go:23
```

- `AccountKey`：最稳定的账号锚（`account_uuid` > email > id），凭据文件轮换后依然存活。
- `AccountUUID`：OAuth 下发的真 UUID，原样写进 `metadata.user_id.account_uuid`；空串合法（对应刚登录、bootstrap 尚未回填的真实 CC 行为）。
- `ClientToken`：下游调用方身份。每个不同的 ClientToken 表现为同一台机器上的另一个并发 CC 窗口。

派生公式：

```
DeviceIDFor(accountKey)   = hex( sha256( "cpa-claude-device/" + accountKey ) )                      // identity.go:33-36  → 64 hex

SessionIDFor(id, body)    = uuidv4Shape( sha256( "cpa-claude-session/" ‖ AccountKey ‖ "|" ‖ ClientToken
                                                 ‖ "|" ‖ sha256(extractFirstUserText(body)) )[:16] ) // identity.go:47-59

SessionIDForSource(id, s) = uuidv4Shape( sha256( "cpa-claude-source-session/" ‖ AccountKey ‖ "|"
                                                 ‖ ClientToken ‖ "|" ‖ s )[:16] )                    // identity.go:66-76

HashClaudeAccountKey(v)   = hex( sha256( "claude-account-key/v1\x00" + trim(v) )[:8] )               // request_policy.go:158-165
```

`uuidv4Shape` = `uuidFromBytes`（`fingerprint.go:168`）：强制 version=4 / variant=RFC4122 的 nibble，再格式化成 8-4-4-4-12。

```mermaid
flowchart TD
    AK["AccountKey<br/>(account_uuid &gt; email &gt; id)"]
    CT["ClientToken<br/>(下游用户)"]
    B["请求体<br/>第一条非 meta user 文本"]
    S["genuine 客户端<br/>metadata.user_id.session_id"]

    AK --> D["DeviceIDFor<br/>sha256('cpa-claude-device/'+AK)"]
    AK --> SS["SessionIDFor<br/>sha256('cpa-claude-session/'|AK|CT|sha256(first))"]
    CT --> SS
    B --> SS
    AK --> SRC["SessionIDForSource<br/>sha256('cpa-claude-source-session/'|AK|CT|src)"]
    CT --> SRC
    S --> SRC

    D --> UID["metadata.user_id<br/>{device_id, account_uuid, session_id}"]
    SS --> UID
    SRC -.->|genuine rewrite 时取代 SessionIDFor| UID
    SS --> H["X-Claude-Code-Session-Id"]
    SRC -.-> H
```

两条派生的分工（`identity.go:61-65`）：官方 Claude Code 在 main / title / prompt-suggestion 三类请求上**复用同一个 source session**，尽管它们的首条 user 消息不同；所以这些请求类不能走 `SessionIDFor` 的首消息派生，必须走 `SessionIDForSource`。

`metadata.user_id` 是一个**被 JSON 字符串包起来的 JSON**：字段顺序固定为 `device_id, account_uuid, session_id`（`buildJSONUserID`，`body.go:605-616`；导出版 `BuildJSONUserID`，`body.go:601`，供 sidecar 复用同一取值）。顺序由 `TestBuildJSONUserIDUsesClaudeCodeFieldOrder`（`body_test.go:396`）守护。

---

## prepared-request 管线

旧路径（`ApplyClaudeCodeBodyMimicry` + `ApplyClaudeCodeHeaders`）是"尽力而为"：失败就发原文。真实 Claude Code 流量经 Anthropic OAuth 转发时不能这样——身份绑定错了比不发更糟。prepared 管线因此把"分类 → 定策 → 准备 → 应用"拆成四步，**任何一步出错都 fail-closed**。

### 数据流

```mermaid
sequenceDiagram
    participant F as fork (调用方)
    participant M as mimicry
    participant U as 上游 (api.anthropic.com)

    F->>M: ClassifyClaudeCodeRequest(original)
    M-->>F: RequestClassGenuine / Generic / Unknown
    F->>M: NewClaudeCodeRequestPolicy(class, genuineMode)<br/>或 NewGenericClaudeCodeSynthesizePolicy()
    M-->>F: RequestPolicy{class, mode, valid}
    Note over F: 凭据调度 auth.Pool.Acquire → 得到 AccountKey/Kind
    F->>M: PrepareClaudeCodeRequest(body, model, id, policy, credentialKind)
    Note over M: 重新分类校验 class 未变<br/>改写 body / 绑定账号身份<br/>校验 metadata + billing
    M-->>F: BodyTransformResult (opaque, 带 sha256 摘要)
    Note over F: 此刻才读取最新 bearer（OAuth 可能已轮换）
    F->>M: ApplyClaudeCodePreparedRequest(req, token, accountKey, kind, stream, isAnthropicBase, result)
    Note over M: 校验 result → 校验凭据绑定 → 校验 beta 向量<br/>然后才 mutate req：写头 + 装 body（副本）
    M-->>F: nil / error
    F->>U: 发送（error 时必须放弃本次尝试，不得 failover）
```

**为什么 bearer 在 Apply 阶段才传**：`PrepareClaudeCodeRequest` 与实际发送之间可能隔着 sidecar bootstrap 的等待，期间 OAuth token 可能被刷新（`request_policy.go:197-200`）。

**准备错误绝不触发凭据 failover**（`request_policy.go:209-211`）：那是本地准备错误，不是凭据的问题；也不允许"退化成 preserve 把原文发出去"。

### 类与模式

| 类型 | 取值 | 含义 | 行号 |
|---|---|---|---|
| `RequestClass` | `Unknown` / `Generic` / `Genuine` | **仅从 body 判定，不信任任何请求头** | `request_policy.go:19-23`、`171-180` |
| `GenuineRequestMode` | `Unspecified` / `Preserve` / `Rewrite` | `GenuineRequestRewriteStripCCH` 是 `Rewrite` 的兼容别名（Deprecated） | `request_policy.go:41-50` |
| `GenericRequestMode` | `Legacy` / `Synthesize` | `Legacy` 走老 `ApplyClaudeCodeBodyMimicry`；`Synthesize` 是 fail-closed 账号绑定路径 | `request_policy.go:69-72` |

分类判据（`ClassifyClaudeCodeRequest`，`request_policy.go:171`）：body 能解析成非 null JSON object 且（`systemHasBillingBlock` 或 `hasClaudeCodeSystemPrefix`）→ `Genuine`；能解析但不匹配 → `Generic`；解析失败 → `Unknown`。

`RequestPolicy` 字段全私有（`request_policy.go:83-88`），调用方无法伪造 class/mode 组合；只能通过 `NewClaudeCodeRequestPolicy`（`:90`）或 `NewGenericClaudeCodeSynthesizePolicy`（`:113`）构造。

`BodyTransformResult`（`request_policy.go:129-141`）同样全私有 + 带 `bodyDigest [sha256.Size]byte`，Apply 时重算比对，防止调用方在两步之间改了 body。

### 四条处理路径

| policy | 行为 | 行号 |
|---|---|---|
| Generic + Legacy | `ApplyClaudeCodeBodyMimicry`，`accountIdentityApplied=false` | `request_policy.go:232-233` |
| Generic + Synthesize | 重建 system（外部计费块 + CC 引导语 + 原 blocks）、强制写 `metadata.user_id`、cache 断点、双重校验 | `request_policy.go:277-347` |
| Genuine + Preserve | **返回原始字节**，只读出 source session | `request_policy.go:236-238` |
| Genuine + Rewrite | 字节手术：只替换 `metadata.user_id` 与 `system[0].text` 两段 span | `request_policy.go:249-275`、`519-589` |

**Generic Synthesize 的计费块**（`buildExternalBillingBlock`，`request_policy.go:352-357`）刻意是 custom-base-url 形态：`cc_version=…; cc_entrypoint=cli;` —— **没有 `cch`，没有 `cc_prev_req`**，因为中继无法重新生成或重新绑定这两个一方字段。

**Genuine Rewrite 的字节手术**（`rewriteGenuineIdentity`，`request_policy.go:519`）：用 `requireJSONObjectMemberSpan` / `requireJSONArrayElementSpan`（`:624` / `:665`）定位 `metadata.user_id` 与 `system[0].text` 的原始字节区间，再 `applyByteReplacements`（`:719`）拼接。好处是**除这两处外整个 body 逐字节不变**（`TestGenuineRewriteChangesOnlyIdentityAndBillingTextValues`，`request_policy_test.go:324`）。计费文本只重写 `cc_version` 的值（`billingHeader.rewritten`，`:838`），`cc_entrypoint` 保留来源值。

### fail-closed 条件表

**`PrepareClaudeCodeRequest`（`request_policy.go:212`）**

| 触发条件 | 错误 | 行号 |
|---|---|---|
| `policy.valid == false` | `invalid Claude request policy` | `:213-215` |
| `id.AccountKey` 为空白 | `empty upstream credential account key` | `:216-218` |
| `credentialKind` 不是 `oauth`/`apikey` | `unsupported upstream credential kind %q` | `:219-221` |
| 重新分类结果 ≠ policy.class（body 在定策后被改） | `claude request class changed: policy=… body=…` | `:222-225` |
| Genuine 模式不是 Preserve/Rewrite | `unsupported genuine request mode` | `:241-242` |
| class 为 Unknown | `cannot transform an unknown Claude request class` | `:244-245` |

**`transformGenuineRewrite`（`:249`）**

| 触发条件 | 错误 | 行号 |
|---|---|---|
| `credentialKind != KindOAuth` | `rewrite requires an OAuth credential` | `:250-252` |
| `AccountKey` 空 | `rewrite requires a non-empty account key` | `:253-255` |
| `AccountUUID` 空 | `rewrite requires the OAuth account UUID` | `:256-258` |
| `ClientToken` 空 | `rewrite requires a downstream client token` | `:259-261` |
| body 的 `metadata.user_id.session_id` 缺失/为空 | `rewrite requires a genuine source session: …` | `:262-268` |

**`rewriteGenuineIdentity`（`:519`）**

| 触发条件 | 错误 | 行号 |
|---|---|---|
| body 非合法 JSON | `genuine body is not a JSON object` | `:520-522` |
| 无 `metadata` / `metadata.user_id` / `system` 字段 | `JSON object has no %q field` | `:524-537`（经 `:657`） |
| 上述字段**重复出现** | `JSON object has duplicate %q fields` | `:660-661` |
| `system` 不是数组或无 element 0 | `JSON array has no element 0` | `:540-543` |
| `system[0]` 非 object / 非 text 块 / `text` 非字符串 | `system[0] is not a …` | `:862-872` |
| `system[0]` 不是计费块 | `system[0] is not a billing block` | `:877-879` |
| 计费文本不以 `;` 结尾 / 有空字段 / 字段无 `=` / 键或值为空 / 字段重复 | 见 `parseBillingText` | `:776-813` |
| 计费块缺 `cc_version` 或 `cc_entrypoint` | `billing header has no … field` | `:815-820` |
| `cc_entrypoint` 不是 `cli` 或 `sdk-cli` | `unsupported cc_entrypoint %q` | `:830-832` |
| **计费块含 `cch` 或 `cc_prev_req`** | `genuine rewrite does not accept first-party billing field %q` | `:556-560` |
| `system[1..]` 里还有第二个计费块 | `genuine system contains multiple billing blocks` | `:893-895` |
| 替换后 metadata 与身份不符 | `refusing partial identity rewrite: metadata verification failed` | `:582-584` |
| 替换后 billing 校验失败 | `refusing partial identity rewrite: …` | `:585-587` |

> `cch` / `cc_prev_req` 拒收的理由（`request_policy.go:205-207`、`fingerprint`/`body.go` 注释）：custom-base-url 的 Claude Code **本来就不发这两个字段**；如果它们意外出现，说明这是一路 first-party 流量，而代理既无法重新生成 `cch`（真算法未知），也无法重新绑定 `cc_prev_req`（需要保留上游 response request-id 的状态）。宁可失败也不转发一个无法安全再生的值。

**`transformGenericSynthesize`（`:277`）**

| 触发条件 | 错误 | 行号 |
|---|---|---|
| 非 OAuth 凭据 | `generic synthesis requires an OAuth credential` | `:278-280` |
| `AccountKey` / `AccountUUID` / `ClientToken` 任一为空 | 对应 `generic synthesis requires …` | `:281-289` |
| body 非 JSON object | `generic body is not a JSON object` | `:291-294` |
| 无 `messages` 数组（或不是 `[` 开头） | `generic body requires a messages array` | `:295-300` |
| 合成后 metadata 不匹配身份 | `refusing partial generic synthesis: metadata verification failed` | `:340-342` |
| 合成后 billing 校验失败 | `refusing partial generic synthesis: …` | `:343-345` |

**`ApplyClaudeCodePreparedRequest`（`:390`）—— 全部校验在 mutate `req` 之前完成**

| 触发条件 | 错误 | 行号 |
|---|---|---|
| `req == nil` | `nil upstream request` | `:391-393` |
| result/policy 无效、`body == nil`、`credentialAccountKey` 空 | `unprepared Claude request` | `:467-469` |
| result 的 kind 非法 | `prepared Claude request has an invalid credential kind` | `:470-472` |
| **body 摘要与 `bodyDigest` 不符**（两步之间被改） | `prepared Claude request body was mutated` | `:473-475` |
| 重新分类与 policy.class 不符 | `prepared Claude request class no longer matches its body` | `:481-483` |
| Generic Synthesize 的产物分类不是 Genuine | `prepared generic synthesis is not a Claude Code body` | `:477-480` |
| Generic Synthesize 无 OAuth 身份 / 无 sessionID | `prepared generic synthesis has no OAuth account identity` | `:484-487` |
| Generic Synthesize metadata / billing 复核失败 | 对应 `prepared generic synthesis …` | `:488-493` |
| Genuine Rewrite 无身份 / 无 sessionID | `prepared rewrite has no account identity` | `:495-498` |
| Genuine Rewrite metadata / billing 复核失败 | 对应 `prepared rewrite …` | `:499-504` |
| `credentialToken` 空白 | `empty upstream credential` | `:397-399` |
| `credentialAccountKey`/`credentialKind` 与 result 绑定不符 | `prepared request credential binding mismatch` | `:400-402` |
| **Genuine Rewrite 且下游未提供 `Anthropic-Beta`** | `genuine rewrite requires the downstream Anthropic-Beta feature vector` | `:403-410` |
| Genuine 非 Preserve 且非合法 Rewrite | `invalid prepared genuine rewrite` | `:442-443` |
| class 非法 | `invalid prepared request class` | `:450-451` |

> **beta 向量为什么必须由下游提供**（`:405-409`）：真实 CC 的请求 beta 是"请求类 + 上下文模式"的特征向量——main、1M、title 三者不同——不是一个全局版本常量。缺了下游向量就无法安全合成正确的 2.1.220 列表，于是 fail-closed，而不是把所有请求默认成 `Full`。

### Apply 阶段各路径写的头

| policy | 头处理 | 行号 |
|---|---|---|
| Generic + Legacy | `ApplyClaudeCodeHeaders`（客户端值优先） | `:417` |
| Generic + Synthesize | `ApplyClaudeCodeHeaders` → `forcePinnedClaudeCodeProfile` → 强制 `Anthropic-Beta=Full`、`Accept: application/json`、`X-Claude-Code-Session-Id=result.sessionID`、（first-party 时）新 `x-client-request-id` | `:418-429` |
| Genuine + Preserve | **保留客户端自己的版本/profile 头**；只 `applyCredentialHeader`、补 `Content-Type`、以 body 的 session 覆盖 `X-Claude-Code-Session-Id` | `:431-441` |
| Genuine + Rewrite | `ApplyClaudeCodeHeaders` → `forcePinnedClaudeCodeProfile` → `Accept: application/json`、`X-Claude-Code-Session-Id=result.sessionID`（**`Anthropic-Beta` 不动，保留下游向量**） | `:445-448` |

body 装载走 `installPreparedBody`（`:457-464`）：`bytes.Clone` 后同时设置 `req.Body`、`req.ContentLength` 与 `req.GetBody`（重试/重定向必需）。

### 辅助导出

`ClaudeCodeSourceSessionID(body) (string, bool)`（`request_policy.go:186`）：仅对 Genuine 请求返回客户端 metadata 里的 session。CLAUDE.md 的建议是——sticky slot 的 key 应优先用它，而不是可能冲突的 ingress 头，因为 prepared 头层也把 body 当作权威。

---

## Codex 指纹

Codex 侧和 Claude 侧结构相似但**没有 prepared 管线**，也没有计费块 / 身份派生这一套。

### 头（`ApplyCodexCLIHeaders`，`codex.go:58`）

```go
func ApplyCodexCLIHeaders(req *http.Request, accessToken, accountID string, isCompact bool)
```

| Header | 值 | 备注 | 行号 |
|---|---|---|---|
| `Authorization` | `Bearer <accessToken>` | 强制 | `:59` |
| `Content-Type` | `application/json` | | `:60` |
| `Accept` | `application/json`（compact）/ `text/event-stream` | | `:61-65` |
| `OpenAI-Beta` | `responses=experimental` | HTTP POST 路径；WS 用 `responses_websockets=2026-02-06` | `:66` |
| `Accept-Encoding` | `identity` | **传输必要性，非 capture 指纹** —— 保证 SSE 与 4xx 错误体端到端可读 | `:67` |
| `Connection` | `Keep-Alive` | | `:68` |
| `Session_id` | 每请求新 UUID | | `:69` |
| `Version` | `0.144.4` | | `:70` |
| `Originator` | `codex-tui` | | `:71` |
| `User-Agent` | `CodexCLIUserAgent` | **强制覆盖**——转发 `curl/8.x` 会被 Cloudflare 边缘 403 | `:72` |
| `Chatgpt-Account-Id` | `accountID`（非空时） | | `:73-75` |

**刻意不复制**的 WS/TUI-only 头（`codex.go:24-29`）：`x-codex-turn-metadata`（含 workspace + git 状态）、`x-codex-window-id`、`x-codex-beta-features`、`thread-id`。代理没有真实 workspace/window，伪造比省略更像假的。

### 体（`SanitizeCodexRequestBody`，`codex_body.go:97`）

与 Claude 侧"加东西"的逻辑相反，Codex 侧主要是**收窄到后端接受的子集**：

| 动作 | 细节 | 行号 |
|---|---|---|
| 剥 thinking 后缀 | `gpt-5.3-codex(high)` → `gpt-5.3-codex`（`StripThinkingSuffix`，`:322`） | `:110-113` |
| 强制 `stream=true` | 后端只用 SSE 发 completed；非流式客户端在我们这侧聚合 | `:117` |
| 强制 `store=false` | | `:120` |
| 强制 `include=["reasoning.encrypted_content"]` | | `:127` |
| **`parallel_tool_calls` 原样透传** | 曾硬编码 `true`，会打掉 gpt-5.6 需要的 `false` → Responses-Lite 报 invalid_request_error（`crack/codex/SPEC.md` §5） | `:121-126` |
| 删字段 | `prompt_cache_retention`、`safety_identifier`、`stream_options`、`max_output_tokens`、`max_completion_tokens`、`temperature`、`top_p`、`truncation`、`user`、`context_management` | `:135-148` |
| **保留 `previous_response_id`** | Codex CLI 靠它串多轮；剥掉会让每轮冷启动并可能触发 CF 限流突刺 | `:130-134` |
| `service_tier` | 只留 `priority`，其余删 | `:151-153` |
| `input` 字符串 → 规范 message 形态 | | `:157-166` |
| `role: system` → `developer` | Codex 在 input 里拒绝 `system` | `:170-178` |
| reasoning item 修复 | 删服务端 `id`（store=false 下回放会 404 `Item with id 'rs_…' not found`），缺失 `summary` 补 `[]`（`filterCodexInputItems`，`:265`） | `:178` |
| 内置工具别名归一 | `web_search_preview{,_2025_03_11}` → `web_search`（`:284`、`:311`） | `:181` |
| `instructions` 兜底为 `""` | 后端要求键存在 | `:184-187` |
| `image_generation` 工具注入 | `ensureImageGenerationTool`（`:352`）：`*spark` 与 gpt-5.6 家族（`codexResponsesLiteModel`，`:340`）**跳过**，其余补齐 | `:191` |

`/v1/responses/compact` 是另一套更严的白名单（`sanitizeCodexCompactRequestBody`，`:207`），只保留 8 个字段：`model, input, instructions, tools, parallel_tool_calls, reasoning, text, previous_response_id`。

路由辅助：`CodexOAuthPath`（`:73`）把 `/v1/responses/compact` 映到 `/responses/compact`，其余一律 `/responses`；`JoinCodexAPIKeyUpstreamURL`（`:46`）解决两个 fork 长期不一致的 BaseURL 拼接（带 path 的 BaseURL 权威，剥掉入站 `/v1`；裸 origin 则保留完整入站 path）。

### Claude 与 Codex 的差异速查

| 维度 | Claude | Codex |
|---|---|---|
| 身份锚 | `SimIdentity` → device/session 内容寻址 | 无；只有 `Chatgpt-Account-Id` + 每请求随机 `Session_id` |
| 计费块 | `system[0]` 的 `x-anthropic-billing-header` | 无 |
| beta | `Anthropic-Beta`，随请求类/上下文模式变化 | `OpenAI-Beta` 单值常量 |
| `Accept-Encoding` | `gzip, br`（复刻 capture） | `identity`（传输需要，非指纹） |
| body 策略 | **注入**（system、cache 断点、metadata） | **收窄**（删字段、白名单、归一） |
| fail-closed 管线 | 有（prepared-request） | 无 |

---

## 与 `crack/` 的对应关系

| capture 目录 | 锚定的常量 / 行为 |
|---|---|
| `crack/cc2220/SPEC.md` §「Client environment」+「Main /v1/messages request」 | `CLICurrentVersion`、`ClaudeCLIUserAgent`、`ClaudeStainless{Lang,Runtime,RuntimeV,PackageV,Arch,Timeout,RetryCnt}`、`ClaudeAnthropicVersion` |
| `crack/cc2220/SPEC.md` §1a（2026-07-31 Linux，双模式同会话） | `ClaudeAnthropicBetaFull`（13 项非 1M）、`ClaudeAnthropicBeta1M`（15 项，单样本） |
| `crack/cc2220/SPEC.md` §1b（4 个 count_tokens 样本） | `ClaudeAnthropicBetaCountTokens`、`headers.go:52` 的路径判定、`headers.go:89-92` 的 timeout 省略 |
| `crack/cc2220/SPEC.md` §「Billing, fingerprint suffix, and cch」+「cch 穷尽静态分析」 | `fingerprintSalt`、`computeClaudeCodeFingerprint` 的 UTF-16 `[4,7,20]` 语义、`cchSeed` 被标注为 legacy、`cch`/`cc_prev_req` 仅 firstParty 出现（→ prepared 管线的拒收规则） |
| `crack/cc2220/SPEC.md` §「Identity and session invariants」 | 头 `X-Claude-Code-Session-Id` 与 `metadata.user_id.session_id` 必须 37/37 一致 → `ApplyClaudeCodePreparedRequest` 用同一个 `result.sessionID` 同时写头与体 |
| `crack/cc2220/SPEC.md` §「Multi-turn cc_prev_req」+ `chain-redacted.json` | 证明 `cc_prev_req` = 上一条 main 响应的 `request-id`（main 9/9、prompt-suggestion 6/6）→ 代理无状态、不合成 |
| `crack/cc2220/SPEC.md` §「Title/Haiku request」 | Haiku/title 是独立请求类（9 项 beta、三块 system、`thinking:disabled`）→ `body.go:100` 对 haiku 整体跳过，代理不合成 title 调用 |
| `crack/cc2220/ANALYSIS.md` | capture 的完整性、cch 验证（0/37）、指纹后缀验证（UTF-16 通过 / rune 在 emoji 上失败）、多轮链验证的原始结论 |
| `crack/cc2214/SPEC.md` §3 | `ClaudeReportedBetas` 的 9 项 1M 变体（sidecar 遥测用） |
| `crack/apikey/rows/*-POST-…v1_messages` | `ClaudeAnthropicBetaApikey` |
| `crack/COMPARE.md` §3.2–3.5 | OAuth vs apikey 的 beta 三项差集（`oauth-2025-04-20` / `advanced-tool-use-2025-11-20` / `cache-diagnosis-2026-04-07`）、system 块数差异（4 vs 3）、cache_control 分层差异 —— 解释了 `headers.go:63-68` 为什么必须分 kind 选表 |
| `crack/codex/SPEC.md`「Original 0.135.0 capture」 | `CodexOriginator`、UA/Version 头格式、`CodexUsageUserAgent` |
| `crack/codex/SPEC.md` 2026-07-10 / 2026-07-14 两节 | `CodexCLIVersion`/`CodexCLIUserAgent` 提升到 `0.144.4`（无新 capture，wire 中立） |
| `crack/codex/SPEC.md` §5 | `parallel_tool_calls` 透传、`/compact` 白名单 4→8 字段、`codexResponsesLiteModel` 跳过 `image_generation` |
| （无 capture，来自 2.1.197 bundle 反编译） | `dateline.go` 的 `rdp`/`odp`/`qla` 三函数语义与四种撇号码点 |

---

## 版本升级 checklist

以下步骤对应 `crack/README.md`「Bumping a fingerprint target」与 `crack/cc2220/SPEC.md`「cc-core edit checklist」，是**可直接执行**的顺序。

### A. Claude Code 版本升级（如 2.1.220 → 2.1.2xx）

1. **抓包**：whistle 起代理，`NODE_EXTRA_CA_CERTS` 指向 whistle CA（**不要**关 TLS 校验），跑一次完整会话：全新登录 → bootstrap → ≥10 个独立首轮 → 一段 ≥10 轮的连续对话。导出 dump JSON。
2. **抽取**：`python3 crack/scripts/extract_live.py <dump.json> crack/cc<ver>/rows`。原始 dump 永不入库。
3. **写 SPEC**：`crack/cc<ver>/SPEC.md`，以"相对上一目标的 diff + cc-core 编辑清单"格式撰写。至少覆盖：client environment、main 请求头/beta/body、`count_tokens` 类、title/quota 类、billing/cch、identity 不变式、telemetry、startup 面。
4. **改常量（一次性全改，不要分批）**——`mimicry/fingerprint.go`：
   - `CLICurrentVersion`（`:40`）与 `ClaudeCLIUserAgent`（`:41`）**必须同版本号**。
   - `ClaudeStainlessRuntimeV`（`:48`）/ `ClaudeStainlessPackageV`（`:49`）如 capture 有变则同步；注意 `RuntimeV` 同时喂 sidecar 遥测 `env.node_version`。
   - `ClaudeAnthropicBetaFull`（`:81`）以**非 1M**样本为准；`ClaudeAnthropicBeta1M`（`:94`）以 1M-active 样本为准；`ClaudeAnthropicBetaCountTokens`（`:100`）以 `count_tokens` 样本为准。逐字复制，**顺序不能改**。
   - `ClaudeReportedBetas`（`:116`）只在遥测体样本变化时改，与请求 beta 分开判断。
   - `ClaudeAnthropicBetaApikey`（`:126`）只有拿到新的 apikey 路径 capture 才改。
   - 不要把抓包主机的 OS/终端/shell 写进 `ClaudeStainlessOS`（`:50`）或 `auth.HostProfile`。
5. **改 body/header 形状**（如 capture 显示布局变了）：`body.go:272` 的 system 断点分层、`body.go:485` 的 message 断点位置、`headers.go` 的请求类分支。
6. **同步 sidecar**：`sidecar/sidecar.go` 的 `ccBuildTime`（capture 的 `build_time`）、各 endpoint 的 UA 族（`claude-cli/` vs `claude-code/` vs `axios/`）、bootstrap 步骤与鉴权标志。
7. **补测试**：beta 列表逐字断言进 `mimicry/headers_test.go`；指纹算法变化补 `body_test.go` 的 UTF-16 向量。
8. `go build ./... && go test ./... && go vet ./...`（`sidecar` 套件约 23s 真实计时）。
9. **打 tag**：`git tag v0.8.NN && git push origin main v0.8.NN`（tag 号被占就用下一个空号；打 tag 前 `git status` 确认只提交自己的文件）。
10. **两个 fork 各自** `go get github.com/wjsoj/cc-core@v0.8.NN && go mod tidy`，重新构建部署。

### B. Codex 版本升级

若只是版本号推进（无新 capture、wire 中立）：只改 `mimicry/codex.go:35-36` 两个常量，并在 `crack/codex/SPEC.md` 顶部追加一节说明"无新 capture + 为什么 wire 中立"。若有新 capture，再评估 `OpenAI-Beta`、body 白名单与 `auth/codex_models.go` 的模型目录 / `pricing` 目录（新模型不加会按 0 计费）。

### C. 硬性红线

- 没有 capture 支撑，**不要手改**任何 UA / beta / body 形状；diff 必须落到 `crack/cc<ver>/SPEC.md`。
- 不要把 `cch` "修正"成 `00000`（`TestCCHIsNeverPlaceholder` 会挂）。
- 不要为了让 Genuine Rewrite "能跑"而放宽 `cch`/`cc_prev_req` 或 beta 向量的拒收条件。

---

## 相关测试索引

| 测试 | 守护的行为 | 位置 |
|---|---|---|
| `TestClaudeBetaListsMatchCapture` | 三条 beta 列表逐字匹配 capture | `headers_test.go:13` |
| `TestDefaultBetaListOmits1MOnlyBetas` | 默认列表不含 `context-1m` / `fallback-credit` | `headers_test.go:77` |
| `TestCountTokensHeaderClass` | `count_tokens` 用短列表且无 `X-Stainless-Timeout` | `headers_test.go:99` |
| `TestMainMessagesKeepsTimeoutAndFullBetas` | 主请求两者都有 | `headers_test.go:117` |
| `TestClientSuppliedBetasWinOnCountTokens` | 客户端 beta 优先 | `headers_test.go:134` |
| `TestAPIKeyPathUnaffectedByCountTokens` | apikey 路径不受 count_tokens 分支影响 | `headers_test.go:152` |
| `TestMimicrySmoke` | 端到端 body 改写形状 | `body_test.go:23` |
| `TestPerAccountStability` | 同账号 device_id 恒定 | `body_test.go:180` |
| `TestSessionStableAcrossTurns` | 多轮同会话 session_id 稳定 | `body_test.go:207` |
| `TestHaikuSkip` | Haiku 完全跳过 body mimicry | `body_test.go:226` |
| `TestAlreadyClaudeCode` | CC prompt 前缀命中即不改写 | `body_test.go:236` |
| `TestBillingBlockSkipsRewrite` | 计费块命中即不改写（缓存前缀保护） | `body_test.go:261` |
| `TestNoBetaGatedFieldInjection` | 不注入 `thinking`/`output_config`/`context_management`/`diagnostics` | `body_test.go:297` |
| `TestClientBetaGatedFieldsPassThrough` | 客户端自带的这些字段原样透传 | `body_test.go:313` |
| `TestCCHSigning` | cch 占位被替换且随 body 变化 | `body_test.go:327` |
| `TestClaudeCodeFingerprintUTF16Vectors` | ASCII / BMP / emoji 三类向量下的 `[4,7,20]` 语义 | `body_test.go:344` |
| `TestCCHIsNeverPlaceholder` | 永不发出 `cch=00000` | `body_test.go:375` |
| `TestBuildJSONUserIDUsesClaudeCodeFieldOrder` | user_id 字段顺序 | `body_test.go:396` |
| `TestClassifyClaudeCodeRequestFromBodyOnly` | 分类只看 body | `request_policy_test.go:62` |
| `TestLegacyBodyMimicryRejectsJSONNullWithoutPanic` | JSON `null` 不 panic | `request_policy_test.go:90` |
| `TestGenericSynthesizeIsStrictAccountBoundForEveryModel` | 合成路径对每个模型都账号绑定 | `request_policy_test.go:97` |
| `TestGenericSynthesizeFailsClosed` | 合成路径 fail-closed | `request_policy_test.go:148` |
| `TestGenuinePreserveIsByteExactAndKeepsClientProfile` | Preserve 逐字节不变、保留客户端 profile | `request_policy_test.go:175` |
| `TestGenuineRewriteIsAtomicAndConsistent` | Rewrite 原子性与头体一致 | `request_policy_test.go:237` |
| `TestGenuineRewriteAcceptsOfficialSDKCLIEntrypoint` | `cc_entrypoint=sdk-cli` 合法 | `request_policy_test.go:303` |
| `TestHashClaudeAccountKeyIsStableAndOpaque` | 审计哈希稳定且不泄露身份 | `request_policy_test.go:314` |
| `TestGenuineRewriteChangesOnlyIdentityAndBillingTextValues` | 字节手术只动两处 | `request_policy_test.go:324` |
| `TestGenuineRewriteRejectsDuplicateTargetKeys` | 重复 key 拒绝 | `request_policy_test.go:364` |
| `TestGenuineRewriteRetainsRequestSpecificBetaVector` | 保留下游 beta 向量 | `request_policy_test.go:383` |
| `TestGenuineRewriteRejectsMissingBetaWithoutMutation` | 缺 beta 时拒绝且不改 req | `request_policy_test.go:418` |
| `TestGenuineRewriteUsesSourceSessionAcrossRequestClasses` | main/title/suggestion 共享 source session | `request_policy_test.go:440` |
| `TestGenuineRewriteRejectsFirstPartyChainFields` | `cch`/`cc_prev_req` 拒收 | `request_policy_test.go:465` |
| `TestGenuineRewriteFailuresAreFailClosed` | 各类失败均 fail-closed | `request_policy_test.go:476` |
| `TestPreparedHeaderApplicationRejectsInvalidResultWithoutMutation` | 无效 result 不改 req | `request_policy_test.go:518` |
| `TestPreparedRequestRejectsCredentialBindingMismatchWithoutMutation` | 凭据绑定不符不改 req | `request_policy_test.go:531` |
| `TestPreparedRequestInitializesHeadersAndOwnsBodyCopy` | header 初始化 + body 副本所有权 | `request_policy_test.go:555` |
| `TestPrepareRejectsMissingCredentialBinding` | 缺凭据绑定即拒 | `request_policy_test.go:572` |
| `TestNormalizeDateline_AllBeaconVariants` | 四种撇号 × 两种分隔符 | `dateline_test.go:5` |
| `TestNormalizeDateline_NoOpAndBytePreserving` | 规范形态返回原 slice | `dateline_test.go:36` |
| `TestNormalizeDateline_MixedSeparatorNotMatched` | 混合分隔符不误伤用户文本 | `dateline_test.go:54` |
| `TestSanitizeCodexRequestBody_*`（5 个） | Codex 主/compact/system→developer/reasoning-id/Responses-Lite | `codex_body_test.go:61,135,167,213,356` |
| `TestEnsureImageGenerationTool` | spark / gpt-5.6 跳过注入 | `codex_body_test.go:262` |
| `TestJoinCodexAPIKeyUpstreamURL` | BaseURL 拼接两种形态 | `codex_body_test.go:383` |
| `TestStripThinkingSuffix` / `TestCodexOAuthPath` | 模型名与路径映射 | `codex_body_test.go:8,32` |

---

## 文件清单

| 文件 | 行数 | 职责 |
|---|---|---|
| `mimicry/fingerprint.go` | 184 | 全部 Claude 版本/UA/beta/cache 常量、`NewRequestUUID`、`UUIDFromBytes`、`ensureHeader` |
| `mimicry/headers.go` | 115 | `ApplyClaudeCodeHeaders`、`KindOAuth`/`KindAPIKey`、`count_tokens` 请求类分支 |
| `mimicry/body.go` | 616 | `ApplyClaudeCodeBodyMimicry` 与全部 body 变换、`computeClaudeCodeFingerprint`、`signBillingHeaderCCH`、`BuildJSONUserID` |
| `mimicry/identity.go` | 76 | `SimIdentity`、`DeviceIDFor`、`SessionIDFor`、`SessionIDForSource` |
| `mimicry/request_policy.go` | 943 | prepared-request 全管线：分类、策略、准备、应用、JSON span 字节手术、billing 解析与校验 |
| `mimicry/dateline.go` | 91 | `NormalizeDateline` —— 抹除日期句 3 bit 隐写信标 |
| `mimicry/codex.go` | 82 | Codex 常量 + `ApplyCodexCLIHeaders` |
| `mimicry/codex_body.go` | 372 | `SanitizeCodexRequestBody`、compact 白名单、`CodexOAuthPath`、`JoinCodexAPIKeyUpstreamURL`、工具归一 |
| `mimicry/headers_test.go` | 161 | beta 列表与请求类断言 |
| `mimicry/body_test.go` | 402 | body 改写、跳过条件、指纹向量、cch |
| `mimicry/request_policy_test.go` | 587 | 管线各条 fail-closed 路径 |
| `mimicry/dateline_test.go` | 71 | 信标变体与不误伤 |
| `mimicry/codex_body_test.go` | 407 | Codex body 各分支 |

**包外消费者**（`mimicry.` 引用统计）：`sidecar/sidecar.go`（34 处，遥测/bootstrap 复用版本、UA、`ClaudeReportedBetas`、`BuildJSONUserID`、`DeviceIDFor`）、`codexws/headers.go`（7 处）、`auth/login_probes.go`（2 处）、`auth/codex_usage.go`（1 处）。改任何一个导出常量前先看这三处。

---

## 相关页面

[Crack](Crack) · [Sidecar](Sidecar) · [Auth-Pool](Auth-Pool)
