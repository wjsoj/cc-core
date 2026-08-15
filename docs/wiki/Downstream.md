# downstream —— 返回给客户端的响应清洗

`mimicry` / `sidecar` / `crack` 都在处理**上行**：让我们发给 Anthropic 的东西像真实客户端。`downstream` 是反方向的那一半：**我们回给客户端的东西，应该像一个普通的 Anthropic 兼容网关，而不是一根从凭据池直通上游的透明管道。**

## 问题

转发上游响应头会把我们凭据池的运行状态直接交给下游用户。一条来自 `api.anthropic.com` 的 200 就带着（`crack/claudev2.1.224/rows/13-v1_messages.json`）：

```
anthropic-ratelimit-unified-status                  ← 服务该请求的账号的配额裁决
anthropic-ratelimit-unified-5h-status/-reset/-utilization
anthropic-ratelimit-unified-7d-status/-reset/-utilization
anthropic-ratelimit-unified-representative-claim
anthropic-ratelimit-unified-fallback-percentage
anthropic-ratelimit-unified-reset
anthropic-ratelimit-unified-overage-status
anthropic-ratelimit-unified-overage-disabled-reason
anthropic-organization-id                           ← 我们的组织 UUID
anthropic-workspace-id                              ← 我们的工作区
request-id / traceresponse / cf-ray / cf-cache-status
server: cloudflare / server-timing
```

12 个配额头合起来就是：**这个账号买的是哪档订阅、5h 和 7d 各用掉多少、有没有开超额、窗口在哪个 unix 时间戳重置**。加上组织与工作区 UUID，足以指纹化并主动探测我们的池子。这些没有一样是调用方的。

## 为什么剥离是安全的，而不是猜测

`crack/claudev2.1.226-inbound/SPEC.md §4` 记录了对照：真实第三方网关**一个 `anthropic-*` 响应头都不返回**，只有 `content-type` / `cache-control` / `vary` / `content-encoding` 和它自己的 correlator，而真实 Claude Code 对着它工作完全正常。所以白名单是**已知可行的行为**。

## 白名单

允许放行的**全部**内容（`downstream/headers.go`）：

| Header | 理由 |
|---|---|
| `Content-Type` | 没有它客户端无法解析响应体 |
| `Cache-Control` | SSE 正确性，中间层依赖它 |
| `Retry-After` | 调用方唯一真正需要的限流信息 |
| `Vary` | 两侧抓包都有，缓存中间层需要 |
| `Content-Encoding` | **仅在我们没有解码时存活**。`stream.Decompress` 会为 gzip/br 删掉它；它放行的编码（zstd、deflate）必须声明，否则客户端读不了字节 |

**刻意是白名单，不是黑名单。** 黑名单要在 Anthropic 每次加头时同步维护，而漏掉的失败模式是静默泄漏 —— `anthropic-workspace-id` 就是这样一路发到客户端、直到 2026-08 的抓包才第一次被命名的。

被丢弃的头及其理由写在 `headers.go` 的注释块里，逐条列明，避免后来者想当然地加回去。

## Retry-After 的保全

清洗必须发生在 fork 已经读完限流头做调度判断**之后**、拷贝给客户端**之前**。但 429 场景下还有一个坑：如果 Anthropic 没发 `Retry-After`，客户端的退避就只能靠 `anthropic-ratelimit-unified-*-reset` —— 而那正是我们要删的。

所以 `ScrubUpstreamHeaders` 是**一个函数而不是两个**：它先从 unified reset 合成 `Retry-After`，再执行白名单。派生所依赖的信息在几行之后就被删掉了，拆成两个调用迟早会有人搞反顺序。

合成规则：

- 上游自带 `Retry-After` 则**原样保留**（它是权威值）。
- 取三个 reset 里**最近的一个未来时间**（而非 representative）—— 把最长的窗口交给客户端会让它白等。
- **向上取整到分钟**：等久一点是对的，早重试是错的；同时使派生值无法反推出精确的 reset 时间戳。
- **上限 1 小时**：5h 窗口耗尽本会产生长达 5 小时的延迟，那既公布了我们池子窗口的精确边界，客户端体验也比"早点重试、再被告知一次"更差。

## API

| 函数 | 用途 |
|---|---|
| `CopyResponseHeaders(dst, src, now)` | **响应写出处应该用的入口。** 清洗 `src` 的副本后追加到 `dst` |
| `ScrubUpstreamHeaders(h, now)` | 就地清洗一个我们独占的 header map |
| `HeaderAllowed(name)` | 单个头的判定，大小写无关 |
| `ScrubErrorPayload(b)` | 剥离错误 JSON 里的 `request_id`，并 redact message free-text 中的 UUID / `req_` 标识 |
| `ScrubSSELine(event, line)` | 仅对 `event: error` 帧做同样处理，保留 `data:` 前缀、空格与换行 |

`CopyResponseHeaders` 存在的意义是让两种错法不可能发生：

1. **清洗 `dst`** —— 会连 fork 自己设的头一起删掉（`X-Provider-Restricted`、`X-Client-Blocked`、以及它自己算出的 `Retry-After`），那些是在写上游响应之前设的。
2. **就地改 `src`** —— 调用方可能还要用：重试循环会在写出之后再读一次被扣留响应的限流头。

## SSE 只拦 error 帧

`ScrubSSELine` 只在 `event == "error"` 时做事，靠 `SSEScanner.Event()` 一次字符串比较拦截。一次响应里中继要经手成千上万条 `content_block_delta`，为了找一个只在错误里出现的字段而对每条都跑一遍 JSON 解码，是实打实的成本换零收益。

错误体的处理与请求侧不同：**不做字节手术**。请求体要对齐抓包所以键顺序重要；网关返回的错误形状是它自己的，没有 capture 要匹配，`encoding/json` 往返即可。

## Codex：两条白名单够不着的泄漏通道

`downstream/headers.go` 的做法之所以成立，是因为 Anthropic 侧**所有敏感信息都以响应头的形式到达**，一个白名单就能拦全。Codex 不是这样——它从两个 header 白名单永远看不到的地方漏出去，于是有了 `downstream/codex.go`。

ground truth：`crack/codexapp0.147.0/rows/10`（握手）与 `rows/13`（每种服务端事件各一条样本）。

### 1. WebSocket 的 101 响应头

一个 101 不是普通响应，原样转发等于把这些交给调用方：

| 头 | 泄漏什么 |
|---|---|
| `cf-ray` | **后缀就是 Cloudflare 数据中心代码**，直接定位我们的出口 |
| `set-cookie` | 上游的 `__cf_bm` bot-management 状态 |
| `x-models-etag` | 每账号的模型目录版本；**能把两次请求关联到同一个上游账号** |
| `x-openai-proxy-wasm` | 上游基础设施版本 |
| `cf-cache-status` / `server` / `report-to` / `nel` 等 | 基础设施指纹，且点名了服务商 |

放行的**只有** 4 个协议头（`allowedWSHandshakeHeaders`，`downstream/codex.go:42`）：`Connection`、`Upgrade`、`Sec-Websocket-Accept`、`Sec-Websocket-Extensions`（另有 `Sec-Websocket-Protocol`，仅在协商过子协议时出现）。

| 函数 | 用途 | 行号 |
|---|---|---|
| `WSHandshakeHeaderAllowed(name)` | 单头判定，大小写无关 | `codex.go:67` |
| `ScrubWSHandshakeHeaders(h)` | 就地清洗一个我们独占的 header map | `codex.go:77` |
| `CopyWSHandshakeHeaders(dst, src)` | **写出处应该用的入口**：清洗 `src` 的副本后追加到 `dst` | `codex.go:93` |

与 HTTP 侧同一条纪律：**清洗上游那份，绝不清洗 `dst`**（`dst` 里已经有代理自己设的头），也**绝不就地改 `src`**（调用方还要用它做 401/403/429 的凭据分类，见 [Transports](Transports) → `Conn.HandshakeResponse()`）。

这里不需要像 HTTP 侧那样"先派生再删除"：101 上根本没有限流信息，Codex 把限流放在流里。

### 2. 流内事件帧

| 帧类型 | 泄漏什么 | 处置 | 行号 |
|---|---|---|---|
| `codex.rate_limits` | `plan_type`、`used_percent`、`window_minutes`、`reset_after_seconds`、`reset_at`、`credits.balance`、`promo` | **重写**为 `{allowed, limit_reached}` | `codex.go:113`、`253` |
| `codex.response.metadata` | `x-models-etag`、加密的 `x-codex-turn-state`、内部安全模型名 | **整帧丢弃** | `codex.go:118` |
| `responsesapi.websocket_timing` | `engine_ids`（如 `gpt56sol-codex-a-c321`）、队列深度、每引擎的缓存/非缓存 prompt token 总量 | **整帧丢弃** | `codex.go:123` |

`codex.rate_limits` 是 Codex 版的"十二个 `anthropic-ratelimit-unified-*` 头"——同样的披露，只是到达的位置让 header 白名单完全够不着。保留 `allowed` / `limit_reached` 是因为**被限流的客户端有正当理由知道自己被限流了**，但它没有理由知道是谁的配额、还剩多少、窗口什么时候滚动。

此外，`response.created` / `.in_progress` / `.completed` 上回声的 `response` 对象里有三个字段被删（`codexResponseObjectFields`，`codex.go:132`）：

- **`safety_identifier`** —— 字面就是服务该请求账号的 `user-<chatgpt_user_id>`；
- `service_tier` —— 该账号解析到的档位；
- `prompt_cache_retention` —— 我们账号的上游缓存策略。

| 函数 | 用途 | 行号 |
|---|---|---|
| `ScrubCodexEvent(frame)` | WS 帧形态；返回 `(要转发的帧, 是否转发)` | `codex.go:163` |
| `ScrubCodexSSELine(line)` | HTTP/SSE 形态的同一套逻辑，处理 `data: {...}` 行 | `codex.go:197` |
| `CodexEventDropped(eventType)` | 不做实际工作地判断该类型是否会被整帧丢弃（给指标/日志用） | `codex.go:328` |

三条实现纪律：

1. **热路径先走子串扫描。** 抓到的那一轮 541 帧里有 495 条（**91%**）是 `*.delta`，它们必须只付一次 `bytes.Contains` 的代价，而不是一次 JSON 解析。命中子串后还要用 `codexEventType`（`codex.go:231`）复核 `"type"` 字段，防止类型名出现在工具参数或错误文本里造成误伤。
2. **无法解析的 `codex.rate_limits` 一律 fail-closed（丢弃）**（`codex.go:260-265`）。这个帧是咨询性的，丢掉不影响进展；而一个未知形状里完全可能带着我们正要删的字段。
3. **`scrubCodexResponseObject` 是 cc-core 里唯一允许 map 往返的地方**（`codex.go:287`）。map 会重排 key，而 key 顺序只在**我们向上游伪装客户端**时才重要；这里是我们回给自己下游调用方的响应，且每轮只跑 3–4 帧。

### 尚未覆盖

**Codex 方向的 `Retry-After` 合成还没有。** `ensureRetryAfter` 目前只读 `Anthropic-Ratelimit-Unified-*`，而这次抓包里没有出现任何 Codex 的 429，没有可依据的形状（`crack/codexapp0.147.0/SPEC.md` §7）。在拿到一次真实的 Codex 429 之前不要照猜。

## 已知残留

- **`usage.cache_creation.ephemeral_1h_input_tokens`。** 客户端在自定义 base URL 下只能发裸 `ephemeral`，而 `mimicry` 会把断点升级成 1h（见 [mimicry](Mimicry) 的 cache_control 修补），于是响应里报的是 1h 档的 cache-creation 数字。细心的客户端能据此推断请求被中间层改过。折算回 5m 需要知道客户端原本要什么，是响应清洗层拿不到的状态，且会篡改 fork 自己也在解析的计费数字 —— 记录在案，暂不处理。
- **`message_start.message.id`** 仍是 Anthropic 的 `msg_01…` 格式，与网关自己的 id 格式不同。它不暴露我们的账号，且改写它可能破坏做 id 关联的客户端，故保留。

## 测试

`downstream/headers_test.go` 直接拿 `crack/claudev2.1.224/rows/13` 的**真实完整响应头集合**做输入 —— 过滤的是真货，不是挑出来的子集。`TestScrubbedHeadersAreGoneIndividually` 逐条断言，这样将来某次改动放行了其中一个，失败信息里会直接带上那个头的名字。

`TestScrubIsNearlyNoOpOnGatewayResponse` 反向验证白名单没有过紧：对着我们要模仿的网关响应，清洗应该几乎什么都不做。

Codex 侧在 `downstream/codex_test.go`：

| 测试 | 断言 | 位置 |
|---|---|---|
| `TestScrubWSHandshakeHeaders` | 101 只剩 4 个协议头 | `:12` |
| `TestCopyWSHandshakeHeadersLeavesSrcAndDstAlone` | 不改 `src`、不清洗 `dst` | `:62` |
| `TestScrubCodexEventRewritesRateLimits` / `…PreservesLimitReached` | 重写成 `{allowed, limit_reached}`，且被限流状态不丢 | `:94,127` |
| `TestScrubCodexEventDropsUnparseableRateLimits` | 无法解析即 fail-closed | `:158` |
| `TestScrubCodexEventDropsTelemetryFrames` | 两类遥测帧整帧丢弃 | `:164` |
| `TestScrubCodexEventStripsResponseObjectFields` | `safety_identifier` / `service_tier` / `prompt_cache_retention` 被删 | `:177` |
| `TestScrubCodexEventLeavesDeltaFramesUntouched` | delta 帧逐字节不变 | `:211` |
| `TestScrubCodexEventIgnoresTypeNameInPayload` | 类型名出现在 payload 里不误伤 | `:229` |
| `TestScrubCodexSSELine` | `data:` 行的前缀/空格/换行保持 | `:246` |
| `TestWSAllowlistIsSeparateFromHTTPAllowlist` | 两个白名单不得合并 | `:312` |
