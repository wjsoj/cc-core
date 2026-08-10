# downstream —— 返回给客户端的响应清洗

`mimicry` / `sidecar` / `crack` 都在处理**上行**：让我们发给 Anthropic 的东西像真实客户端。`downstream` 是反方向的那一半：**我们回给客户端的东西，应该像一个普通的 Anthropic 兼容网关，而不是一根从凭据池直通上游的透明管道。**

## 问题

转发上游响应头会把我们凭据池的运行状态直接交给下游用户。一条来自 `api.anthropic.com` 的 200 就带着（`crack/cc2224/rows/13-v1_messages.json`）：

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

`crack/thirdparty/SPEC.md §4` 记录了对照：真实第三方网关**一个 `anthropic-*` 响应头都不返回**，只有 `content-type` / `cache-control` / `vary` / `content-encoding` 和它自己的 correlator，而真实 Claude Code 对着它工作完全正常。所以白名单是**已知可行的行为**。

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

## 已知残留

- **`usage.cache_creation.ephemeral_1h_input_tokens`。** 客户端在自定义 base URL 下只能发裸 `ephemeral`，而 `mimicry` 会把断点升级成 1h（见 [mimicry](Mimicry) 的 cache_control 修补），于是响应里报的是 1h 档的 cache-creation 数字。细心的客户端能据此推断请求被中间层改过。折算回 5m 需要知道客户端原本要什么，是响应清洗层拿不到的状态，且会篡改 fork 自己也在解析的计费数字 —— 记录在案，暂不处理。
- **`message_start.message.id`** 仍是 Anthropic 的 `msg_01…` 格式，与网关自己的 id 格式不同。它不暴露我们的账号，且改写它可能破坏做 id 关联的客户端，故保留。

## 测试

`downstream/headers_test.go` 直接拿 `crack/cc2224/rows/13` 的**真实完整响应头集合**做输入 —— 过滤的是真货，不是挑出来的子集。`TestScrubbedHeadersAreGoneIndividually` 逐条断言，这样将来某次改动放行了其中一个，失败信息里会直接带上那个头的名字。

`TestScrubIsNearlyNoOpOnGatewayResponse` 反向验证白名单没有过紧：对着我们要模仿的网关响应，清洗应该几乎什么都不做。
