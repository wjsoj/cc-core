# cc-core Wiki

`github.com/wjsoj/cc-core` —— 两个反向代理分叉 **CPA-Claude** 与 **hypitoken** 共用的核心库。

它**没有 `main`、不能独立运行**：所有与身份、凭据、计费、指纹相关的逻辑集中放在这里，让两个分叉在"必须与真实客户端字节一致"的部分不会各自漂移。改动只有在某个分叉 **bump `cc-core` 依赖并重新部署**之后才会到达生产环境，因此**发布单位是一个 git tag（`v0.8.x`）**，标准工作流是「在 cc-core 里修好 → 打 tag → 两个 fork 各自 bump」。

派生自 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（MIT）：Anthropic OAuth 刷新、Codex JWT 解析、uTLS Chrome 传输三块源自上游。

---

## 页面地图

### 起步
| 页面 | 内容 |
|---|---|
| [架构总览](Architecture) | 包依赖分层、一次请求的完整生命周期、每个包的职责边界 |
| [发布流程与下游集成](Release) | 构建/测试命令、打 tag、两个 fork 如何 bump、下游消费矩阵 |
| [约定与维护指南](Conventions) | 内容寻址身份派生、append-only 字段、行为常量的改动纪律 |

### 凭据与身份
| 页面 | 内容 |
|---|---|
| [auth —— 凭据调度与健康状态机](Auth-Pool) | `Pool.Acquire` 的两轮调度与 last-resort 放行、七态 `HealthState`、API-key 三计数器熔断器、瞬时错误分类（**最重、改动最频繁**） |
| [auth —— 登录、OAuth 与上游探针](Auth-Login-Codex) | Anthropic PKCE / session-cookie 登录、凭据文件格式、Codex JWT、两类 ChatGPT 探针、uTLS 与 HostProfile |

### 指纹仿真
| 页面 | 内容 |
|---|---|
| [mimicry —— 客户端指纹](Mimicry) | 版本常量、请求头/体构造、prepared-request 管线与 fail-closed 条件 |
| [sidecar —— 辅助流量仿真](Sidecar) | 真实 CC 启动时的 bootstrap burst 与心跳复刻 |
| [crack/ —— 抓包档案](Crack) | 指纹的事实来源；版本升级操作手册 |

### 账本与闸门
| 页面 | 内容 |
|---|---|
| [requestlog —— 请求账本与 SQLite 索引](Requestlog) | Record 结构、增量 ingest 自愈、`agg_cube` 与三大陷阱 |
| [计费、配额与网关闸门](Billing) | `usage` / `pricing` / `ratelimit` / `clienttoken` / `clientguard` / `advisor` |

### 传输层
| 页面 | 内容 |
|---|---|
| [downstream —— 返回客户端的响应清洗](Downstream) | 上游身份/配额头的白名单剥离、`Retry-After` 保全、错误体与 SSE error 帧脱敏 |
| [传输层与辅助工具](Transports) | `stream` SSE 中继、`codexws` WebSocket 上游、`thinkingsig` 切号清洗、`backup` 加密快照 |

---

## 按任务查

| 我要…… | 去看 |
|---|---|
| 加一个新模型（否则按 0 计费） | [计费](Billing) → pricing 内置目录 |
| 排查"凭据莫名其妙全黑了" | [auth 调度与健康](Auth-Pool) → 瞬时错误 vs 凭据错误 |
| 状态页要判断"整池还能不能服务" | [auth 调度与健康](Auth-Pool) → 七态健康枚举（用 `Pool.Health().Available()`，**不要**用 `healthy` 布尔） |
| 中转 API key 一直不轮转 / 一直在冷却里空转 | [auth 调度与健康](Auth-Pool) → 三计数器熔断器、API-key 的两级排序 |
| 升级 Claude Code 指纹版本 | [crack/](Crack) → 版本升级操作手册 → [mimicry](Mimicry) → 升级 checklist |
| 改健康阈值 / 定价权重 | [约定与维护指南](Conventions) → 行为常量纪律（**必须配测试**） |
| 排查管理面板统计慢 / 数字不对 | [requestlog](Requestlog) → `agg_cube` 与三大陷阱 |
| 发一个新版本给两个 fork | [发布流程](Release) |
| 加一个新的 OAuth 凭据文件字段 | [auth 登录](Auth-Login-Codex) → 凭据文件格式（append-only） |
| 中途切号报 `signature in thinking` | [传输层](Transports) → thinkingsig |

---

## 这份 Wiki 怎么维护

页面源文件在仓库里：**`docs/wiki/*.md`**，跟代码一起 review、一起进 git 历史。Wiki 站点只是它的一份镜像。

```bash
# 改完 docs/wiki/*.md 之后
bash docs/wiki/sync-wiki.sh "docs(wiki): 说明改了什么"
```

> 首次使用前，需要在网页上 https://github.com/wjsoj/cc-core/wiki 创建过至少一个页面，
> 否则 `cc-core.wiki.git` 这个仓库还不存在，脚本 clone 会失败。

页面里引用代码一律用 `路径:行号` 形式（例如 `auth/pool.go:412`）。行号会随代码漂移，**修改对应代码时请顺手更新引用**；把 Wiki 当作 spec 而不是笔记 —— `auth` 的健康规则、`requestlog` 的三大陷阱、`mimicry` 的常量联动，每一条背后都有一次生产事故。
