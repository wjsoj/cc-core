# 发布流程与下游集成

> [← Wiki 首页](Home) · [架构总览](Architecture)

## 概览：cc-core 没有 main，发布单位是 tag

`github.com/wjsoj/cc-core` 是**纯 Go 库**（`go 1.25.0`，无 `main` 包、无二进制、
无 Makefile、无 bun、仓库内无 CI），它被消费，不被运行。

它服务两个同级 reverse-proxy fork：

| fork | 路径 | 定位 |
|---|---|---|
| CPA-Claude | `/home/wjs/Documents/project/Go/CPA-Claude` | 较精简的一支 |
| hypitoken | `/home/wjs/Documents/project/Go/hypitoken` | 多了 SaaS / shop 产品层 |

两个 Go module **都叫 `github.com/wjsoj/CPA-Claude`**（`hypitoken/go.mod` 的
module 行也是 `CPA-Claude`），容易混淆 —— 靠**目录路径**区分，不要靠 module 名。

因此：

- cc-core 里的改动**只有在某个 fork bump 依赖并重新部署之后才到生产**；
- 发布单位就是一个 git tag `v0.8.NN`；
- 标准闭环是 **"在 cc-core 修 → 打 tag → 两个 fork 各自 bump"**。

凡是身份、凭据、计费、指纹相关的东西都住在 cc-core，正是为了让两个 fork 在
"必须和真实客户端逐字节一致"的部分上不会漂移。

---

## 构建与测试命令表

在 `/home/wjs/Documents/project/Go/cc-core` 下执行：

| 目的 | 命令 | 备注 |
|---|---|---|
| 全量编译 | `go build ./...` | 没有 main，只验证可编译 |
| 全量测试 | `go test ./...` | 14 个包带测试：`advisor auth backup clientguard clienttoken codexws mimicry pricing ratelimit requestlog sidecar stream thinkingsig usage` |
| 静态检查 | `go vet ./...` | |
| 单个测试 | `go test ./auth/ -run TestSessionsHeld -v` | |
| sidecar 套件 | `go test ./sidecar/ -timeout 60s` | 对着真实 `httptest.Server` 跑真实计时，约 23s，默认 timeout 也够但显式给更稳 |
| 指纹相关最小回归 | `go test ./mimicry/ ./sidecar/ ./auth/ -v` | 改任何 fingerprint 常量后必跑 |
| 看谁引用了某符号 | `git grep -n "SomeSymbol" -- '*.go'` | 跨 fork 时到各自仓库再 grep |

**没有仓库内 CI**（无 `.github/`）。所有验证靠本地这几条命令 —— 这也是
"每改一个行为常量都必须配一个测试"这条约定的现实原因：没有流水线兜底。

行为常量（`hardFailureThreshold`、`degradedProbeAfter`、pricing 权重、
`transientErrFragments` 条目、指纹常量）一改就**同时改变两个 fork 的生产行为**，
所以每一处都要配测试。

---

## 发布步骤

```bash
cd /home/wjs/Documents/project/Go/cc-core

# 1. 只提交自己动过的文件（关键：可能有别的 session 也在这棵工作树里改东西）
git status
git add <你自己改的路径>
git commit -m "fix(auth): 一句话说清这次改了什么"

# 2. 本地验证
go build ./... && go vet ./... && go test ./...

# 3. 选一个还没被占用的 tag 号
git fetch --tags
git tag | sort -V | tail -5

# 4. 打 tag 并推送（tag 打在一个 subject 已经描述清楚本次变更的 commit 上）
git tag v0.8.NN
git push origin main v0.8.NN

# 5. 更新 CHANGELOG.md（见下文"CHANGELOG 约定"），可以并进步骤 1 的 commit
```

关于 tag 形式：CLAUDE.md 写的是 lightweight tag（`git tag v0.8.NN`），
仓库里绝大多数 tag 也确实是 commit 对象；但最近几个（`v0.8.62`–`v0.8.66`）是
**annotated tag**，附了一句主题（如 `v0.8.62  requestlog SQLite index; Kiro bridge removed`）。
两种都能被 `go get` 正常解析，跟随现状即可；用 annotated 时给一句能读的主题。

**发布本身不属于抓包档案。** `crack/cc2220/SPEC.md` 结尾明确写着：
"No tag, downstream dependency bump, commit, or push is part of the capture
archive itself." —— 抓包和发版是两件事，分开做。

---

## 下游 fork bump 步骤

对 **每一个** fork 重复（先 CPA-Claude 再 hypitoken，或反之，无强制顺序；
但只要 cc-core 的改动是两边都需要的，就必须两边都做，否则 fork 之间开始漂移）：

```bash
cd /home/wjs/Documents/project/Go/CPA-Claude        # 或 .../hypitoken
go get github.com/wjsoj/cc-core@v0.8.NN
go mod tidy
go build ./...
go test ./...
git add go.mod go.sum
git commit -m "chore(deps): pin cc-core to v0.8.NN"
# 然后按该 fork 自己的方式重新部署
```

CPA-Claude 的历史里就有这个提交形态：`7c907cb chore(deps): pin cc-core to v0.8.64`。

如果这次 cc-core 的新能力需要 fork 侧接线（不是纯 bug 修复），CHANGELOG 会
明确写出接法。例如 v0.8.66 的说明："Consumed by adding a
`POST /auths/:id/codex-subscription` admin route in each fork, mirroring the
existing `codex-usage` handler."，并把完整接线片段放在 `docs/codex-subscription.md`。

### 当前 pin 状态（调研时点）

| fork | go.mod 中的 cc-core | 落后 |
|---|---|---|
| CPA-Claude | `v0.8.66` | 最新 |
| hypitoken | `v0.8.62` | 落后 4 个版本：agg_cube/dual-write/可选 JSONL（63–65）+ ChatGPT 订阅探针（66） |

> 两个 fork 的 pin **允许短暂不一致**，但只要涉及指纹/凭据/计费，就应该尽快拉齐 ——
> 让两支在"必须字节一致"的部分上保持一致，正是 cc-core 存在的理由。
> 顺带一提两边 Go 版本也不同：CPA-Claude `go 1.26.2`，hypitoken `go 1.25.0`，
> cc-core 自身 `go 1.25.0`（所以 cc-core 不能用 1.26 才有的语言特性）。

---

## 下游消费矩阵

统计口径：在各 fork 中 `grep -rhoE "github.com/wjsoj/cc-core/[a-z0-9_]+" --include="*.go"`
的 import 出现次数（≈ 引用该包的 Go 文件数）。

| cc-core 包 | CPA-Claude | hypitoken | 作用 |
|---|---:|---:|---|
| `auth` | 17 | 20 | 凭据调度器 + 健康状态机 + OAuth 登录 + Codex 探针 + uTLS 传输 |
| `usage` | 16 | 18 | per-auth / per-client-token 消耗账本 |
| `requestlog` | 10 | 12 | 每请求一行 JSONL + SQLite 索引/聚合 cube |
| `pricing` | 5 | 9 | `(provider, model)` → 每 token USD |
| `mimicry` | 3 | 6 | Claude/Codex 指纹（header + body） |
| `clienttoken` | 4 | 3 | 客户端 access token 运行时存储 |
| `thinkingsig` | 3 | 4 | 中途换凭据检测 + thinking 签名清洗/恢复 |
| `stream` | 2 | 2 | 框架无关 SSE 中继 |
| `sidecar` | 2 | 2 | 启动 burst / 心跳等辅助流量模拟 |
| `advisor` | 2 | 2 | `message_delta.usage.iterations[]` 解析 |
| `backup` | 1 | 2 | NaCl 加密的异地状态快照 |
| `ratelimit` | 1 | 1 | RPM + 并发计数器 |
| `codexws` | 1 | 1 | Codex over WebSocket 上游传输 |
| `clientguard` | 1 | 1 | 入口 UA 黑名单 |

读法：

- **两个 fork 消费了全部 14 个有测试的包，没有任何一个包只被单边使用。**
  所以"这个改动只影响一个 fork"这种判断基本不成立，评估影响面时按两边都受影响算。
- `auth` / `usage` / `requestlog` / `pricing` 是热区（也是 CHANGELOG 里改动最密集的），
  hypitoken 在这四个上的引用面更宽（多了 SaaS/shop 产品层）。
- `mimicry` 引用数看着小，但它是**指纹**：改动风险与引用数不成正比。

---

## 版本节奏与 CHANGELOG 约定

### 节奏

- 共 82 个 tag，从 `v0.1.0`（2026-05-09）到 `v0.8.66`（2026-08-07）。
- 按月分布：2026-05 共 26 个、2026-06 共 26 个、2026-07 共 22 个、2026-08 到 7 号已 8 个。
  **约等于每个工作日一个 tag**，一天连打三四个（`v0.8.63`–`v0.8.66` 全在 2026-08-07）
  完全正常。
- 版本号只是**单调递增的发布序号**，不是语义化版本：patch 位一路加，
  `v0.8.x` 从 v0.8.0 一直排到 v0.8.66，没有 minor 提升的迹象。
  破坏性与非破坏性变更共用同一条编号轴 —— fork 侧不能靠版本号判断兼容性，
  只能读 CHANGELOG。
- tag 打在一个 **subject 本身已经描述清楚变更**的 commit 上；tag 主题往往就是
  commit subject 的复述或压缩。commit subject 用 conventional commits 风格：
  `feat(auth):` / `fix(codex):` / `perf(requestlog):` / `refactor:` / `docs:` / `chore(deps):`。

### CHANGELOG.md 约定

- **不是每个 tag 都有条目。** CHANGELOG 只记录值得解释的发布，671 行里只有 17 个
  `## ` 标题（v0.8.66、v0.8.63–v0.8.65、v0.8.21、v0.8.19、v0.8.18、v0.8.12、
  v0.8.7、v0.8.6、v0.8.5、v0.8.0、v0.7.x、v0.6.0、v0.5.0、v0.4.0、v0.3.0、v0.2.0）。
  连续的小版本可以合并成一条（`## v0.8.63–v0.8.65 — request log: aggregate cube,
  dual write, optional JSONL`）。
- **倒序**，最新在最上面。
- 标题格式：`## v0.8.NN — 一句话概括`。
- 正文先写**一段"为什么"**（问题是什么、旧行为错在哪、代价多大），再用
  `### New — <包/文件>` / `### Changed — <包/文件>` / `### Dependencies` 分节列细节。
- 细节条目倾向于写**数字与陷阱**而不是 API 罗列：
  "10,382 rows for 984,049 records"、"1.1s → 0.01s"、"命中 0/37"、
  "`MATERIALIZED` 是显式的，否则 SQLite 可能内联 CTE 悄悄退回四次扫描"。
- 明确写出**下游怎么接**（"Consumed by adding a `POST /auths/:id/codex-subscription`
  admin route in each fork"），以及更详细文档的去处（`docs/codex-subscription.md`）。
- 涉及指纹的条目会写清"哪两个列表分叉了、不要从一个推导另一个"这类红线
  （见 v0.8.18 里的 ⚠ 说明）。

### Wiki

`docs/wiki/*.md` 通过 `bash docs/wiki/sync-wiki.sh ["提交信息"]` 同步到
`git@github.com:wjsoj/cc-core.wiki.git`。脚本只同步顶层 `.md`（脚本自身不进 wiki），
无变更时直接退出。**前置条件**：GitHub 的 wiki git 仓库要先在网页上
`https://github.com/wjsoj/cc-core/wiki → Create the first page` 建过一个页面，
否则 clone 会报 `Repository not found`。

---

## 多 session 协作注意事项

**两个 fork 都把这个仓库当作工作树的同级目录**，同一时间可能有别的
agent / session 正在这里改东西。因此：

1. **打 tag 前先 `git status`。** 确认工作树里没有别人未提交的改动被你顺手带上。
2. **只提交你自己的文件。** 用 `git add <具体路径>`，不要 `git add -A` / `git commit -a`。
3. **tag 号可能被抢。** 先 `git fetch --tags && git tag | sort -V | tail -5`，
   如果你想用的号已被占用，**直接用下一个空号**，不要覆盖别人的 tag。
4. **push 前先同步。** 历史里出现过 `259e139 Merge remote-tracking branch 'origin/main'`
   —— 并发提交是常态，遇到 non-fast-forward 就先 `git pull --rebase`（或按历史习惯 merge）。
5. **重复 tag 是允许的失误面。** `v0.8.60` 和 `v0.8.61` 的主题完全相同
   （`fix(billing): bill only observed usage; add 1h cache axis and USD quantization`），
   对应两个内容相同的 commit —— 说明"多打一个号"比"改已发布的 tag"代价小得多。
   **已经 push 的 tag 不要动**（下游可能已经 `go get` 过，Go module proxy 也会缓存）。
6. **不要替别人 bump fork。** 本次调研对两个 fork 是**只读**的。

---

## 常见问题

**Q: 改了 cc-core，为什么生产没变？**
A: cc-core 没有二进制。必须 tag → fork `go get` → 重新部署，三步齐全才到生产。

**Q: `go get @v0.8.NN` 拿到的还是旧版？**
A: Go module proxy 缓存。先确认 tag 真的推上去了（`git ls-remote --tags origin`），
必要时 `GOFLAGS=-mod=mod GONOSUMDB=… GOPROXY=direct go get github.com/wjsoj/cc-core@v0.8.NN`
或 `GOPROXY=direct` 单次绕过。

**Q: 只有一个 fork 需要这个功能，还要两边都 bump 吗？**
A: 功能可以只在一边接线，但**依赖版本应尽快拉齐** —— 消费矩阵显示 14 个包两边全用，
放着不 bump 等于让两支在指纹/凭据/计费上带着不同的 cc-core 跑。

**Q: 该打 minor 还是 patch？**
A: 现状只有 patch 位在动（v0.8.x 一路加到 66），破坏性变更也没有升 minor。
跟随现状：下一个空号。兼容性信息写进 CHANGELOG，而不是编码进版本号。

**Q: 没 CI，最低验证门槛是什么？**
A: `go build ./... && go vet ./... && go test ./...`。改指纹常量额外跑
`go test ./mimicry/ ./sidecar/ ./auth/ -v`；改健康阈值 / pricing 权重 /
`transientErrFragments` 必须**同时新增测试**（瞬时错误的回归用例要写**逐字**的
错误字符串，放进 `auth/retry_test.go`）。

**Q: CHANGELOG 一定要写吗？**
A: 不是每个 tag 都要。纯 bug 修复、纯版本 bump 可以只靠 commit subject；
新包、行为变化、需要 fork 接线、或带有"别再踩这个坑"信息的发布必须写。

**Q: 抓包升级指纹要走同一套发布流程吗？**
A: 是。抓包 → 写 `crack/cc<ver>/SPEC.md` → 改 `mimicry`/`sidecar` 常量 →
`go test ./...` → tag → 两个 fork bump。但抓包档案本身不含 tag/bump 动作，
详见《crack/ —— 抓包档案与指纹事实来源》。

---

## 相关页面

[Architecture](Architecture) · [Conventions](Conventions)
