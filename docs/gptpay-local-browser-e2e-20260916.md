# 本地浏览器付款链路验证

## 当前结论

本地已打通：网页输入 → 创建订单 → 填账单 → 核对报价 → 填卡 → 用户确认 → Go 调用真实 Chromium 点击 → 查询并核验订单。上游页面和支付响应为明确标记的合成数据，外部拨号全部拒绝；不是官方实付成功，也不证明 403 或验证码问题已解决。生产未发布。

参考目录是上一级 `KC-PAY-GPT`，没有发现 `KC-PAY0-GPT`。本轮阅读了其 `completeStripeCardPayment`、`finalizeCheckoutPayment`、`handlePostSubmitPhase` 与 `waitForPaymentResult`，参考阶段划分，没有运行第三方项目或使用其验证码求解、换卡重试、随机账单实付及跳转即成功逻辑。

## 当前接口与部署门控

- `/api/browser/submit` 仅在 `GPTPAY_BROWSER_SUBMIT_ENABLED=true` 且浏览器服务启用时工作；其他情况下拒绝提交。示例配置保持 false。
- 同一 Session、flow、代理、当前服务端报价、完整已填卡片及 `confirm:true` 是前提；提交体只带金额/币种，不再接受卡数据。
- 仍由 core 在最终报价复核后独占写入防重付记录，再执行一次原生点击。
- 失败或无法确定提交结果不会自动重试；有持久化记录时不能通过遗失内存标记重新提交。
- 点击返回 processing，不返回 paid；结果需核验该订单的账号、套餐、金额和币种。
- 页面新增独立确认按钮；取消确认不发提交，确认前显示金额与账号。提交后锁定，关闭浏览器保留结账编号用于恢复查询。

## 验证证据

普通 hypitoken Go race 回归通过；28 项前端模块测试通过。core 的完整 Chromium race 回归通过，浏览器包耗时 69.082 秒。

`TestRealBrowserHTTPPaymentIntegration` 使用真实浏览器 worker，不是 fakeBrowser，经过真实 HTTP handler 完成创建、填表、报价、确认、状态核验、重复提交拒绝与关闭。仅上游被替换为合成页面/响应；HTTP 调用由测试驱动。

该测试的三条分支均通过 race 检查（合计 10.60 秒）：完整 paid 证据得到成功；点击后仍为 unpaid 的订单保持 pending；上游声称 paid 但金额不同被拒绝，不显示成功。合成页面三种情况都显示相同“已记录”文案，证明未用该页面文案替代对账。

另用 Chrome DevTools MCP 打开 loopback 测试页，填写合成 Session、4242 测试卡、虚构账单字段，实际操作网页：

1. 创建/报价/预览/填卡返回 200，尚未点击订阅，trusted_clicks=0。
2. 取消确认后仍为 0，按钮仍可用。
3. 确认后连续触发两次按钮，只出现一条 `/api/browser/submit`，trusted_clicks=1。
4. 页面先显示处理中，再由 `/api/browser/status` 的核验结果显示合成成功；不能由点击本身推断成功。
5. 输入未被清空，提交按钮隐藏，重新报价锁定。关闭浏览器保留结账编号。

前端网络记录没有 `/api/pay`，未回退到旧协议执行。控制台有一条资源 404（未进一步归因），不能声称控制台完全无错误。专用测试标签页已关闭，测试服务正常停止（PASS，121.20 秒），没有关闭用户其他页面。

## 重跑（在 hypitoken 目录）

需同时引用本地 cc-core 与 hypitoken 的 Go workspace，且安装可使用沙箱的非 root Chromium。当前临时 workspace 路径：`/tmp/gptpay-captured-payment.0h1dBu/go.work`。

```sh
GOWORK=/tmp/gptpay-captured-payment.0h1dBu/go.work \
GOTOOLCHAIN=go1.25.6 GPTPAY_TEST_CHROMIUM=/usr/bin/chromium \
go test -tags gptpay_integration -race ./internal/gptpay \
  -run '^TestRealBrowserHTTPPaymentIntegration$' -count=1 -v
```

手动网页联调使用相同环境，加 `GPTPAY_REAL_BROWSER_UI=true`，测试名改为 `TestManualRealBrowserUIIntegration`。输出临时 loopback 地址，最多运行十分钟。只接受合成数据；页面预览明确显示 SYNTHETIC CHECKOUT。`/__fixture/stop` 仅存在于测试服务，用于结束该次验证。

禁止将带 `gptpay_integration` 标签的构建部署到生产。普通构建无该支架、无测试付款路由。

## 尚未完成

官方页面的动态字段兼容性、首次登录/验证恢复、远程用户验证码与银行验证接管、观察器对实际新 Payment Page 响应的兼容性，以及生产隔离/容量/重启恢复验收仍待完成。本机可见订单窗口见下文；真实人工验证未验收。现在不能把本地合成成功当成可公开上线的完整卡付平台。

## 追加：本机可见订单窗口

独立二进制增加 `-local-browser-window`。服务模式必须监听字面量回环地址（例如 `127.0.0.1:8321`），开启浏览器服务并具备 DISPLAY 或 WAYLAND_DISPLAY；不自动开启提交开关，不放宽 HTTPS 来源要求。不提供远程桌面或公开 CDP。窗口显示在 Go 主机，不能把该开关当成服务器上的远程用户接管功能。

普通构建：`/tmp/gptpay-local-window-20260916`。可先执行不联网的运行检查：

```sh
/tmp/gptpay-local-window-20260916 -check-browser -local-browser-window -chromium /usr/bin/chromium
```

本次检查通过，Chromium 153.0.8010.36，en-US、America/New_York，JavaScript 与 WebAssembly 正常。实际服务在原有 HTTPS 代理及 GPTPAY 环境配置下增加 `-addr 127.0.0.1:8321 -local-browser-window` 即可；不要把公开生产部署切换到此本机调试模式。

整链路测试加入 `GPTPAY_TEST_HEADFUL=true` 后复跑六个合成分支，实际显示窗口，全部通过 race（22.37 秒测试主体，包总计 23.419 秒）。普通 Go race（2.195 秒）、vet、44 项前端测试、JS 语法与 diff 检查通过。所有此次测试进程及其订单浏览器已正常结束，没有启动长期真实付款服务或改动生产。

验证状态下页面提示切换到已打开的订单窗口，由本人验证后返回查询，保持助手页和订单窗口打开。沿用原浏览器、原出口和生命周期，不自动解验证码，也不自动重付。应用防重付不限制用户在原生订单页手动点击；请勿重复点击 Subscribe。测试未进行真实验证码或银行验证，也未真实扣款。

## 追加：本单支付响应观察

新增被动 Network 观察器，仅在可靠写入防重付记录后工作；主页面及已验证的卡片 iframe 各自最多追踪 32 条候选请求，读取队列上限 32、单响应 256 KiB、单目标网络缓冲 2 MiB。大响应、队列溢出、读取失败、未知结构均不据此声明成功。不修改或重放请求，不处理验证码。

旧流程先核验 ChatGPT confirm 请求中的结账编号，再由其响应提取关联 PaymentIntent ID；不会长期保留完整 client_secret。之后仅接受该 ID、相同金额和币种的业务状态。新 Payment Page 分支要求 URL 与响应 ID 均对应本单，且存在带金额/币种的展开 Intent 对象；当前抓包未提供该响应正文，这一结构只做保守兼容，不能声称已验证真实新流程。

普通单测覆盖未提交、无关联、串 Intent、金额/币种缺失或矛盾、旧响应乱序、未知/过大正文与敏感字段不回传。HTTP 测试覆盖观察器不能覆盖成功对账、对账错误、过期状态或提交前状态，也不能以观察器的 paid 标志宣告成功。

真实 Chromium 跨仓整链路新增 requires_action 与 payment_intent_authentication_failure 合成响应：经实际页面 fetch、CDP Network 响应读取和 HTTP 状态接口得到准确分类。五条分支（paid/pending/金额矛盾/需验证/验证失败）全部通过 race 测试，共 18.31 秒。前端 29 项测试通过，并明确提示当前只读预览尚不能接管验证。此轮没有用真实 Session/卡片，没有部署生产。

增加观察器后的 core 完整 Chromium race 回归通过（69.074 秒），hypitoken 普通 HTTP race 回归和两仓相关包的 vet 通过。观察器只识别已关联的响应；若关联响应缺失、乱序导致尚未建立关联、缓冲被淘汰或结构变化，可能无法提供提示，仍需保留 unknown/pending 和人工核对路径。

## 追加：延迟显示账单与重新报价

参照 KC 中填卡后等待账单区出现的结构，新增前端有界准备流程。仅当初次账单缺失时，填卡后再填一次账单并刷新报价，撤销旧报价、展示新的含税金额；再按新报价填卡，完成后仍要求独立用户确认。失败不自动重试或提交；账号、套餐、币种变化及过期报价拒绝接受。

自动化整链路新增 `late_billing`：合成页面初始隐藏账单，卡号输入后显示；账单填写后合成报价从 2000 更新到 2150，旧金额被接口拒绝。六条浏览器分支全部通过 race 测试（21.70 秒），42 项前端测试通过，hypitoken 普通 HTTP race 回归与 vet 通过。

Chrome DevTools MCP 在真实网页上验证了同一链路：依次出现 fill-card、fill-billing、quote、fill-card 请求，之后确认弹窗显示 USD 21.50；取消弹窗仍为 0 次，确认后只有一次可信点击，最终对账显示合成成功。输入保留；忙碌及已提交时辅助填地址按钮被禁用。关闭浏览器后保留结账编号。测试服务 PASS（108.67 秒）且专用页面已关闭。

手动重跑时在前述环境中添加 `GPTPAY_UI_SCENARIO=late_billing`。该参数只在测试文件中读取，生产没有此模拟模式。此验证仅覆盖这类先隐藏再显示的表单，不证明官方当前页面或所有 SDK 重绘变体均已可用。

## 追加：待验证状态刷新与恢复原浏览器

修复 pagehide 对已提交订单仍调用 close 的问题。未提交的准备会话仍关闭；已尝试提交（包括响应未知）的原浏览器保留到既有 TTL，不延长其生命周期。离开页面仍清理前端凭据和截图。明确点击关闭/清空仍属于主动关闭，不代表撤销付款。

当前标签页 sessionStorage 只保存 `checkout_session_id` 与 `processor_entity` 两字段，提交前写入，刷新后只读恢复编号并锁定付款。Session、卡、账单、代理凭据和 flow 不写入存储。存储受限时不崩溃，仍需手动保存编号。浏览器关闭标签页后该临时存储可能消失。

`/api/recover` 在持久化所有权核验之后优先使用匹配的活动浏览器。原代理不一致、忙碌、核验矛盾不回退第二个客户端；返回原 flow 后恢复预览和状态，不解锁付款。普通测试覆盖错所有者、换代理、忙碌、未提交、金额不符、成功优先于观察器及不调用另一后端。六条 Chromium 整链路加入丢失 flow 后按编号恢复，race 通过（21.85 秒主体）；普通 Go race 通过（2.260 秒），48 项前端测试通过，vet 与语法检查通过。

Chrome DevTools MCP 的独立页面 `http://127.0.0.1:35219/` 使用 `GPTPAY_UI_SCENARIO=requires_action` 完成实测：合成提交一次、返回需验证；主动刷新后 Session/卡输入为空、编号存在、报价锁定、代理可重新输入；粘贴原合成 Session、点击恢复查询，仍显示 requires_action，预览接口 200，提交按钮隐藏，trusted_clicks 始终为 1。没有新建订单或重付。专用标签页关闭，测试服务 PASS（221.00 秒）。

在正式提交前，测试页面曾出现一次未由本次测试指令触发的刷新；当时计数为 0，旧准备会话已不可用，重新填写后才执行上述提交验证。该次刷新原因未确认。控制台仍观察到一条资源 404，未归因，不能声称浏览器完全无错误。

普通本地构建更新为 `/tmp/gptpay-browser-recovery-20260916`，不含 integration 构建标签。没有用真实凭据、没有真实扣款、没有部署生产。活动浏览器过期或进程重启之后的代理绑定、远程交互验证和官方当前页兼容性仍需完成。

## 追加：持久化网络绑定

上述重启后代理绑定现已补齐本地实现。两种提交入口都使用带网络摘要的 Ledger 句柄，在付款确认记录内同时写入 selected-proxy 与 pinned-endpoint 的 SHA-256 摘要和版本。基础 Ledger 不被共享修改，排他防重付文件及 fsync 语义不变。代理凭据和端点明文不落盘。

恢复无活动浏览器的订单时，在代理解析前校验原配置，在创建出站客户端前校验固定后的端点。公网校验仍由 pinProxy 执行；任何不一致停止，不尝试其他端点或直连。既有活动浏览器恢复仍优先走原进程原出口。

新增 core 测试覆盖重开 Ledger、直连/代理区分、凭据不写记录、不同所有者拒绝、绑定不修改共享句柄、已有记录不可覆盖、未知版本/损坏/旧记录拒绝默认直连。HTTP 测试覆盖原直连和原代理可查询，换代理、增删代理、固定端点变化、无绑定旧记录在调用后端前拒绝；浏览器提交后关闭进程也能按绑定恢复，换代理被拒绝。端点变化使用合成固定 IP 输入测试，未做真实代理商出口测试。

本轮 core race 通过（checkout 2.042 秒，browser 缓存结果），hypitoken race 通过（2.289 秒），两仓 vet 通过；六条真实 Chromium + 合成上游整链路回归通过（21.29 秒主体，包总计 22.322 秒）。无新增真实支付或生产操作。

普通本地二进制：`/tmp/gptpay-network-binding-20260916`。旧记录不自动迁移，回滚到忽略绑定的旧服务会丢失该校验；上线前需制定相应停用恢复/升级策略。当前依旧不代表真实官方付款或完整生产验收已完成。
