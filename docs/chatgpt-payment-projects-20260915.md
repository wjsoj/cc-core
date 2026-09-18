# ChatGPT 支付项目调研（2026-09-15）

## 结论与验证边界

未找到已经由本次调研证明可直接上线、稳定完成美区 USD 银行卡订阅、同时满足现有代理约束的开源成品。不能把代码存在、作者宣称成功、HTTP 200、生成链接或创建任务当成付款成功证据。

建议保留 hypitoken / cc-core 的 Go 主体，按模块参考多个项目，而不是整体换成 KC。优先研究订单隔离、幂等、敏感信息处理、报价校验和支付后对账；需要用户认证的阶段保留用户交互，不导入验证码求解、风控规避、自动换卡或随机地址实付逻辑。这里只提出方案，未改变当前付款入口。

本次使用公开网页与 GitHub REST API，检索 `chatgpt checkout`、`chatgpt payment`、`chatgpt recharge`、`chatgpt 代充`、`gpt pay language:Go`，结合前轮候选复查。搜索结果含大量广告教程、API Token 零售和商家 ACP 接入项目，均不等同于 ChatGPT 会员付款实现。结果不是全 GitHub 穷举；派生仓库不计作独立成功证明。

验证仅为文档阅读、文件树及选定源码静态审查。未安装依赖、执行第三方代码、运行其测试、提交订单或发送用户 Session/银行卡。KC 本地基线为 `fb4da763f5cdcd6995b5b8ad3b7f758ae0684963`；其他链接指向检索时公开版本，后续会变化。

## 12 个候选项目

表中的能力若无单独源码证据，属于仓库自述，不是已验证的线上能力。

| 项目 | 范围 / 实现类型 | 本次判断 |
| --- | --- | --- |
| [KC-CatK/KC-PAY-GPT](https://github.com/KC-CatK/KC-PAY-GPT) | Node.js / Playwright / MySQL；兑换码、卡池、浏览器付款、上游 API | 完整平台参考，但本地代码存在成功误判、敏感卡信息落库、默认密钥问题，不应原样上线 |
| [nowtostudeyday/PAY-GPT-UPGRADE](https://github.com/nowtostudeyday/PAY-GPT-UPGRADE) | KC 的派生版，增加订阅管理、卡池策略和供应商 Webhook | 不是独立验证；默认取消续费等行为也不符合未经用户选择的支付助手需求 |
| [Han5111255am/GPA](https://github.com/Han5111255am/GPA) | Python、自托管 PH 结账工作台，含订单、认证、CDK、支付适配层和测试 | 会话隔离与测试设计值得参考；地区、双代理和密钥保护有明显适配成本 |
| [suyancc/openai-plus-vxt](https://github.com/suyancc/openai-plus-vxt) | WXT 浏览器扩展；提链与支付页辅助填表 | 本地浏览器辅助思路有参考价值；服务器模式存在向固定第三方 HTTP 地址发送 Token 的代码，不可原样使用 |
| [1537271403/pay153-checkout-link](https://github.com/1537271403/pay153-checkout-link) | Python / Flask，多渠道链接与二维码，另有 UPI Go 子模块 | 可比较普通请求契约和状态组织；不是已验证的完整美区银行卡付款服务，不采纳其跨区优惠或安全机制规避逻辑 |
| [DanOps-1/Gpt-Agreement-Payment](https://github.com/DanOps-1/Gpt-Agreement-Payment) | 协议研究工具集；PayPal / GoPay / QRIS 等链路 | 仓库明确具有研究性质、运行门槛及限制，包含验证码/反欺诈研究；不作为公众付款服务的直接部署候选 |
| [kacalayar/Autoplus](https://github.com/kacalayar/Autoplus) | 派生自 any-auto-register，覆盖注册、PayPal 和 GoPay | 范围远大于用户付款助手；不是纯 Go，也非美区银行卡的等价证明；README 另有非商业使用声明 |
| [Niceswz/chatgpt-upi-extractor](https://github.com/Niceswz/chatgpt-upi-extractor) | FastAPI / SQLite，UPI 提链和任务管理 | 不是银行卡付款；README 明确单进程运行限制，不宜把持久化记录理解为完整多 Worker 队列 |
| [wutianj/upi-link-extractor](https://github.com/wutianj/upi-link-extractor) | UPI 提链、CDK 和可选 Foarge 上游支付 | 有凭证脱敏测试、任务隔离及未知结果保留占用的设计；支付模式会向第三方发送 Token，需要独立授权，不能默认接入 |
| [biypan/chatgpt-upi-checkout](https://github.com/biypan/chatgpt-upi-checkout) | UPI 二维码工作流 | 特定支付方式，不解决美区银行卡需求；不使用其绕过地区/安全校验的做法 |
| [ciaooo55/chatgpt-checkout-link-gui](https://github.com/ciaooo55/chatgpt-checkout-link-gui) | Python 标准库 / Tkinter；创建并检查托管链接 | 适合作为最小提链对照；文档明确不处理风控绕过，没有自动化测试套件 |
| [renrenjiami/checkout-converter-standalone](https://github.com/renrenjiami/checkout-converter-standalone) | Python WebUI / CLI / API；从 GuJumpgate 拆分的链接生成器 | 适合比较输入输出与错误模型；到生成链接为止，并非完整付款 |

另查到 [moment-ge/ChatGPT-Plus-Checkout](https://github.com/moment-ge/ChatGPT-Plus-Checkout)，公开树只有一个 userscript，描述是生成支付长链接；本轮未深入其脚本，不作为完整平台候选。

## KC 本地静态审查

### 1. 付款成功可能误判（高优先级）

`stripe-payment.js:954` 的分支仅因 URL 包含 chatgpt.com 且不包含 `/checkout/` 就返回成功；`handlePostSubmitPhase` 在约 804 行也有相同类型判断。返回首页、登录页等并不能证明扣款。`index.js:588` 接着根据该结果输出 `PAYMENT_SUCCESS`。本次检查的调用链在这一成功分支没有强制核验订单已支付。

建议：页面跳转仅作为进度信号；最终结果必须关联本次结账 ID、账号、套餐、金额、币种，并取得权威支付终态。仅查到账号已经是 Plus 也不能证明本次订单支付成功。

### 2. 卡号与 CVC 直接入库（高优先级）

`mysql-store.js:3255` 把卡号、有效期、CVC 和姓名直接传入 SQL INSERT，没有应用层加密；`mysql-store.js:3319` 的账单记录还支持完整卡号。不能沿用这个模型处理公众用户的敏感卡数据。

### 3. 管理员 Token 密钥的默认值可预测（高优先级）

`admin-auth.js:20` 在缺少 `ADMIN_TOKEN_SECRET` 时使用工作目录和固定文本推导签名密钥；`.env.example:4` 也允许留空。这不是独立随机秘密。应要求显式配置高熵密钥并在缺失时拒绝启动。本次没有尝试伪造令牌或访问任何部署实例。

### 4. 代理与数据外发不符合现有约束

`server.js` 的第三方 worker 从平台池获取代理，并组装 Session、完整新卡和代理交给供应商。`server.js:3254` 附近的空代理说明是由上游使用平台代理池，不能等同于用户要求的“不提供代理就直连”。接口是否严格执行用户选定代理，还必须获得上游契约和行为证据。

### 5. 测试证明有限

本地 `test/` 下发现 `gpt-api-client.test.js`，覆盖的是 axios mock、请求字段和响应映射。它有价值，但不是浏览器付款、重启恢复、重复扣款防护或真实成功率的证据。

## 其他源码核查

- **GPA**：[security.py](https://github.com/Han5111255am/GPA/blob/master/backend/security.py) 的 `seal_secret` 使用重复密钥 XOR，没有随机 nonce 或认证标签；[service.py](https://github.com/Han5111255am/GPA/blob/master/backend/service.py) 用它保存可恢复的用户 API Key。不能把函数名当成可靠加密。其 [会话隔离测试](https://github.com/Han5111255am/GPA/blob/master/tests/test_checkout_core_features.py) 涵盖账号/Token 不匹配时缓存不复用，但使用 mock，未证明实付可用。README 的双出口配置也与当前严格单代理要求冲突。
- **OpenAI Plus VXT**：[checkout.ts](https://github.com/suyancc/openai-plus-vxt/blob/main/src/features/link-extractor/checkout.ts) 的服务器模式确实将 Token POST 到固定的第三方 HTTP 地址。只评价源码事实，不代表已经发生窃取；本次未调用该地址、未安装扩展。
- **UPI Link Extractor**：[test_credentials.py](https://github.com/wutianj/upi-link-extractor/blob/main/tests/test_credentials.py) 有 Token 解析与脱敏测试。README 描述不确定支付结果继续占用资源、等待对账，这比把超时直接当失败后重试合理，但本轮未完整审计其实现。

## 对现有项目的方案建议

没有单一“最佳仓库”；按本项目约束，推荐模块化组合，而非替换技术栈。

1. **保留 Go 业务核心**：国家、币种、计划、报价、订单、状态和用户权限仍由 cc-core / hypitoken 管理。
2. **先完善订单正确性**：幂等键、账号与订单绑定、每个订单独立上下文、超时为未知而非自动重付、重启后查询恢复。参考 GPA 的隔离测试与 KC / UPI 项目的任务组织，独立实现并验证。
3. **代理作为明确契约**：用户未提供时显式直连；提供时固定该链路。禁止静默环境代理、代理池、换出口或失败后直连回退。验收要覆盖所有网络客户端。
4. **付款执行层独立**：正常支付协议、浏览器辅助和经用户明确同意的供应商可以是不同适配器，不共用 Cookie/Token。不支持的验证阶段明确转入等待用户操作，不能伪装成功。
5. **敏感数据最小化**：不持久化 CVC；Session 不进 URL、日志、截图或第三方遥测；不得把用户输入自动提交到这些开源项目作者的服务。
6. **以证据决定是否上线**：正常/失败/需用户验证/超时未知、双击提交、服务重启、账户串单、代理断连、套餐金额变化都要有测试。端到端测试中真实确认与验证由用户完成。

本轮未修改任何业务代码、未部署；新增文件仅为这份调研报告。此前工作区已有的支付状态相关改动保持不动。
