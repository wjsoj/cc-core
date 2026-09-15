# 账单地址提供接口

2026-09-15 使用 Chrome DevTools MCP 检查 MockAddress 线上资源和公开源码。

## 调研结果

- 首页生成逻辑在浏览器执行，按需加载静态 JSON，并非查询用户/银行账单资料的后台 API。
- 当前免税州模式从独立的、按州分组的地址池随机抽取**整条地址记录**，而不是现场拼接街道和邮编；
  该模式没有合成地址的兜底逻辑。姓名、性别、电话、邮箱另行随机生成。
- 地址字段包含 street、city、county、state、stateCode、zip、fullAddress、country。
- 实测地址池数量：AK 888、DE 888、MT 888、NH 123、OR 788，共 3,575 条；
  数据文件标注生成时间为 2026-04-26。该数量是当前页面使用的专用数据池，不是所有地址模式的总量。
- 页面宣传政府/地图数据来源，但当前专用数据文件没有逐条来源或持卡人关系证明；
  不能仅凭网页宣传确认数据来源完整性、投递有效性或持卡人账单地址归属。
- 抽中一个存在的地址不等于获得某位用户的真实账单地址。

参考：[MockAddress 首页](https://mockaddress.com/)、
[服务说明](https://mockaddress.com/en/about/)、
[使用条款](https://mockaddress.com/en/terms/)。条款将生成数据定位于测试/示例，
不许可作为真实地址提交用于支付验证。本项目不复制其代码或地址库，不调用其生成器提交付款。
账单核验参考 [Stripe AVS 说明](https://docs.stripe.com/disputes/prevention/verification)。

## cc-core 扩展点

`BillingAddressProvider.Resolve(ctx, query)` / `ResolveBillingAddress(ctx, provider, query)`。

- 查询：country、state、input（均可选），不接受 Session、卡号、CVV。
- 返回：地址字段、source、sample、requires_confirmation。
- 数据源未配置时返回 `ErrBillingAddressProviderNotConfigured`，不会随机填充兜底。
- 返回候选地址后要求用户核对；sample 保持标记，不改写为真实用户地址。
- 接口与 Create/Quote/Pay 独立，不自动修改现有账单，不开放网站 HTTP 地址生成端点。
- 后续可接入用户保存的真实地址或授权的地址补全服务。真实支付仍使用用户确认的账单信息。

## 样例地址池实现

已实现 `NewSampleAddressPool(source, rows)` 和 `LoadSampleAddressPool(source, reader)`。
数据由调用方提供，不内置第三方地址库，也不请求 MockAddress 网站。

- `BillingAddressQuery{}`：从整个地址库按记录等概率抽取，不先随机选择州。
- `BillingAddressQuery{Country: "US"}`：在该国家的所有记录中随机抽取。
- `BillingAddressQuery{Country: "US", State: "CA"}`：按国家和州过滤后抽取。
- 抽取完整记录，保持街道/城市/州/邮编组合，不自动拼接地址。
- 返回保留 `sample=true`、`requires_confirmation=true` 和数据源标记。
- 支持最多 50,000 条、16 MiB JSON 数组；拒绝空库、未知字段、残缺数据和无匹配地区。
- 复制输入数据、并发只读、支持 context 取消；单元测试仅使用明确标注的虚构测试记录。

本次实现的是独立的样例数据接口，没有实现“随机地址 → 真实付款”的连接，也未在生产网站开放地址生成端点。
