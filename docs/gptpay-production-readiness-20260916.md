# GPTPay 浏览器版生产准备检查

检查日期：2026-09-16。通过此前指定的 SSH 主机仅执行只读检查；未安装软件、写生产文件、读取支付记录或密钥内容、重启服务、改变付款开关。以下是检查时的快照，不代表将来的主机状态。

## 已核实的生产状态

| 项目 | 观察结果 |
| --- | --- |
| 系统 | Ubuntu 26.04 LTS，Linux 7.0.0-28-generic，x86_64 |
| 应用进程 | gptpay.service active/running，User/Group 均为 gptpay |
| 程序发布 | `/opt/gptpay/current` 指向 `/opt/gptpay/releases/20260915T140007Z` |
| 监听 | `127.0.0.1:8321`，未监听公网地址 |
| Caddy | active，User=caddy；读取的 Caddyfile 适配结果包含本站一条路由和一个反向代理，上游为 `127.0.0.1:8321` |
| 配置健康查询 | 本地和 HTTPS `/api/config` 均返回 enabled=true、default_network=direct、proxy_mode=optional；未出现新版本 browser_available 字段 |
| 私有目录 | `/var/lib/gptpay`、`/var/lib/gptpay/payments` 均为 0700，gptpay:gptpay |
| 环境文件 | `/etc/gptpay/gptpay.env` 为 0600，root:root；未读取内容 |
| 浏览器可执行文件 | PATH、Deb 包查询和五个常见路径均未发现 Chromium/Chrome；未做全盘搜索 |
| 服务资源限制 | MemoryMax=256 MiB，TasksMax=128 |
| 系统资源快照 | 总内存约 3910 MiB，可用约 2820 MiB；swap 约 4 GiB；根分区剩余约 23 GiB |
| systemd 限制 | NoNewPrivileges、PrivateTmp、PrivateDevices、ProtectSystem=strict、ProtectHome、MemoryDenyWriteExecute 均开启 |
| 命名空间 | unprivileged_userns_clone=1，user.max_user_namespaces=11213；AppArmor 非特权 userns 限制=1 |

生产仍是原部署，已有旧版功能处于 enabled 状态；本次没有发布本地新增的浏览器执行层。Caddy 的适配 JSON 没有显式 retries 字段，本次没有改写配置或据此声称完成无重试验收。

## 启用浏览器前必须完成

1. 选定并安装受维护的 Linux 浏览器，确认实际可执行路径和 AppArmor 配置。Ubuntu 的 userns 限制要求相关应用由适当的配置允许使用命名空间；不能以全局关闭限制或 `--no-sandbox` 替代核验。[Ubuntu 官方说明](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)
2. 解决服务单元与执行引擎的兼容性。systemd 文档明确说明 MemoryDenyWriteExecute 与运行时生成代码的 JIT 引擎不兼容。是否需要针对浏览器服务调整，应在相同单元限制下测试；本次没有更改此项。[systemd 官方文档源文件](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
3. 重新做容量测试。256 MiB/128 tasks 是现有 Go 服务的限制，不能作为两个独立 Chromium 进程已通过容量验收的依据。建议先单会话压测，测量冷启动、报价、iframe、验证页面与关闭后的峰值/回收，再确定内存、任务数和并发限额；不能只根据宿主机“可用内存”调整。
4. 核验浏览器进程与其他服务、支付记录目录之间的隔离，以及只经批准出口访问的系统级策略。现有应用层中继和浏览器参数不能代替 OS 出口隔离证明。
5. 在与最终服务相同的用户、挂载、AppArmor、systemd 与资源条件下执行下面的离线自检。普通 SSH shell 下通过不代表 systemd 中能启动。
6. 浏览器付款入口现已在本地接入，通过独立 `GPTPAY_BROWSER_SUBMIT_ENABLED` 开关默认关闭。真实 Chromium + 合成上游链路已验证；用户验证接管、支付响应观察、真实订单对账以及完整失败/重启/断网验收仍未完成。未达到上线门槛前保持生产新浏览器能力关闭。

## 新增离线自检命令

应用仍为 Go 二进制；浏览器模式另外依赖系统安装的 Chromium。新增：

浏览器启动还依赖可执行的 `/usr/bin/env`，缺失时明确拒绝启动，不回退到继承服务环境。Chromium 仅接收白名单环境；服务密钥、默认代理和 TLS 密钥日志配置不会由父进程环境传给它。有界面模式会保留显示会话设置，相关目录仍须由部署权限控制。此项是进程环境卫生措施，不是隔离同 UID 文件访问或 `/proc` 的完整方案。

```text
gptpay -check-browser -chromium <已核验的浏览器绝对路径>
```

未提供 `-chromium` 时读取 `GPTPAY_CHROMIUM_PATH`；时区读取 `GPTPAY_BROWSER_TIMEZONE`，默认 America/New_York。自检使用与订单浏览器相同的启动/安全参数，拒绝 root，并以禁止所有目标拨号的中继只加载 about:blank。它不启动 HTTP 服务、不创建支付 Ledger、不导入 Session、不填写卡片。

输出仅包含浏览器版本、JavaScript/WebAssembly 执行结果、语言、时区和 offline 标识。它不证明代理可用、支付资格、完整 OS 沙箱策略或付款成功。

本地两仓 workspace 构建 `/tmp/gptpay-env-isolation-20260916`（包含环境隔离启动器）的实际输出：

```json
{"product":"Chrome/153.0.8010.36","javascript":true,"webassembly":true,"locale":"en-US","timezone":"America/New_York","offline":true}
```

环境隔离后的完整 Chromium 合成测试通过 race 检查，hypitoken HTTP race 回归、五个前端测试模块和两仓相关包的 vet 通过。当前二进制离线自检通过；此前诊断命令的参数检查已验证 `-h` 正常，单独使用 `-chromium` 而没有 `-check-browser` 会拒绝启动。此二进制没有上传生产。

## 发布与回退约束

目前 hypitoken 依赖版本尚未发布匹配的 cc-core；本地验证使用同时包含两个仓库的临时 Go workspace。正式构建必须固定两仓实际源码及依赖，记录 dirty/untracked 改动，不能只记录 HEAD 后声称可复现。

待完整验收及审批后才准备新的不可变 release 目录，验证二进制和配置，再切换 current 并观察健康状态。保留现有 release 作为回退目标。无论发布、回退还是恢复备份，都不能删除或回滚已经产生的付款确认记录；否则可能破坏防重复付款保证。

本轮没有执行任何上述生产变更。
