# Wuwan 双模式部署与使用

## 源码与核心版本

基于 `main` 开发，不创建功能分支。保留 Wuwan/WuwanForAndroid 品牌、绿色 Android
图标、支持项目/关于内容、applicationId、数据库和配置格式。应用版本 1.7.0，
官方 sing-box 锁定 `v1.15.0-alpha.3`，tag 对应提交
`93fff5954390367dd456cad3cbd79be54f8b941f`。这是预发布版。
`nb4a.properties` 是版本唯一来源；`libcore/go.mod` 的本地 replace 使用同级官方源码。

## 运行顺序

1. 打开应用，后台执行 `su -c <APK内置加载器> probe`，Root 管理器可能弹授权。
   检测有 15 秒期限，拒绝、超时或找不到 su 均可继续使用 VPN。
2. Probe 创建短暂 TUN，真实调用 `BPF_PROG_LOAD`，并尝试创建 TCX 出口 link，
   随即释放。不会根据内核版本字符串或 `/proc/config.gz` 宣称支持。
3. 在运行模式选择“自动”（新安装默认值）；已有用户的手动 VPN 值不会被覆盖。
   导入订阅/节点、选择节点，点击原连接开关。系统 VPN 许可预先申请，用作降级准备。
4. Root 加载器创建私有 TUN，通过带 UID 验证的随机 Unix 域套接字传递 FD。
   sing-box 初始化成功后才发送激活指令，在本机非回环接口上挂载 eBPF。
5. UI 只在内核启动与挂载成功后显示“eBPF透明代理”；否则显示“VPNService模式”。
6. 加载器监听接口增删，挂载新接口；失败或控制通道失联后释放全部 BPF link。
   应用清理旧核心后仅重试一次 VPN。停止代理会释放 TUN、控制连接和加载器。

## 支持范围与降级条件

Root 后端需要 Android 8+、可执行 APK 内置原生文件、Root 授权、TUN、BPF 系统调用、
`SCHED_CLS` 程序及使用到的 helper、TCX egress BPF link（一般 Linux 6.6+），
还需要 SELinux 允许加载、挂载和 FD 传递。不能仅凭 GKI、6.12 或 root 状态判断可用。
不修改 SELinux、不刷内核、不写分区、不依赖 iptables/tc 命令、不 pin BPF 对象。
不替换或删除 Android/netd 或其他程序的 BPF/qdisc。

原来的节点、订阅、测速、DNS、链式代理、规则和本地代理模式保留。分应用、进程
匹配及绕过 LAN 设置要求 Android VPN 行为时，使用 VPN；不会为进入 Root 模式而
删除这些设置。规则内的直连仍然直连。“全局接管”不是把所有规则强制改为代理。

代理进程 UID 和 Android protectedFromVpn 标记套接字绕行以避免代理及系统 DNS 回环，回环接口、ARP、IPv4 组播/广播、IPv6 组播与链路
本地流量保留系统处理。IPv6 扩展头、分片、QUIC、厂商硬件 offload、无 socket
归属报文和 sing-box system/mixed/gVisor 栈的兼容性必须在设备上验证。
eBPF 重定向并不增加 sing-box 对任意 IP 协议的支持。

没有 kill switch：新网卡出现及降级切换时可能短暂直连。若业务必须保证零直连，
本实现不满足该要求。已存在的其他 VPN、OEM 路由、硬件 offload 也可能改变实际
覆盖范围。不能把“程序挂载成功”等同于“真机全部流量已验证”。

## 本地构建

安装 JDK 17、Go 1.25.5+、Android SDK 35、Build Tools 35.0.1、NDK 25.0.8775105。
NDK 的 Clang 为四种原 ABI 编译 PIE 可执行加载器，以 `libwuwan_ebpf.so` 包装进入 APK；
它不是 JNI 共享库，不使用 `System.loadLibrary`。加载器最低 API 26，应用最低 API 21
不变，旧系统降级 VPN。Linux/macOS 构建脚本见 `buildScript/ebpf/build.sh`。

```bash
git checkout main
git pull --ff-only origin main
./run lib core
./run init action gradle
./gradlew app:testOssDebugUnitTest app:assembleOssRelease
```

按原项目规范配置 `local.properties`/环境变量与 `release.keystore`。Gradle 中
Root helper 会在 preBuild 自动构建，无需手工拷贝 .so。不生成临时发布密钥。

## GitHub Actions 生产签名

在 Settings → Secrets and variables → Actions 配置：

| Secret | 含义 |
| --- | --- |
| RELEASE_KEYSTORE_BASE64 | 现有正式 keystore 的 Base64 内容 |
| KEYSTORE_PASS | 原 keystore 密码 |
| ALIAS_NAME | 原签名 alias |
| ALIAS_PASS | 原 alias 密码 |

必须使用能升级现有安装的原签名身份；换密钥通常无法覆盖安装。
不要把密钥或密码提交到仓库。流水线复用项目既有 release signingConfig，不改变包名。

`Production Release` 在 main 推送时构建四个 ABI 的正式签名 APK，并上传
`Wuwan-production-<commit>` Artifact；`v*` 标签构建成功后发布 GitHub Release。
缺少任一密钥 Secret 会直接失败，不采用 debug.keystore、随机密钥或无签名产物。
旧的 Release 工作流有历史调试签名逻辑，仍保留供原用途，不作为生产交付流程。

构建产物包括 APK、SHA256SUMS、源提交号及版本配置。CI 的 `Wuwan-debug-APKs`
是调试包，与正式签名包区分。`Core and eBPF checks` 检查核心编译和测试，并在隔离
网络命名空间内试载真实 BPF 程序；这不替代 Android 真机验证。

## 验证清单

| 场景 | 预期 |
| --- | --- |
| 无 su / 拒绝 Root / 超时 | 启动不阻塞 UI，VPN 可连接 |
| Root，BPF syscall 不可用或 EPERM | 日志说明原因，VPN 可连接 |
| BPF 可用但 TCX / helper / SELinux 不满足 | 清理 Root 资源，自动 VPN |
| 全部能力满足 | 核心先启动，再挂载，显示 eBPF |
| eBPF 激活失败 / 加载器被终止 | 先清理后重启 VPN，不循环尝试 Root |
| Wi-Fi ↔ 蜂窝，开关飞行模式 | 新接口加入；挂载失败则 VPN |
| 开关反复切换、切节点、进程被终止 | 不留下 pinned BPF、规则、持久 TUN |
| TCP、UDP/QUIC、IPv4、IPv6、DNS | 对照抓包与出口 IP 验证，确认无回环 |
| 分应用/进程规则、绕过 LAN | VPN 保留原设置行为 |
| 订阅更新、测速、备份、链式代理、原协议 | 与 main 基线对照回归 |

检查日志中的 `RootProbe`、`ROOT_GRANTED`、`BPF_PROG_LOAD`、`TCX_EGRESS`、`Mode=`。
这份提交的设备兼容性不应在未执行上述真机测试前被描述为已验证。

## 此修改包的验证状态

- C 加载器：Linux 主机 GCC `-Wall -Wextra -Werror` 编译通过。
- BPF 路由程序：13 项解释执行测试通过（IPv4/IPv6、UID、受保护 socket、组播/控制报文、无效头）。
- XML、YAML、shell 语法及补丁检查：在交付前检查。
- 本执行环境无 Android SDK/NDK/Go 工具链，也无 CAP_BPF/CAP_NET_ADMIN；没有完成 APK 编译或 Android 真机测试。
- GitHub 写入返回 403 `Resource not accessible by integration`，普通 git push 无凭据；提交仅在本地，未发布到 main，未触发新流水线。
- 因缺少实际编译，1.15 预发布核心的完整 ABI/API 兼容性尚不能保证；不得将此包标为编译通过或生产验收通过。
