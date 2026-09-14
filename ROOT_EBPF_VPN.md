# Wuwan Root/eBPF 与 VPN 模式说明

## 已实现的运行选择

Wuwan 的“自动”服务模式在启动前执行 Root/eBPF 能力探测。探测同时检查 `su` 是否返回 `uid=0`、`/sys/fs/bpf` 是否可用、`/sys/kernel/btf/vmlinux` 是否存在，以及设备是否提供 `bpftool` 或 `tc` 加载器。只有全部条件满足时，应用才选择代理服务分支；否则选择 Android `VpnService`，不要求 Root。

手动选择“VPN”时始终申请系统 VPN 权限。手动选择“仅代理”时仍要求 Root/eBPF 条件满足；不满足时启动入口会安全降级为 VPN，不会启动一个看似成功但未接管流量的空代理。

项目保留原有节点、订阅、路由、分应用代理、日志、测速、WireGuard 和 sing-box 能力。节点选择和日志面板继续使用原有主界面与 Logcat 面板。

## eBPF 设备前置条件

Android Root 权限本身不等于 eBPF 全局透明代理。设备内核必须启用 BPF 相关能力并提供可用的 BPF 文件系统、BTF 元数据和加载器。不同厂商的 SELinux 策略、内核版本、网络命名空间和厂商防火墙实现可能阻止全局挂载或 tc/XDP 接管。因此应用只把能力探测作为入口门禁，不绕过内核限制，也不伪造“已接管全部流量”的状态。

要在特定设备上完成真正的 eBPF 全局透明代理，还需要针对该设备提供经过编译和验证的 eBPF 对象、挂载点、代理端口、绕行规则和卸载脚本。该对象不应由 Java 层动态猜测生成。当前主分支已经提供安全的探测与模式选择边界，设备专用 eBPF loader 应通过 Root 管理器或系统镜像注入，并在真机上验证 DNS、IPv4、IPv6、UDP、应用 UID 和断网恢复。

## 构建

本地构建仍使用仓库原有流程：

```bash
./run init action gradle
./gradlew app:assemblePreviewRelease
```

GitHub Actions 的 `release.yml` 现在支持 `main` 分支 push 和手动触发。工作流会构建 libcore、构建 APK、签名并创建 GitHub Release。生产签名应把正式 keystore 放在 GitHub Actions Secrets 中，并替换工作流中的调试签名回退逻辑；仓库内的 debug keystore 只用于可复现测试包。

## 使用

1. 安装 APK 并导入或创建节点。
2. 在“设置 → 运行模式”选择“自动：Root/eBPF，否则使用 VPN”。
3. Root 设备先授权 `su`；若设备满足 eBPF 探测条件，应用选择 Root/代理服务分支。
4. 无 Root 设备或 eBPF 条件不完整时，系统会弹出 VPN 授权，授权后使用 VpnService。
5. 在主界面使用节点选择面板；故障诊断进入“导出调试信息/Logcat”。

## 验证建议

应在至少一台无 Root Android 设备和一台 Root 设备上验证。Root 设备还应分别覆盖“内核支持 eBPF”和“只有 Root 但缺少 BTF/加载器”两种情况。后者必须显示并记录 VPN 回退，而不是继续使用代理服务。

## 给 GPT/GTP 的生成口令

```text
基于 GitHub 仓库 https://github.com/lit008834-pixel/WuwanForAndroid 的 main 分支开发 Android 代理 APP，不要删除或削弱原有 sing-box 节点、订阅、路由、分应用代理、测速、日志、WireGuard 和 VPN 能力。需求如下：

1. 启动时自动检测 Root：执行 su -c id，只有返回 uid=0 才认为有 Root。
2. Root 分支必须进一步检查 /sys/fs/bpf、/sys/kernel/btf/vmlinux，以及 bpftool 或 tc 加载器；Root 单独存在不能视为 eBPF 可用。
3. 只有 Root、BPF 文件系统、BTF 和加载器全部满足时，才选择 Root/eBPF 透明代理分支；必须记录检测结果和当前模式。
4. 无 Root，或任何 eBPF 前置条件不满足，必须自动降级到 Android VpnService，不得显示虚假的“全局透明代理已启用”。VPN 分支要申请系统 VPN 权限并接管系统路由。
5. 自动模式默认优先 Root/eBPF，失败安全回退 VPN；用户可以手动选择 VPN。手动 Root/代理模式如果探测失败也必须回退 VPN。
6. UI 保持简洁：主开关、当前运行模式状态（Root/eBPF 透明代理或 VpnService 模式）、节点选择面板、Logcat 日志面板。复用仓库已有 UI，不要另起一套破坏现有功能。
7. 真正的 eBPF 全局透明代理必须使用可验证的设备专用 eBPF object、挂载点、代理端口、绕行规则和卸载逻辑；不能用 Java 代码伪造成功。如果仓库没有可运行的设备专用 eBPF loader，就实现清晰的能力探测和 loader 接口，并明确文档中需要注入/验证该 loader，同时保证失败自动 VPN。
8. 修改必须兼容 Kotlin/Android 现有架构，避免启动阶段递归初始化 DataStore；为 Root 探测、模式选择和回退添加单元测试或可测试的纯函数。
9. 添加或更新 .github/workflows/release.yml：支持 main push 和 workflow_dispatch，构建 libcore、构建 APK、上传 artifact，并使用 GitHub Release 发布。正式签名使用 GitHub Secrets，不要把生产私钥提交到仓库。
10. 更新 README 或新增 ROOT_EBPF_VPN.md，写清构建、安装、Root/eBPF 前置条件、VPN 回退、节点选择、日志查看、真机验证矩阵和已知限制。
11. 完成后运行 ./gradlew test 和 ./gradlew app:assemblePreviewRelease；修复编译错误；检查 git diff；提交到 main 分支并推送到 origin/main。
12. 最终输出：修改文件列表、构建命令、GitHub Actions 文件位置、提交哈希、主分支地址、APK artifact/release 地址，以及明确说明哪些部分已在代码中验证、哪些 eBPF 行为需要特定真机内核和 loader 才能验证。
```
