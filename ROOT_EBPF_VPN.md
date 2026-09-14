# Wuwan Root/eBPF 与 VPN 模式说明

完整且当前有效的文档见 [部署与使用指南](docs/ROOT_EBPF.md)。

自动模式使用 APK 内置加载器真实调用 BPF 系统调用并验证 TCX 挂载，不再把
BPF 文件系统、BTF 文件、bpftool/tc 是否存在视作已完成透明代理的依据。
手动 VPN 始终使用系统 VPN；仅代理保持原本地代理功能。运行状态来自服务进程。

核心升级为官方 sing-box v1.15.0-alpha.3；生产构建使用
[Production Release](.github/workflows/production-release.yml)，要求现有正式签名。
