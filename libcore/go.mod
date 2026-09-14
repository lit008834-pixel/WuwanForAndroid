module libcore

go 1.25.5

require (
	// v0.1.6签名与 v1.13.16 锁定版一致。
	github.com/exclavenetwork/sing-juicity v0.1.6
	github.com/gofrs/uuid/v5 v5.5.1
	// 与 Throne 2e7182b9ea99947a409fee30f74df83752ab763c 的测速基线一致。
	github.com/Mahdi-zarei/speedtest-go v1.7.13-0.20260107171856-79c565dfd83a
	github.com/miekg/dns v1.1.72
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.7
	github.com/sagernet/sing v0.9.4-0.20260912053229-7776850263cd
	// 版本唯一来源是 ../nb4a.properties 的 SINGBOX_VERSION；此处仅为 Go
	// module graph 所需占位值，实际源码始终由下方 replace 指向 CI 检出的官方 tag。
	github.com/sagernet/sing-box v0.0.0
	github.com/sagernet/sing-tun v0.9.4-0.20260912075549-869f0a4d76af
	github.com/ulikunitz/xz v0.5.15
	golang.org/x/mobile v0.0.0-20231108233038-35478a0c49da
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0
)

// 官方内核：构建时由 buildScript/lib/core/get_source.sh 按 nb4a.properties 的
// SINGBOX_VERSION 克隆并校验 SagerNet/sing-box 到仓库同级目录（../../sing-box）。
replace github.com/sagernet/sing-box => ../../sing-box
