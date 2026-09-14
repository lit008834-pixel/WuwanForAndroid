package libcore

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
)

func tunNameFromFD(fd int, fallback string) string {
	// TUNGETIFF returns ifreq; its first IFNAMSIZ bytes always contain the
	// actual name. This matters when the root TUN is wuwan0 rather than tun0.
	var request [40]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		return fallback
	}
	name := request[:16]
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	if len(name) == 0 {
		return fallback
	}
	return string(name)
}
