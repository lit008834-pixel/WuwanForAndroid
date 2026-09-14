//go:build !linux

package libcore

func tunNameFromFD(fd int, fallback string) string { return fallback }
