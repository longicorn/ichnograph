package main

import (
	"os"
	"syscall"
)

func main() {
	_, _, errno := syscall.Syscall6(syscall.SYS_OPENAT, ^uintptr(99), 0, 0, 0, 0, 0)
	if errno != syscall.EFAULT {
		os.Exit(1)
	}
}
