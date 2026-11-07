//go:build linux && amd64

package main

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	path, err := unix.BytePtrFromString(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	fd, _, errno := unix.Syscall(unix.SYS_OPEN, uintptr(unsafe.Pointer(path)), uintptr(unix.O_RDONLY), 0)
	runtime.KeepAlive(path)
	if errno != 0 {
		os.Exit(1)
	}
	unix.Close(int(fd))
	path, err = unix.BytePtrFromString(os.Args[2])
	if err != nil {
		os.Exit(1)
	}
	fd, _, errno = unix.Syscall(unix.SYS_CREAT, uintptr(unsafe.Pointer(path)), 0600, 0)
	runtime.KeepAlive(path)
	if errno != 0 {
		os.Exit(1)
	}
	unix.Close(int(fd))
}
