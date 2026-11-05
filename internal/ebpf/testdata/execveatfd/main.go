//go:build linux && amd64

package main

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	fd, err := unix.Open(os.Args[1], unix.O_RDONLY, 0)
	if err != nil {
		os.Exit(1)
	}
	name, _ := unix.BytePtrFromString("")
	arg, _ := unix.BytePtrFromString(os.Args[1])
	argv := []*byte{arg, nil}
	env := []*byte{nil}
	unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])), unix.AT_EMPTY_PATH, 0)
	runtime.KeepAlive(name)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(env)
	os.Exit(1)
}
