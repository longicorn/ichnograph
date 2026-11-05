//go:build linux && amd64

package main

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func execute(path string) unix.Errno {
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		os.Exit(1)
	}
	argv := []*byte{name, nil}
	env := []*byte{nil}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, ^uintptr(99), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])), 0, 0)
	runtime.KeepAlive(name)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(env)
	return errno
}

func main() {
	if execute(os.Args[1]) != unix.ENOENT {
		os.Exit(1)
	}
	execute("/bin/true")
	os.Exit(1)
}
