//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	how := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC}
	fd, err := unix.Openat2(unix.AT_FDCWD, os.Args[1], how)
	if err != nil {
		os.Exit(1)
	}
	unix.Close(fd)
	fd, err = unix.Openat2(unix.AT_FDCWD, os.Args[2], how)
	if err != unix.ENOENT {
		if err == nil {
			unix.Close(fd)
		}
		os.Exit(1)
	}
}
