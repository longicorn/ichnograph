package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	dir := os.Args[1]
	var buf [1]byte
	// Reuse the same numeric descriptor for two distinct files.
	fd, err := unix.Open(filepath.Join(dir, "reuse-a"), unix.O_RDONLY, 0)
	check(err)
	_, err = unix.Read(fd, buf[:])
	check(err)
	time.Sleep(150 * time.Millisecond)
	check(unix.Close(fd))
	next, err := unix.Open(filepath.Join(dir, "reuse-b"), unix.O_RDONLY, 0)
	check(err)
	if next != fd {
		fmt.Fprintln(os.Stderr, "descriptor was not reused", fd, next)
		os.Exit(1)
	}
	_, err = unix.Read(next, buf[:])
	check(err)
	time.Sleep(150 * time.Millisecond)
	check(unix.Close(next))
	// An invalid buffer causes EFAULT; retry the same file immediately.
	fd, err = unix.Open(filepath.Join(dir, "retry"), unix.O_RDONLY, 0)
	check(err)
	_, _, errno := unix.Syscall(unix.SYS_READ, uintptr(fd), 0, 1)
	if errno != unix.EFAULT {
		fmt.Fprintln(os.Stderr, "expected EFAULT, got", errno)
		os.Exit(1)
	}
	_, err = unix.Read(fd, buf[:])
	check(err)
	time.Sleep(150 * time.Millisecond)
	check(unix.Close(fd))
	// Replace an fd from a second OS thread while the first thread is idle.
	runtime.LockOSThread()
	fd, err = unix.Open(filepath.Join(dir, "thread-a"), unix.O_RDONLY, 0)
	check(err)
	_, err = unix.Read(fd, buf[:])
	check(err)
	time.Sleep(150 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		other, e := unix.Open(filepath.Join(dir, "thread-b"), unix.O_RDONLY, 0)
		if e == nil {
			e = unix.Dup3(other, fd, 0)
			unix.Close(other)
		}
		done <- e
	}()
	check(<-done)
	_, err = unix.Read(fd, buf[:])
	check(err)
	time.Sleep(150 * time.Millisecond)
	check(unix.Close(fd))
	// Exit immediately after a short-lived access to expose procfs timing limits.
	fd, err = unix.Open(filepath.Join(dir, "short"), unix.O_RDONLY, 0)
	check(err)
	_, err = unix.Read(fd, buf[:])
	check(err)
	check(unix.Close(fd))
}
