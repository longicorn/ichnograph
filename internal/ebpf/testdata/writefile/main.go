package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	fd, err := unix.Open(os.Args[1], unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		os.Exit(1)
	}
	defer unix.Close(fd)
	if n, err := unix.Write(fd, []byte("hello")); err != nil || n != 5 {
		os.Exit(1)
	}
	if n, err := unix.Pwrite(fd, []byte("world"), 0); err != nil || n != 5 {
		os.Exit(1)
	}
	parts := [][]byte{[]byte("he"), []byte("llo")}
	if n, err := unix.Writev(fd, parts); err != nil || n != 5 {
		os.Exit(1)
	}
	if n, err := unix.Pwritev(fd, parts, 0); err != nil || n != 5 {
		os.Exit(1)
	}
	if n, err := unix.Pwritev2(fd, parts, 0, 0); err != nil || n != 5 {
		os.Exit(1)
	}
	if _, err := unix.Write(-1, []byte("x")); err != unix.EBADF {
		os.Exit(1)
	}
	time.Sleep(500 * time.Millisecond)
}
