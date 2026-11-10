package main

import (
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	var fds [2]int
	if unix.Pipe(fds[:]) != nil {
		os.Exit(1)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	var buf [1]byte
	for i := 0; i < 10; i++ {
		if _, err := unix.Write(fds[1], []byte("x")); err != nil {
			os.Exit(1)
		}
		if _, err := unix.Read(fds[0], buf[:]); err != nil {
			os.Exit(1)
		}
	}
	fd, err := unix.Open(os.Args[1], unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		os.Exit(1)
	}
	defer unix.Close(fd)
	for i := 0; i < 10; i++ {
		if _, err := unix.Write(fd, []byte("x")); err != nil {
			os.Exit(1)
		}
		if _, err := unix.Read(fd, buf[:]); err != nil {
			os.Exit(1)
		}
	}
}
