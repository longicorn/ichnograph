package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	var buf [64]byte
	n, err := os.Stdin.Read(buf[:])
	if err != nil || n == 0 {
		os.Exit(1)
	}
	if n, err = unix.Pread(0, buf[:], 0); err != nil || n != 5 {
		os.Exit(1)
	}
	if _, err = unix.Seek(0, 0, 0); err != nil {
		os.Exit(1)
	}
	if n, err = unix.Readv(0, [][]byte{buf[:2], buf[2:5]}); err != nil || n != 5 {
		os.Exit(1)
	}
	if n, err = unix.Preadv(0, [][]byte{buf[:2], buf[2:5]}, 0); err != nil || n != 5 {
		os.Exit(1)
	}
	if n, err = unix.Preadv2(0, [][]byte{buf[:2], buf[2:5]}, 0, 0); err != nil || n != 5 {
		os.Exit(1)
	}
	mapping, err := unix.Mmap(0, 0, 5, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil || string(mapping) != "hello" {
		os.Exit(1)
	}
	defer unix.Munmap(mapping)

	time.Sleep(500 * time.Millisecond)
}
