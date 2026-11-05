package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	dir, err := os.Open(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), "target", unix.O_RDONLY, 0)
	if err != nil {
		os.Exit(1)
	}
	defer unix.Close(fd)
	// Keep the directory descriptor available while the collector reads the event.
	time.Sleep(500 * time.Millisecond)
}
