package main

import (
	"golang.org/x/sys/unix"
	"os"
	"time"
)

func main() {
	var buf [1]byte
	if _, err := unix.Read(0, buf[:]); err != nil {
		os.Exit(1)
	}
	time.Sleep(100 * time.Millisecond)
}
