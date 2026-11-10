package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	previous := -1
	for _, name := range []string{"first", "second"} {
		fd, err := unix.Open(filepath.Join(os.Args[1], name), unix.O_WRONLY, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if previous >= 0 && fd != previous {
			fmt.Fprintln(os.Stderr, "fd not reused")
			os.Exit(1)
		}
		for i := 0; i < 1000; i++ {
			if _, err := unix.Write(fd, []byte("x")); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		time.Sleep(150 * time.Millisecond)
		if err := unix.Close(fd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		previous = fd
	}
}
