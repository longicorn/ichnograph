package main

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ready := make(chan bool)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if unix.Gettid() == os.Getpid() {
			ready <- false
			return
		}
		ready <- true
		err := unix.Exec("/bin/sh", []string{"sh", "-c", `: < "$1"`, "sh", os.Args[1]}, os.Environ())
		_ = err
		os.Exit(1)
	}()
	if !<-ready {
		os.Exit(1)
	}
	select {}
}
