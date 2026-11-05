package main

import (
	"os"
	"runtime"
)

func main() {
	ready := make(chan bool, 2)
	release := make(chan struct{})
	for _, path := range os.Args[1:] {
		go func(path string) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			f, err := os.Open(path)
			if err == nil {
				defer f.Close()
			}
			ready <- err == nil
			<-release
		}(path)
	}
	ok := true
	for i := 0; i < 2; i++ {
		if !<-ready {
			ok = false
		}
	}
	close(release)
	if !ok {
		os.Exit(1)
	}
}
