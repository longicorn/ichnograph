package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"sync"
)

func main() {
	if len(os.Args) == 2 {
		port, err := strconv.Atoi(os.Args[1])
		if err != nil {
			os.Exit(2)
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			os.Exit(1)
		}
		defer unix.Close(fd)
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	mode, arg := os.Args[1], os.Args[2]
	if mode == "inherited" || mode == "cancel" {
		port, err := strconv.Atoi(arg)
		if err != nil {
			os.Exit(2)
		}
		fd := 0
		if mode == "inherited" {
			if err := unix.SetNonblock(fd, true); err != nil {
				os.Exit(1)
			}
		}
		if mode == "cancel" {
			fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				os.Exit(1)
			}
		}
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
		if err != unix.EINPROGRESS {
			fmt.Fprintln(os.Stderr, "expected pending:", err)
			os.Exit(1)
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		timeout := 5000
		if mode == "cancel" {
			timeout = 100
		}
		n, e := unix.Poll(p, timeout)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		if mode == "cancel" {
			if n != 0 {
				fmt.Fprintln(os.Stderr, "connection completed before cancellation")
				os.Exit(1)
			}
			if unix.Close(fd) != nil {
				os.Exit(1)
			}
			fmt.Println("pending connection closed")
			return
		}
		if n != 1 {
			os.Exit(1)
		}
		code, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if e != nil || code != 0 {
			fmt.Fprintln(os.Stderr, "SO_ERROR", code, e)
			os.Exit(1)
		}
		fmt.Println("inherited socket connected")
		return
	}
	if mode == "concurrent" {
		port, err := strconv.Atoi(arg)
		if err != nil {
			os.Exit(2)
		}
		const n = 32
		var ready sync.WaitGroup
		ready.Add(n)
		var done sync.WaitGroup
		done.Add(n)
		start := make(chan struct{})
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			go func() {
				defer done.Done()
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					errs <- err
					ready.Done()
					return
				}
				defer unix.Close(fd)
				ready.Done()
				<-start
				err = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
				if err == unix.EINPROGRESS {
					p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
					count, e := unix.Poll(p, 5000)
					if e != nil || count != 1 {
						errs <- fmt.Errorf("poll: %d %v", count, e)
						return
					}
					code, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
					if e != nil || code != 0 {
						errs <- fmt.Errorf("so_error: %d %v", code, e)
						return
					}
				} else if err != nil {
					errs <- err
				}
			}()
		}
		ready.Wait()
		close(start)
		done.Wait()
		close(errs)
		for e := range errs {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Printf("completed=%d concurrent=true\n", n)
		return
	}
	if mode == "reuse" {
		port, err := strconv.Atoi(arg)
		if err != nil {
			os.Exit(2)
		}
		prior := -1
		for i := 0; i < 20; i++ {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				os.Exit(1)
			}
			if prior >= 0 && fd != prior {
				fmt.Fprintln(os.Stderr, "descriptor not reused")
				os.Exit(1)
			}
			err = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
			if err == unix.EINPROGRESS {
				p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
				n, e := unix.Poll(p, 5000)
				if n != 1 || e != nil {
					os.Exit(1)
				}
				soerr, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if e != nil || soerr != 0 {
					os.Exit(1)
				}
			} else if err != nil {
				os.Exit(1)
			}
			if unix.Close(fd) != nil {
				os.Exit(1)
			}
			prior = fd
		}
		fmt.Println("completed=20 same_fd=true")
		return
	}
	family, kind := unix.AF_INET, unix.SOCK_STREAM
	if mode == "unix" || mode == "fail" {
		family = unix.AF_UNIX
	}
	if mode == "udp" {
		kind = unix.SOCK_DGRAM
	}
	if mode == "nonblock" || mode == "poll-good" || mode == "poll-bad" {
		kind |= unix.SOCK_NONBLOCK
	}
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		os.Exit(1)
	}
	defer unix.Close(fd)
	if family == unix.AF_UNIX {
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: arg})
	} else {
		port, e := strconv.Atoi(arg)
		if e != nil {
			os.Exit(2)
		}
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
	}
	if mode == "poll-good" || mode == "poll-bad" {
		if err != nil && err != unix.EINPROGRESS {
			fmt.Fprintln(os.Stderr, "connect:", err)
			os.Exit(1)
		}
		if err == unix.EINPROGRESS {
			p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			n, e := unix.Poll(p, 5000)
			if e != nil || n != 1 {
				fmt.Fprintln(os.Stderr, "poll:", n, e)
				os.Exit(1)
			}
			soerr, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			fmt.Printf("immediate=pending so_error=%d\n", soerr)
			if (mode == "poll-good" && soerr != 0) || (mode == "poll-bad" && soerr != int(unix.ECONNREFUSED)) {
				os.Exit(1)
			}
			return
		}
		fmt.Println("immediate=success so_error=0")
		if mode == "poll-bad" {
			os.Exit(1)
		}
		return
	}
	if mode == "fail" {
		if err == nil {
			os.Exit(1)
		}
		return
	}
	if mode == "nonblock" {
		if err != nil && err != unix.EINPROGRESS {
			os.Exit(1)
		}
		return
	}
	if err != nil {
		os.Exit(1)
	}
}
