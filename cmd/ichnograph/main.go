package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/longicorn/ichnograph/internal/ebpf"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--ichnograph-exec-helper" {
		helper()
		return
	}
	output := flag.String("o", "", "output JSON file (required)")
	flag.Parse()
	if *output == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: ichnograph -o output.json command [args...]")
		os.Exit(2)
	}
	result, code, err := ebpf.Run(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err == nil {
		err = os.WriteFile(*output, append(data, '\n'), 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}
func helper() {
	if len(os.Args) < 3 {
		os.Exit(2)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	path, err := exec.LookPath(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, os.ErrPermission) {
			os.Exit(126)
		}
		os.Exit(127)
	}
	err = syscall.Exec(path, os.Args[2:], os.Environ())
	fmt.Fprintln(os.Stderr, err)
	if errors.Is(err, os.ErrNotExist) {
		os.Exit(127)
	}
	os.Exit(126)
}
