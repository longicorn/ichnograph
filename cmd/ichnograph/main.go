package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/longicorn/ichnograph/internal/ebpf"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--ichnograph-exec-helper" {
		helper()
		return
	}
	output := flag.String("o", "", "output JSON file (required)")
	includeLogs := flag.Bool("include-logs", false, "include /var/log and .log file records")
	flag.Parse()
	if *output == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: ichnograph [-include-logs] -o output.json command [args...]")
		os.Exit(2)
	}
	result, code, err := ebpf.Run(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !*includeLogs {
		filterLogs(&result)
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

// filterLogs filters the output after collection; it does not reduce BPF traffic.
func filterLogs(result *ebpf.Result) {
	kept := result.Records[:0]
	for _, rec := range result.Records {
		if isLogPath(rec.Path) || isLogPath(rec.ResolvedPath) {
			continue
		}
		kept = append(kept, rec)
	}
	result.Records = kept
	result.Limitations = append(result.Limitations, "Records with paths under /var/log or ending in .log are excluded by default; relative and descriptor paths may be unresolved or inaccurate. Use -include-logs to include them. Filtering occurs after collection and does not reduce event loss.")
}

func isLogPath(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	return clean == "/var/log" || strings.HasPrefix(clean, "/var/log/") || strings.HasSuffix(clean, ".log")
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
