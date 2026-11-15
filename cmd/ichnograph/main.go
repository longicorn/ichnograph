package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return usageError("missing subcommand", "")
	}
	switch args[0] {
	case "-h", "--help":
		if len(args) != 1 {
			return usageError("unexpected arguments", "")
		}
		printHelp(os.Stdout, "")
		return 0
	case "help":
		if len(args) == 1 {
			printHelp(os.Stdout, "")
			return 0
		}
		if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
			printHelp(os.Stdout, "help")
			return 0
		}
		if len(args) != 2 {
			return usageError("unexpected arguments", "help")
		}
		if args[1] != "trace" && args[1] != "clew" && args[1] != "help" {
			return usageError("unknown subcommand: "+args[1], "")
		}
		printHelp(os.Stdout, args[1])
		return 0
	case "clew":
		return runClew(args[1:])
	case "trace":
		return runTrace(args[1:])
	default:
		return usageError("unknown subcommand: "+args[0], "")
	}
}

func usageError(message, topic string) int {
	fmt.Fprintln(os.Stderr, "error:", message)
	printHelp(os.Stderr, topic)
	return 2
}

func printHelp(w io.Writer, topic string) {
	switch topic {
	case "trace":
		f, _, _ := traceFlags(w)
		f.Usage()
	case "clew":
		f, _, _ := clewFlags(w)
		f.Usage()
	case "help":
		fmt.Fprintln(w, "usage: ichnograph help [subcommand]\nDisplay help for a public subcommand.")
	default:
		fmt.Fprintln(w, "usage: ichnograph <subcommand> [options] [arguments]\n\nSubcommands:\n  trace  Trace a command and write observations to JSON.\n  clew   Group trace or clew JSON output.\n  help   Display help.\n\nUse ichnograph help <subcommand> for details.")
	}
}

func traceFlags(w io.Writer) (*flag.FlagSet, *string, *bool) {
	f := flag.NewFlagSet("trace", flag.ContinueOnError)
	f.SetOutput(w)
	output := f.String("o", "", "output JSON file (required; default: none)")
	logs := f.Bool("include-logs", false, "include /var/log and .log file records (default: false)")
	f.Usage = func() {
		fmt.Fprintln(w, "usage: ichnograph trace [-include-logs] -o output.json command [args...]\nTrace a command and write observations to JSON.\nOptions:")
		f.PrintDefaults()
	}
	return f, output, logs
}

func runTrace(args []string) int {
	flags, output, includeLogs := traceFlags(os.Stderr)
	// flag invokes Usage for help; suppress it and render to the appropriate stream.
	flags.Usage = func() {}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printHelp(os.Stdout, "trace")
			return 0
		}
		printHelp(os.Stderr, "trace")
		return 2
	}
	if *output == "" || flags.NArg() == 0 {
		return usageError("trace requires -o and a command", "trace")
	}
	result, code, err := ebpf.Run(flags.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
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
		return 1
	}
	return code
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
	result.Limitations = append(result.Limitations, "Records with paths under /var/log or ending in .log are excluded by default; relative and descriptor paths may be unresolved or inaccurate. Use -include-logs to include them. Filtering occurs after collection and does not reduce kernel event volume or loss.")
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
