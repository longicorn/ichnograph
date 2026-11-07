// Package ebpf collects Linux file-open observations.
package ebpf

import (
	"bytes"
	"crypto/md5"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:embed program.o
var object []byte

type Record struct {
	Path         string    `json:"path"`
	ResolvedPath string    `json:"resolved_path,omitempty"`
	PID          uint32    `json:"pid"`
	TID          uint32    `json:"tid"`
	Timestamp    time.Time `json:"timestamp"`
	Event        string    `json:"event"`
	Success      *bool     `json:"success"`
	ExecError    string    `json:"exec_error,omitempty"`
	OpenError    string    `json:"open_error,omitempty"`
	WriteError   string    `json:"write_error,omitempty"`
	ReadError    string    `json:"read_error,omitempty"`
	MmapError    string    `json:"mmap_error,omitempty"`
	DirFD        *int32    `json:"dirfd,omitempty"`
	FD           *int32    `json:"fd,omitempty"`
	BytesWritten *int32    `json:"bytes_written,omitempty"`
	BytesRead    *int32    `json:"bytes_read,omitempty"`
	MD5          string    `json:"md5,omitempty"`
	Note         string    `json:"note,omitempty"`
	pathRetried  bool
	rawKind      uint32
}
type Result struct {
	Records              []Record `json:"records"`
	Lost                 uint64   `json:"lost"`
	DescendantsRemaining bool     `json:"descendants_remaining"`
	Limitations          []string `json:"limitations"`
}
type rawEvent struct {
	NS         uint64
	PID, TID   uint32
	DirFD      int32
	PathResult int32
	Kind       uint32
	Path       [256]byte
}

// Run starts the command only after probes and process tracking are ready.
func Run(args []string) (Result, int, error) {
	return run(args, runOptions{})
}

// runOptions permits deterministic overload testing without changing the CLI.
type runOptions struct {
	ringSize    uint32
	helper      string
	startReader <-chan struct{}
}

func run(args []string, options runOptions) (Result, int, error) {
	result := Result{Records: []Record{}, Limitations: []string{"Only execve, execveat, open, creat, openat, openat2, read, pread64, readv, preadv, preadv2, write, pwrite64, writev, pwritev, pwritev2 and file-backed mmap attempts are recorded; other file operations are not covered. Reads and writes include non-file descriptors. A mapping does not prove data was read. Success is null when the exit event is unavailable.", "Paths may be truncated or unavailable; relative and descriptor paths use later process state and may be inaccurate. Hashes are computed later and may differ from accessed content.", "After the command exits, collection waits up to one second for tracked descendants; later activity is not captured."}}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return result, 1, err
	}
	if options.ringSize != 0 {
		spec.Maps["events"].MaxEntries = options.ringSize
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return result, 1, fmt.Errorf("load eBPF programs (requires BPF privileges): %w", err)
	}
	defer coll.Close()
	var links []link.Link
	for _, p := range []struct{ name, group, event string }{{"fork_event", "sched", "sched_process_fork"}, {"exit_event", "sched", "sched_process_exit"}, {"exec_transition", "sched", "sched_process_exec"}, {"openat_event", "syscalls", "sys_enter_openat"}, {"openat2_event", "syscalls", "sys_enter_openat2"}, {"openat_exit", "syscalls", "sys_exit_openat"}, {"openat2_exit", "syscalls", "sys_exit_openat2"}, {"open_event", "syscalls", "sys_enter_open"}, {"open_exit", "syscalls", "sys_exit_open"}, {"creat_event", "syscalls", "sys_enter_creat"}, {"creat_exit", "syscalls", "sys_exit_creat"}, {"execve_event", "syscalls", "sys_enter_execve"}, {"execve_exit", "syscalls", "sys_exit_execve"}, {"execveat_event", "syscalls", "sys_enter_execveat"}, {"execveat_exit", "syscalls", "sys_exit_execveat"}, {"read_event", "syscalls", "sys_enter_read"}, {"read_exit", "syscalls", "sys_exit_read"}, {"pread_event", "syscalls", "sys_enter_pread64"}, {"pread_exit", "syscalls", "sys_exit_pread64"}, {"readv_event", "syscalls", "sys_enter_readv"}, {"readv_exit", "syscalls", "sys_exit_readv"}, {"preadv_event", "syscalls", "sys_enter_preadv"}, {"preadv_exit", "syscalls", "sys_exit_preadv"}, {"preadv2_event", "syscalls", "sys_enter_preadv2"}, {"preadv2_exit", "syscalls", "sys_exit_preadv2"}, {"write_event", "syscalls", "sys_enter_write"}, {"write_exit", "syscalls", "sys_exit_write"}, {"pwrite_event", "syscalls", "sys_enter_pwrite64"}, {"pwrite_exit", "syscalls", "sys_exit_pwrite64"}, {"writev_event", "syscalls", "sys_enter_writev"}, {"writev_exit", "syscalls", "sys_exit_writev"}, {"pwritev_event", "syscalls", "sys_enter_pwritev"}, {"pwritev_exit", "syscalls", "sys_exit_pwritev"}, {"pwritev2_event", "syscalls", "sys_enter_pwritev2"}, {"pwritev2_exit", "syscalls", "sys_exit_pwritev2"}, {"mmap_event", "syscalls", "sys_enter_mmap"}, {"mmap_exit", "syscalls", "sys_exit_mmap"}} {
		l, e := link.Tracepoint(p.group, p.event, coll.Programs[p.name], nil)
		if e != nil {
			for _, old := range links {
				old.Close()
			}
			return result, 1, fmt.Errorf("attach %s: %w", p.event, e)
		}
		links = append(links, l)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return result, 1, err
	}
	defer reader.Close()
	exe := options.helper
	if exe == "" {
		exe, err = os.Executable()
	}
	if err != nil {
		return result, 1, err
	}
	cmd := exec.Command(exe, append([]string{"--ichnograph-exec-helper"}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return result, 1, err
	}
	// The helper stops itself before exec, preventing missed initial accesses.
	var status unix.WaitStatus
	if _, err = unix.Wait4(cmd.Process.Pid, &status, unix.WUNTRACED, nil); err != nil || !status.Stopped() {
		cmd.Process.Kill()
		cmd.Wait()
		return result, 1, fmt.Errorf("wait for stopped helper: %v (status %v)", err, status)
	}
	tid := uint32(cmd.Process.Pid)
	one := uint32(1)
	if err = coll.Maps["tracked"].Put(tid, one); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return result, 1, err
	}
	var mono unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return result, 1, err
	}
	boot := time.Now().Add(-time.Duration(mono.Nano()))
	type readResult struct {
		records   []Record
		ambiguous bool
		err       error
	}
	done := make(chan readResult, 1)
	go func() {
		state := eventState{pending: make(map[uint32]int), boot: boot}
		if options.startReader != nil {
			<-options.startReader
		}
		for {
			sample, e := reader.Read()
			if errors.Is(e, ringbuf.ErrClosed) || errors.Is(e, ringbuf.ErrFlushed) {
				done <- readResult{state.records, state.ambiguous, nil}
				return
			}
			if e != nil {
				done <- readResult{state.records, state.ambiguous, e}
				return
			}
			var raw rawEvent
			if e = binary.Read(bytes.NewReader(sample.RawSample), binary.LittleEndian, &raw); e != nil {
				done <- readResult{state.records, state.ambiguous, e}
				return
			}
			state.add(raw)
		}
	}()
	if err = cmd.Process.Signal(syscall.SIGCONT); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		reader.Close()
		<-done
		return result, 1, err
	}
	waitErr := cmd.Wait()
	remaining, trackingErr := waitForDescendants(coll.Maps["tracked"], time.Second)
	flushErr := reader.Flush()
	if flushErr != nil {
		reader.Close()
	}
	read := <-done
	result.Records = read.records
	if read.ambiguous {
		result.Limitations = append(result.Limitations, "Overlapping or mismatched events make subsequent entry/exit correlations unavailable for the affected thread ID.")
	}
	if result.Records == nil {
		result.Records = []Record{}
	}
	var key uint32
	if e := coll.Maps["lost"].Lookup(key, &result.Lost); e != nil {
		return result, 1, e
	}
	if read.err != nil {
		return result, 1, fmt.Errorf("read events: %w", read.err)
	}
	if flushErr != nil {
		return result, 1, fmt.Errorf("flush events: %w", flushErr)
	}
	if trackingErr != nil {
		return result, 1, fmt.Errorf("check descendant processes: %w", trackingErr)
	}
	result.DescendantsRemaining = remaining
	if remaining {
		result.Limitations = append(result.Limitations, "Tracked descendants remained when collection stopped; their later activity is not captured.")
	}
	result.invalidateOnLoss()
	hashRecords(result.Records, hashFile)
	if waitErr != nil {
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) {
			return result, commandExitCode(exit), nil
		}
		return result, 1, waitErr
	}
	return result, 0, nil
}

func hashRecords(records []Record, hash func(string) (string, error)) {
	type hashResult struct {
		sum string
		err error
	}
	results := make(map[string]hashResult)
	for i := range records {
		rec := &records[i]
		if rec.Note != "" || rec.Success == nil || !*rec.Success || !filepath.IsAbs(rec.Path) {
			continue
		}
		clean := filepath.Clean(rec.Path)
		if clean == "/proc/self" || strings.HasPrefix(clean, "/proc/self/") || clean == "/proc/thread-self" || strings.HasPrefix(clean, "/proc/thread-self/") {
			rec.Note = "hash unavailable: proc self path refers to the collector when read later"
			continue
		}
		result, ok := results[rec.Path]
		if !ok {
			result.sum, result.err = hash(rec.Path)
			results[rec.Path] = result
		}
		rec.MD5 = result.sum
		if result.err != nil {
			rec.Note = "hash unavailable: " + result.err.Error()
		}
	}
}

func waitForDescendants(tracked *ebpf.Map, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		var tid uint32
		err := tracked.NextKey(nil, &tid)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !time.Now().Before(deadline) {
			return true, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func commandExitCode(exit *exec.ExitError) int {
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exit.ExitCode()
}

type eventState struct {
	records   []Record
	pending   map[uint32]int
	boot      time.Time
	uncertain map[uint32]bool
	ambiguous bool
}

func eventName(kind uint32) string {
	switch kind {
	case 0, 10, 11, 12:
		return "open_attempt"
	case 1:
		return "read_attempt"
	case 2:
		return "pread_attempt"
	case 3:
		return "readv_attempt"
	case 4:
		return "preadv_attempt"
	case 5:
		return "preadv2_attempt"
	case 6:
		return "mmap_attempt"
	case 7, 8:
		return "exec_attempt"
	case 13:
		return "write_attempt"
	case 14:
		return "pwrite_attempt"
	case 15:
		return "writev_attempt"
	case 16:
		return "pwritev_attempt"
	case 17:
		return "pwritev2_attempt"
	default:
		return "unknown_attempt"
	}
}

func isOpenKind(kind uint32) bool {
	return kind == 0 || kind == 10 || kind == 11 || kind == 12
}

func (s *eventState) add(raw rawEvent) {
	if raw.PID == 0 {
		if raw.Kind == 9 {
			old := uint32(raw.DirFD)
			_, collision := s.pending[raw.TID]
			collision = collision && old != raw.TID
			index, ok := s.pending[old]
			mismatch := ok && s.records[index].Event != "exec_attempt"
			if s.uncertain[old] || s.uncertain[raw.TID] || collision || mismatch {
				if s.uncertain == nil {
					s.uncertain = make(map[uint32]bool)
				}
				s.ambiguous = true
				s.uncertain[old] = true
				s.uncertain[raw.TID] = true
				delete(s.pending, old)
				delete(s.pending, raw.TID)
				return
			}
			delete(s.pending, old)
			delete(s.pending, raw.TID)
			if ok && s.records[index].Event == "exec_attempt" {
				success := true
				s.records[index].Success = &success
			}
			return
		}
		if index, ok := s.pending[raw.TID]; ok {
			if raw.Kind != s.records[index].rawKind {
				if s.uncertain == nil {
					s.uncertain = make(map[uint32]bool)
				}
				s.uncertain[raw.TID] = true
				s.ambiguous = true
				delete(s.pending, raw.TID)
				return
			}
			ret := int64(raw.DirFD)
			if raw.Kind == 6 {
				ret = int64(raw.NS)
			}
			success := ret >= 0 || ret < -4095
			s.records[index].Success = &success
			if !success {
				if raw.Kind == 6 {
					s.records[index].MmapError = syscall.Errno(-ret).Error()
				} else if raw.Kind == 7 || raw.Kind == 8 {
					s.records[index].ExecError = syscall.Errno(-ret).Error()
				} else if raw.Kind >= 13 && raw.Kind <= 17 {
					s.records[index].WriteError = syscall.Errno(-ret).Error()
				} else if !isOpenKind(raw.Kind) {
					s.records[index].ReadError = syscall.Errno(-ret).Error()
				} else {
					s.records[index].OpenError = syscall.Errno(-raw.DirFD).Error()
				}
			} else if !isOpenKind(raw.Kind) && raw.Kind != 6 && raw.Kind != 7 && raw.Kind != 8 {
				count := raw.DirFD
				if raw.Kind >= 13 && raw.Kind <= 17 {
					s.records[index].BytesWritten = &count
				} else {
					s.records[index].BytesRead = &count
				}
			}
			if (isOpenKind(raw.Kind) || raw.Kind == 7 || raw.Kind == 8) && raw.PathResult > 0 && s.records[index].Path == "" {
				s.records[index].Path = string(bytes.TrimRight(raw.Path[:], "\x00"))
				s.records[index].Note = "path read after the syscall; it may have changed or been truncated"
				s.records[index].pathRetried = true
			}
			delete(s.pending, raw.TID)
		}
		return
	}
	path := string(bytes.TrimRight(raw.Path[:], "\x00"))
	rec := Record{Path: path, PID: raw.PID, TID: raw.TID, Timestamp: s.boot.Add(time.Duration(raw.NS)), Event: "open_attempt", rawKind: raw.Kind}
	if !isOpenKind(raw.Kind) && raw.Kind != 7 && raw.Kind != 8 {
		rec.Event = eventName(raw.Kind)
		fd := raw.DirFD
		rec.FD = &fd
		resolved, err := resolveDescriptor(raw.PID, raw.TID, fd)
		if err != nil {
			rec.Note = "descriptor path unavailable: " + err.Error()
		} else {
			rec.ResolvedPath = resolved
			rec.Note = "descriptor path read from process state after the event; it may have changed"
		}
	} else if raw.PathResult < 0 {
		rec.Path = ""
		rec.Note = fmt.Sprintf("path unavailable: %v", syscall.Errno(-raw.PathResult))
	} else if len(path) == 255 {
		rec.Note = "path may be truncated"
	} else if path == "" && raw.Kind == 8 {
		resolved, err := resolveDescriptor(raw.PID, raw.TID, raw.DirFD)
		if err != nil {
			rec.Note = "empty pathname; descriptor target unavailable: " + err.Error()
		} else {
			rec.ResolvedPath = resolved
			rec.Note = "empty pathname; descriptor path read after the event and may have changed; flags are not recorded"
		}
	} else if path == "" {
		rec.Note = "empty pathname"

	} else if !filepath.IsAbs(path) {
		resolved, err := resolveRelativePath(raw.PID, raw.TID, raw.DirFD, path)
		if err != nil {
			rec.Note = "relative path is unresolved: " + err.Error()
		} else {
			rec.ResolvedPath = resolved
			rec.Note = "relative path resolved from process state after the event; it may have changed"
		}
	}
	if raw.Kind == 7 || raw.Kind == 8 {
		rec.Event = eventName(raw.Kind)
	}
	if isOpenKind(raw.Kind) || raw.Kind == 7 || raw.Kind == 8 {
		dirfd := raw.DirFD
		rec.DirFD = &dirfd
	}
	if _, exists := s.pending[raw.TID]; exists {
		if s.uncertain == nil {
			s.uncertain = make(map[uint32]bool)
		}
		s.uncertain[raw.TID] = true
		s.ambiguous = true
		delete(s.pending, raw.TID)
	}
	if !s.uncertain[raw.TID] {
		s.pending[raw.TID] = len(s.records)
	}
	s.records = append(s.records, rec)
}

func (r *Result) invalidateOnLoss() {
	if r.Lost == 0 {
		return
	}
	// Lost entries or exits make correlation ambiguous, including after TID reuse.
	r.Limitations = append(r.Limitations, "Success results are unavailable because event loss makes entry/exit correlation unreliable.")
	for i := range r.Records {
		r.Records[i].Success = nil
		r.Records[i].OpenError = ""
		r.Records[i].ExecError = ""
		r.Records[i].ReadError = ""
		r.Records[i].WriteError = ""
		r.Records[i].MmapError = ""
		r.Records[i].BytesRead = nil
		r.Records[i].BytesWritten = nil
		if r.Records[i].pathRetried {
			r.Records[i].Path = ""
			r.Records[i].Note = "path unavailable: event loss makes retry correlation unreliable"
		}
	}
}

func resolveDescriptor(pid, tid uint32, fd int32) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/task/%d/fd/%d", pid, tid, fd))
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
		return "", fmt.Errorf("descriptor has no available absolute path")
	}
	return path, nil
}

// resolveRelativePath uses a later snapshot, which can differ from syscall-time state.
func resolveRelativePath(pid, tid uint32, dirfd int32, path string) (string, error) {
	for _, component := range strings.Split(path, "/") {
		if component == ".." {
			return "", fmt.Errorf("path contains .. and may cross symbolic links")
		}
	}
	base := fmt.Sprintf("/proc/%d/task/%d/", pid, tid)
	if dirfd == unix.AT_FDCWD {
		base += "cwd"
	} else {
		base += fmt.Sprintf("fd/%d", dirfd)
	}
	dir, err := os.Readlink(base)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) || strings.HasSuffix(dir, " (deleted)") {
		return "", fmt.Errorf("base is not an available absolute path")
	}
	return filepath.Join(dir, path), nil
}

func hashFile(path string) (string, error) {
	// O_PATH inspects the target without opening devices or FIFOs for reading.
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	ref := os.NewFile(uintptr(fd), path)
	defer ref.Close()
	info, err := ref.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return "", fmt.Errorf("inspect filesystem: %w", err)
	}
	if uint64(fs.Type) == uint64(unix.PROC_SUPER_MAGIC) {
		return "", fmt.Errorf("procfs contents depend on process or runtime state")
	}
	// Reopen the inspected inode, not the original path, which may have changed.
	readFD, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(readFD), path)
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
