package ebpf

import (
	"bytes"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestEmbeddedProgram(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fork_event", "exit_event", "exec_transition", "openat_event", "openat2_event", "openat_exit", "openat2_exit", "open_event", "open_exit", "creat_event", "creat_exit", "execve_event", "execve_exit", "execveat_event", "execveat_exit", "read_event", "read_exit", "pread_event", "pread_exit", "readv_event", "readv_exit", "preadv_event", "preadv_exit", "preadv2_event", "preadv2_exit", "write_event", "write_exit", "pwrite_event", "pwrite_exit", "writev_event", "writev_exit", "pwritev_event", "pwritev_exit", "pwritev2_event", "pwritev2_exit", "mmap_event", "mmap_exit"} {
		if spec.Programs[name] == nil {
			t.Errorf("missing program %s", name)
		}
	}
	for _, name := range []string{"tracked", "events", "lost", "retry_paths", "mmap_pending"} {
		if spec.Maps[name] == nil {
			t.Errorf("missing map %s", name)
		}
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := hashFile(path)
	if err != nil || got != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("hashFile = %q, %v", got, err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFile(fifo); err == nil {
		t.Fatal("expected FIFO to be rejected")
	}
	if _, err := hashFile("/dev/null"); err == nil {
		t.Fatal("expected device to be rejected")
	}
	if _, err := hashFile(dir); err == nil {
		t.Fatal("expected directory to be rejected")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if got, err := hashFile(link); err != nil || got != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("hashFile symlink = %q, %v", got, err)
	}
	procLink := filepath.Join(dir, "proc-link")
	if err := os.Symlink("/proc/self/status", procLink); err != nil {
		t.Fatal(err)
	}
	for _, procPath := range []string{"/proc/self/status", "/proc/meminfo", procLink} {
		if _, err := hashFile(procPath); err == nil || !strings.Contains(err.Error(), "procfs") {
			t.Fatalf("expected procfs rejection for %s: %v", procPath, err)
		}
	}
}

func TestResolveRelativePath(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid, tid := uint32(os.Getpid()), uint32(unix.Gettid())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveRelativePath(pid, tid, unix.AT_FDCWD, ".")
	if err != nil || got != cwd {
		t.Fatalf("cwd: got %q, %v; want %q", got, err, cwd)
	}
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err = resolveRelativePath(pid, tid, int32(f.Fd()), "child")
	if err != nil || got != filepath.Join(dir, "child") {
		t.Fatalf("dirfd: got %q, %v", got, err)
	}
	if _, err := resolveRelativePath(pid, tid, unix.AT_FDCWD, "link/../file"); err == nil {
		t.Fatal("expected ambiguous path to be rejected")
	}
	if _, err := resolveRelativePath(pid, tid, 999999, "file"); err == nil {
		t.Fatal("expected unavailable descriptor to be rejected")
	}
}

func TestOpenResultsAndLoss(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	entry := func(tid uint32, path string) rawEvent {
		e := rawEvent{PID: 1, TID: tid, PathResult: int32(len(path) + 1)}
		copy(e.Path[:], path)
		return e
	}
	state.add(entry(1, "/first"))
	state.add(entry(2, "/missing-exit"))
	state.add(rawEvent{TID: 1, DirFD: 3})
	state.add(entry(1, "/failed"))
	state.add(rawEvent{TID: 1, DirFD: -int32(unix.ENOENT)})
	state.add(rawEvent{TID: 999, DirFD: 5}) // An exit with no entry must not change another record.
	if len(state.records) != 3 {
		t.Fatalf("got %d records", len(state.records))
	}
	if state.records[0].Success == nil || !*state.records[0].Success {
		t.Fatal("successful open not matched")
	}
	if state.records[1].Success != nil {
		t.Fatal("missing exit should have unknown result")
	}
	if state.records[2].Success == nil || *state.records[2].Success || state.records[2].OpenError != unix.ENOENT.Error() {
		t.Fatalf("failure not matched: %+v", state.records[2])
	}
	result := Result{Records: state.records, Lost: 1}
	result.invalidateOnLoss()
	for _, rec := range result.Records {
		if rec.Success != nil || rec.OpenError != "" {
			t.Fatalf("result survived event loss: %+v", rec)
		}
	}
	if len(result.Limitations) == 0 {
		t.Fatal("loss limitation missing")
	}
}

func TestPathRetryAndLoss(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	state.add(rawEvent{PID: 10, TID: 10, PathResult: -int32(unix.EFAULT)})
	exit := rawEvent{TID: 10, DirFD: 3, PathResult: 6}
	copy(exit.Path[:], "/file")
	state.add(exit)
	if len(state.records) != 1 || state.records[0].Path != "/file" || !state.records[0].pathRetried || state.records[0].Note == "" {
		t.Fatalf("retry missing: %+v", state.records)
	}
	result := Result{Records: state.records, Lost: 1}
	result.invalidateOnLoss()
	if result.Records[0].Path != "" {
		t.Fatalf("retry path survived loss: %+v", result.Records[0])
	}
}

func TestMmapResults(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	state.add(rawEvent{PID: 1, TID: 1, Kind: 6, DirFD: 3})
	state.add(rawEvent{TID: 1, Kind: 6, NS: 0x7fff12340000})
	if state.records[0].Success == nil || !*state.records[0].Success || state.records[0].BytesRead != nil {
		t.Fatalf("successful mmap: %+v", state.records[0])
	}
	state.add(rawEvent{PID: 1, TID: 1, Kind: 6, DirFD: 3})
	errno := int64(-int64(unix.EBADF))
	state.add(rawEvent{TID: 1, Kind: 6, NS: uint64(errno)})
	if state.records[1].Success == nil || *state.records[1].Success || state.records[1].MmapError != unix.EBADF.Error() {
		t.Fatalf("failed mmap: %+v", state.records[1])
	}
}

func TestWriteResultsAndLoss(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	state.add(rawEvent{PID: 1, TID: 1, Kind: 13, DirFD: 3})
	state.add(rawEvent{TID: 1, Kind: 13, DirFD: 5})
	state.add(rawEvent{PID: 1, TID: 1, Kind: 14, DirFD: 3})
	state.add(rawEvent{TID: 1, Kind: 14, DirFD: -int32(unix.EBADF)})
	if state.records[0].BytesWritten == nil || *state.records[0].BytesWritten != 5 || state.records[0].BytesRead != nil || state.records[1].WriteError != unix.EBADF.Error() {
		t.Fatalf("unexpected write results: %+v", state.records)
	}
	result := Result{Records: state.records, Lost: 1}
	result.invalidateOnLoss()
	for _, rec := range result.Records {
		if rec.Success != nil || rec.BytesWritten != nil || rec.WriteError != "" {
			t.Fatalf("write result survived loss: %+v", rec)
		}
	}
}

func TestVectoredWriteResults(t *testing.T) {
	for _, tc := range []struct {
		kind uint32
		name string
	}{{15, "writev_attempt"}, {16, "pwritev_attempt"}, {17, "pwritev2_attempt"}} {
		state := eventState{pending: make(map[uint32]int)}
		state.add(rawEvent{PID: 1, TID: 1, Kind: tc.kind, DirFD: 3})
		state.add(rawEvent{TID: 1, Kind: tc.kind, DirFD: 5})
		r := state.records[0]
		if r.Event != tc.name || r.Success == nil || !*r.Success || r.BytesWritten == nil || *r.BytesWritten != 5 || r.BytesRead != nil {
			t.Fatalf("kind %d: %+v", tc.kind, r)
		}
	}
}

func TestCommandExitCode(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{{"exit 7", 7}, {"kill -TERM $$", 143}} {
		err := exec.Command("/bin/sh", "-c", tc.script).Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("%s: expected exit error, got %v", tc.script, err)
		}
		if got := commandExitCode(exit); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.script, got, tc.want)
		}
	}
}

func TestHashRecordsCachesPerPath(t *testing.T) {
	yes, no := true, false
	records := []Record{
		{Path: "/good", Success: &yes}, {Path: "/good", Success: &yes},
		{Path: "/bad", Success: &yes}, {Path: "/bad", Success: &yes},
		{Path: "/failed", Success: &no}, {Path: "/unknown"},
		{Path: "/uncertain", Success: &yes, Note: "later observation"},
		{Path: "relative", Success: &yes},
	}
	calls := map[string]int{}
	hashRecords(records, func(path string) (string, error) {
		calls[path]++
		if path == "/bad" {
			return "", errors.New("unreadable")
		}
		return "hash", nil
	})
	if len(calls) != 2 || calls["/good"] != 1 || calls["/bad"] != 1 {
		t.Fatalf("unexpected hash calls: %v", calls)
	}
	if records[0].MD5 != "hash" || records[1].MD5 != "hash" {
		t.Fatalf("cached hash not applied: %+v", records)
	}
	if records[2].Note != "hash unavailable: unreadable" || records[3].Note != records[2].Note {
		t.Fatalf("cached error not applied: %+v", records)
	}
}

func TestHashRecordsSkipsProcSelf(t *testing.T) {
	yes := true
	records := []Record{
		{Path: "/proc/self/cgroup", Success: &yes},
		{Path: "/proc//thread-self/status", Success: &yes},
		{Path: "/proc/selfish/file", Success: &yes},
	}
	var calls []string
	hashRecords(records, func(path string) (string, error) {
		calls = append(calls, path)
		return "digest", nil
	})
	if len(calls) != 1 || calls[0] != "/proc/selfish/file" {
		t.Fatalf("unexpected hash calls: %v", calls)
	}
	for _, rec := range records[:2] {
		if rec.MD5 != "" || rec.Note == "" {
			t.Fatalf("proc self path was not excluded: %+v", rec)
		}
	}
	if records[2].MD5 != "digest" {
		t.Fatalf("unrelated path excluded: %+v", records[2])
	}
}

func TestExecveatEmptyPathResolution(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	path := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	state := eventState{pending: make(map[uint32]int)}
	tid := uint32(unix.Gettid())
	state.add(rawEvent{PID: uint32(os.Getpid()), TID: tid, Kind: 8, DirFD: int32(f.Fd()), PathResult: 1})
	state.add(rawEvent{TID: tid, Kind: 8})
	rec := state.records[0]
	if rec.Event != "exec_attempt" || rec.Path != "" || rec.ResolvedPath != path || rec.Success == nil || !*rec.Success || rec.Note == "" {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestExecThreadTransition(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	entry := rawEvent{PID: 10, TID: 11, Kind: 7, PathResult: 8}
	copy(entry.Path[:], "/bin/sh")
	state.add(entry)
	state.add(rawEvent{Kind: 9, TID: 10, DirFD: 11})
	state.add(rawEvent{Kind: 7, TID: 10})
	if len(state.records) != 1 || state.records[0].TID != 11 || state.records[0].Success == nil || !*state.records[0].Success {
		t.Fatalf("transition not matched: %+v", state.records)
	}
	if len(state.pending) != 0 {
		t.Fatalf("stale pending entries: %v", state.pending)
	}
}

func TestExecSchedulerSuccess(t *testing.T) {
	for _, kind := range []uint32{7, 8} {
		state := eventState{pending: make(map[uint32]int)}
		entry := rawEvent{PID: 10, TID: 10, Kind: kind, PathResult: 6}
		copy(entry.Path[:], "/file")
		state.add(entry)
		state.add(rawEvent{Kind: 9, TID: 10, DirFD: 10})
		// A subsequent syscall exit, including one with a different exec kind,
		// must not invalidate the scheduler's success observation.
		state.add(rawEvent{Kind: 7, TID: 10})
		state.add(rawEvent{PID: 10, TID: 10, PathResult: 6})
		state.add(rawEvent{TID: 10, DirFD: 3})
		if state.ambiguous || state.records[0].Success == nil || !*state.records[0].Success || state.records[1].Success == nil || !*state.records[1].Success {
			t.Fatalf("kind %d: %+v", kind, state.records)
		}
	}
}

func TestDifferentExecKindsDoNotCorrelate(t *testing.T) {
	for _, pair := range [][2]uint32{{7, 8}, {8, 7}} {
		state := eventState{pending: make(map[uint32]int)}
		state.add(rawEvent{PID: 10, TID: 10, Kind: pair[0], PathResult: 1})
		state.add(rawEvent{TID: 10, Kind: pair[1], DirFD: -int32(unix.ENOENT)})
		if len(state.records) != 1 || state.records[0].Success != nil || state.records[0].ExecError != "" {
			t.Fatalf("entry kind %d matched exit kind %d: %+v", pair[0], pair[1], state.records)
		}
		if len(state.pending) != 0 {
			t.Fatalf("mismatched entry remained pending: %v", state.pending)
		}
		state.add(rawEvent{PID: 10, TID: 10, Kind: pair[0], PathResult: 1})
		state.add(rawEvent{TID: 10, Kind: pair[0]})
		if !state.ambiguous || state.records[1].Success != nil {
			t.Fatalf("subsequent operation should be uncertain: %+v", state.records)
		}
	}
}

func TestOpenKindsCorrelation(t *testing.T) {
	for _, entryKind := range []uint32{0, 10, 11, 12} {
		for _, exitKind := range []uint32{0, 10, 11, 12} {
			state := eventState{pending: make(map[uint32]int)}
			entry := rawEvent{PID: 1, TID: 1, Kind: entryKind, PathResult: 6}
			copy(entry.Path[:], "/file")
			state.add(entry)
			state.add(rawEvent{TID: 1, Kind: exitKind, DirFD: -int32(unix.ENOENT)})
			rec := state.records[0]
			if rec.Event != "open_attempt" || rec.DirFD == nil {
				t.Fatalf("kind %d: unexpected entry: %+v", entryKind, rec)
			}
			if entryKind == exitKind {
				if rec.Success == nil || *rec.Success || rec.OpenError != unix.ENOENT.Error() {
					t.Fatalf("kind %d: missing failure: %+v", entryKind, rec)
				}
			} else if rec.Success != nil || rec.OpenError != "" {
				t.Fatalf("entry %d matched exit %d: %+v", entryKind, exitKind, rec)
			}
		}
	}
}

func TestOverlappingEntriesRemainUncertain(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	entry := rawEvent{PID: 10, TID: 11, Kind: 7, PathResult: 6}
	copy(entry.Path[:], "/file")
	state.add(entry)
	state.add(entry)
	state.add(rawEvent{Kind: 7, TID: 11})
	state.add(rawEvent{Kind: 9, TID: 11, DirFD: 11})
	state.add(rawEvent{Kind: 9, TID: 10, DirFD: 11})
	entry.TID = 11
	state.add(entry)
	state.add(rawEvent{Kind: 7, TID: 11})
	entry.TID = 10
	state.add(entry)
	state.add(rawEvent{Kind: 7, TID: 10})
	if !state.ambiguous || len(state.pending) != 0 {
		t.Fatalf("overlap not retained: %+v", state)
	}
	for _, rec := range state.records {
		if rec.Success != nil || rec.ExecError != "" {
			t.Fatalf("ambiguous operation has a result: %+v", rec)
		}
	}
	entry.TID = 12
	state.add(entry)
	state.add(rawEvent{Kind: 7, TID: 12})
	if rec := state.records[len(state.records)-1]; rec.Success == nil || !*rec.Success {
		t.Fatalf("unaffected thread did not correlate: %+v", rec)
	}
}

func TestExecSchedulerConflicts(t *testing.T) {
	for _, newTID := range []uint32{10, 11} {
		state := eventState{pending: make(map[uint32]int)}
		state.add(rawEvent{PID: 10, TID: 10, Kind: 0, PathResult: 1})
		state.add(rawEvent{Kind: 9, TID: newTID, DirFD: 10})
		state.add(rawEvent{PID: 10, TID: newTID, Kind: 0, PathResult: 1})
		state.add(rawEvent{TID: newTID, Kind: 0, DirFD: 3})
		if !state.ambiguous || !state.uncertain[10] || !state.uncertain[newTID] || state.records[0].Success != nil || state.records[1].Success != nil {
			t.Fatalf("new TID %d: %+v", newTID, state)
		}
	}
}

func TestExecTransitionPendingCollision(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	state.add(rawEvent{PID: 10, TID: 11, Kind: 7, PathResult: 1})
	state.add(rawEvent{PID: 10, TID: 10, Kind: 0, PathResult: 1})
	state.add(rawEvent{Kind: 9, TID: 10, DirFD: 11})
	for _, tid := range []uint32{10, 11} {
		state.add(rawEvent{PID: 10, TID: tid, Kind: 0, PathResult: 1})
		state.add(rawEvent{TID: tid, Kind: 0, DirFD: 3})
		if !state.uncertain[tid] {
			t.Fatalf("TID %d was not marked uncertain", tid)
		}
	}
	if !state.ambiguous || len(state.pending) != 0 {
		t.Fatalf("collision not retained: %+v", state)
	}
	for _, rec := range state.records {
		if rec.Success != nil {
			t.Fatalf("collision produced a result: %+v", rec)
		}
	}
}

func TestExecSchedulerSuccessInvalidatedByLoss(t *testing.T) {
	state := eventState{pending: make(map[uint32]int)}
	state.add(rawEvent{PID: 10, TID: 10, Kind: 8, PathResult: 1})
	state.add(rawEvent{Kind: 9, TID: 10, DirFD: 10})
	if state.records[0].Success == nil || !*state.records[0].Success {
		t.Fatalf("scheduler success missing: %+v", state.records[0])
	}
	result := Result{Records: state.records, Lost: 1}
	result.invalidateOnLoss()
	if result.Records[0].Success != nil || len(result.Limitations) == 0 {
		t.Fatalf("scheduler result survived loss: %+v", result)
	}
}
