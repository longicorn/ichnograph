package ebpf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLongPath(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	if out, err := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	longDir := filepath.Join(dir, strings.Repeat("a", 150), strings.Repeat("b", 150))
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(longDir, "target")
	if err := os.WriteFile(target, []byte("long path"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	if out, err := exec.Command(collector, "-o", output, "/bin/cat", target).CombinedOutput(); err != nil {
		t.Fatalf("collect: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("lost %d events", result.Lost)
	}
	for _, record := range result.Records {
		if record.Event == "open_attempt" && record.Path == target[:255] {
			if record.Success == nil || !*record.Success || record.Note != "path may be truncated" || record.MD5 != "" {
				t.Fatalf("unexpected truncated record: %+v", record)
			}
			return
		}
	}
	t.Fatalf("missing truncated path record: %s", data)
}

func TestMissingFile(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	if out, err := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	missing := filepath.Join(dir, "missing")
	output := filepath.Join(dir, "result.json")
	err := exec.Command(collector, "-o", output, "/bin/cat", missing).Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("expected cat exit 1, got %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("lost %d events", result.Lost)
	}
	for _, record := range result.Records {
		if record.Event == "open_attempt" && record.Path == missing {
			if record.Success == nil || *record.Success || record.OpenError != unix.ENOENT.Error() || record.MD5 != "" {
				t.Fatalf("unexpected failed open: %+v", record)
			}
			return
		}
	}
	t.Fatalf("missing failed-open record: %s", data)
}

func TestProcSelfHash(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	if out, err := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	alias := filepath.Join(dir, "proc-alias")
	if err := os.Symlink("/proc/self/status", alias); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	if out, err := exec.Command(collector, "-o", output, "/bin/cat", "/proc/self/status", alias).CombinedOutput(); err != nil {
		t.Fatalf("collect: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("lost %d events", result.Lost)
	}
	want := map[string]string{
		"/proc/self/status": "hash unavailable: proc self path refers to the collector when read later",
		alias:               "hash unavailable: procfs contents depend on process or runtime state",
	}
	for _, rec := range result.Records {
		if note, ok := want[rec.Path]; ok && rec.Event == "open_attempt" {
			if rec.Success == nil || !*rec.Success || rec.MD5 != "" || rec.Note != note {
				t.Fatalf("unexpected procfs record: %+v", rec)
			}
			delete(want, rec.Path)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing procfs open records %v: %s", want, data)
	}
}

func TestOpenat2(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "openat2")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/openat2"}} {
		if out, err := exec.Command("go", "build", "-o", item.output, item.pkg).CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	existing, missing := filepath.Join(dir, "existing"), filepath.Join(dir, "missing")
	if err := os.WriteFile(existing, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	if out, err := exec.Command(collector, "-o", output, target, existing, missing).CombinedOutput(); err != nil {
		t.Fatalf("collect: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("lost %d events", result.Lost)
	}
	found := make(map[string]bool)
	for _, rec := range result.Records {
		if rec.Event != "open_attempt" || (rec.Path != existing && rec.Path != missing) {
			continue
		}
		if rec.Success == nil || rec.DirFD == nil || *rec.DirFD != unix.AT_FDCWD {
			t.Fatalf("invalid openat2 record: %+v", rec)
		}
		if rec.Path == existing && (!*rec.Success || rec.MD5 != "5d41402abc4b2a76b9719d911017c592") {
			t.Fatalf("unexpected successful openat2: %+v", rec)
		}
		if rec.Path == missing && (*rec.Success || rec.OpenError != unix.ENOENT.Error() || rec.MD5 != "") {
			t.Fatalf("unexpected failed openat2: %+v", rec)
		}
		found[rec.Path] = true
	}
	if !found[existing] || !found[missing] {
		t.Fatalf("missing openat2 records: %s", data)
	}
}

func TestWriteEvents(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "writefile")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/writefile"}} {
		if out, err := exec.Command("go", "build", "-o", item.output, item.pkg).CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	path, output := filepath.Join(dir, "file"), filepath.Join(dir, "result.json")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(collector, "-o", output, target, path).CombinedOutput(); err != nil {
		t.Fatalf("collect: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("lost %d events", result.Lost)
	}
	found := make(map[string]bool)
	failed := false
	for _, rec := range result.Records {
		if rec.Event != "write_attempt" && rec.Event != "pwrite_attempt" && rec.Event != "writev_attempt" && rec.Event != "pwritev_attempt" && rec.Event != "pwritev2_attempt" {
			continue
		}
		if rec.FD != nil && *rec.FD == -1 && rec.Event == "write_attempt" {
			failed = rec.Success != nil && !*rec.Success && rec.WriteError == unix.EBADF.Error() && rec.BytesWritten == nil
		}
		if rec.ResolvedPath == path && rec.Success != nil && *rec.Success && rec.BytesWritten != nil && *rec.BytesWritten == 5 && rec.BytesRead == nil {
			found[rec.Event] = true
		}
	}
	if !found["write_attempt"] || !found["pwrite_attempt"] || !found["writev_attempt"] || !found["pwritev_attempt"] || !found["pwritev2_attempt"] || !failed {
		t.Fatalf("missing write results: found=%v failed=%v records=%s", found, failed, data)
	}
}

// TestChildProcess requires a privileged Linux host capable of loading BPF programs.
func TestChildProcess(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("child test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	// The shell opens target itself, then waits for cat to open it as a child.
	command := exec.Command(binary, "-o", output, "/bin/sh", "-c", `: < "$1"; /bin/cat "$1" >/dev/null; :`, "sh", target)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	pids := make(map[uint32]bool)
	for _, record := range result.Records {
		if record.Path == target {
			pids[record.PID] = true
		}
	}
	if len(pids) < 2 {
		t.Fatalf("expected parent and child to open %s, got PIDs %v; records: %s", target, pids, data)
	}
}

func TestInvalidPath(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	target := filepath.Join(dir, "badpath")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/badpath"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	for _, record := range result.Records {
		if record.Note == "path unavailable: bad address" && record.Path == "" && record.Success != nil && !*record.Success && record.OpenError == "bad address" {
			return
		}
	}
	t.Fatalf("missing bad-address record: %s", data)
}

func TestDirectoryFDPath(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	target := filepath.Join(dir, "dirfd")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/dirfd"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	filename := filepath.Join(dir, "target")
	if err := os.WriteFile(filename, []byte("dirfd test"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target, dir)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	for _, record := range result.Records {
		if record.Path == "target" && record.DirFD != nil && *record.DirFD >= 0 && record.ResolvedPath == filename && record.MD5 == "" && record.Note != "" && record.Success != nil && *record.Success {
			return
		}
	}
	t.Fatalf("missing directory-fd relative path record: %s", data)
}

func TestInheritedRead(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "reader")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/readstdin"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target)
	command.Stdin = file
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	found := make(map[string]bool)
	for _, record := range result.Records {
		if record.Event == "mmap_attempt" && record.FD != nil && *record.FD == 0 && record.ResolvedPath == input && record.Success != nil && *record.Success && record.Note != "" {
			found[record.Event] = true
		}
		if record.FD != nil && *record.FD == 0 && record.ResolvedPath == input && record.Success != nil && *record.Success && record.BytesRead != nil && *record.BytesRead == 5 && record.Note != "" {
			found[record.Event] = true
		}
	}
	for _, event := range []string{"read_attempt", "pread_attempt", "readv_attempt", "preadv_attempt", "preadv2_attempt", "mmap_attempt"} {
		if !found[event] {
			t.Fatalf("missing %s record: %s", event, data)
		}
	}
}

// TestCompareIchno compares independent runs; PIDs and timestamps are expected to differ.
func TestCompareIchno(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	ichno := os.Getenv("ICHNO_BIN")
	if ichno == "" {
		t.Skip("set ICHNO_BIN to an ichno executable")
	}
	if !filepath.IsAbs(ichno) {
		t.Fatal("ICHNO_BIN must be an absolute path")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	parent := filepath.Join(dir, "parent.txt")
	child := filepath.Join(dir, "child.txt")
	for _, path := range []string{parent, child} {
		if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := `: < "$1"; /bin/sh -c 'sleep 0.1; : < "$1"; sleep 0.2' sh "$2"; sleep 0.1`
	type legacyRecord struct {
		Path      string    `json:"path"`
		MD5       string    `json:"md5"`
		PID       int       `json:"pid"`
		TID       int       `json:"tid"`
		Timestamp time.Time `json:"timestamp"`
	}
	type observation struct {
		pid, tid  int
		hash      string
		timestamp time.Time
		event     string
	}
	for _, tool := range []struct{ name, binary string }{{"ichno", ichno}, {"ichnograph", collector}} {
		output := filepath.Join(dir, tool.name+".json")
		command := exec.Command(tool.binary, "-o", output, "/bin/sh", "-c", script, "sh", parent, child)
		if out, err := command.CombinedOutput(); err != nil {
			t.Errorf("%s run: %v\n%s", tool.name, err, out)
			continue
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Error(err)
			continue
		}
		observations := make(map[string][]observation)
		if tool.name == "ichno" {
			var records []legacyRecord
			if err := json.Unmarshal(data, &records); err != nil {
				t.Error(err)
				continue
			}
			for _, r := range records {
				if r.Path == parent || r.Path == child {
					observations[r.Path] = append(observations[r.Path], observation{r.PID, r.TID, r.MD5, r.Timestamp, "not provided"})
				}
			}
		} else {
			var result Result
			if err := json.Unmarshal(data, &result); err != nil {
				t.Error(err)
				continue
			}
			if result.Lost != 0 {
				t.Errorf("ichnograph reports %d lost events", result.Lost)
			}
			for _, r := range result.Records {
				if (r.Path == parent || r.Path == child) && r.Success != nil && *r.Success {
					observations[r.Path] = append(observations[r.Path], observation{int(r.PID), int(r.TID), r.MD5, r.Timestamp, r.Event})
				}
			}
		}
		var pids [2]int
		for index, path := range []string{parent, child} {
			matches := observations[path]
			t.Logf("%s %s: %d observations", tool.name, filepath.Base(path), len(matches))
			valid := false
			for _, r := range matches {
				if r.pid > 0 && r.tid > 0 && !r.timestamp.IsZero() && r.hash == "5d41402abc4b2a76b9719d911017c592" {
					valid = true
					pids[index] = r.pid
					t.Logf("%s %s: pid=%d tid=%d md5=%s timestamp=%s event=%s", tool.name, filepath.Base(path), r.pid, r.tid, r.hash, r.timestamp.Format(time.RFC3339Nano), r.event)
					break
				}
			}
			if !valid {
				t.Errorf("%s: no complete matching record for %s; observations: %+v", tool.name, path, matches)
			}
		}
		if pids[0] != 0 && pids[0] == pids[1] {
			t.Errorf("%s: parent and child records have same PID %d", tool.name, pids[0])
		}
	}
}

func TestShortLivedChildren(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	const children = 20
	for i := 1; i <= children; i++ {
		path := filepath.Join(dir, fmt.Sprintf("input-%d", i))
		if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "result.json")
	script := `i=1; while [ "$i" -le 20 ]; do /bin/cat "$1/input-$i" >/dev/null || exit 1; i=$((i+1)); done`
	command := exec.Command(collector, "-o", output, "/bin/sh", "-c", script, "sh", dir)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	pids := make(map[uint32]bool)
	for i := 1; i <= children; i++ {
		path := filepath.Join(dir, fmt.Sprintf("input-%d", i))
		found := false
		for _, r := range result.Records {
			if r.Event == "open_attempt" && r.Path == path && r.Success != nil && *r.Success && r.PID > 0 && r.TID > 0 && !r.Timestamp.IsZero() && r.MD5 == "5d41402abc4b2a76b9719d911017c592" {
				found = true
				pids[r.PID] = true
				break
			}
		}
		if !found {
			t.Errorf("missing complete successful open record for %s", path)
		}
	}
	if len(pids) != children {
		t.Errorf("expected %d distinct child PIDs, got %d", children, len(pids))
	}
}

func TestThreads(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "threads")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/threads"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	files := []string{filepath.Join(dir, "first"), filepath.Join(dir, "second")}
	for _, path := range files {
		if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target, files[0], files[1])
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	var records [2]Record
	for i, path := range files {
		for _, r := range result.Records {
			if r.Event == "open_attempt" && r.Path == path && r.Success != nil && *r.Success {
				records[i] = r
				break
			}
		}
		if records[i].PID == 0 || records[i].TID == 0 {
			t.Fatalf("missing open record for %s: %s", path, data)
		}
	}
	if records[0].PID != records[1].PID || records[0].TID == records[1].TID {
		t.Fatalf("expected same PID and distinct TIDs, got %+v and %+v", records[0], records[1])
	}
}

func TestDescendantsAfterExit(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	script := `(/bin/sleep 0.2; /bin/cat "$1" >/dev/null) </dev/null >/dev/null 2>&1 & exit 0`
	command := exec.Command(collector, "-o", output, "/bin/sh", "-c", script, "sh", target)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 || result.DescendantsRemaining {
		t.Fatalf("unexpected collection status: lost=%d remaining=%v", result.Lost, result.DescendantsRemaining)
	}
	for _, r := range result.Records {
		if r.Path == target && r.Event == "open_attempt" && r.Success != nil && *r.Success {
			return
		}
	}
	t.Fatalf("missing delayed descendant open: %s", data)
}

func TestDescendantWaitTimeout(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, "/bin/sh", "-c", `(/bin/sleep 3) </dev/null >/dev/null 2>&1 & exit 0`)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.DescendantsRemaining {
		t.Fatalf("expected remaining descendant to be reported: %s", data)
	}
}

func TestCommandExitStatus(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	notExecutable := filepath.Join(dir, "no-execute")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"nonzero", []string{"/bin/sh", "-c", "exit 7"}, 7},
		{"signal", []string{"/bin/sh", "-c", "kill -TERM $$"}, 143},
		{"missing", []string{filepath.Join(dir, "missing-command")}, 127},
		{"permission", []string{notExecutable}, 126},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(dir, tc.name+".json")
			args := append([]string{"-o", output}, tc.args...)
			command := exec.Command(collector, args...)
			out, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != tc.want {
				t.Fatalf("got exit %v, want %d; output: %s", err, tc.want, out)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatalf("missing result: %v; output: %s", err, out)
			}
			var result Result
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("invalid result: %v", err)
			}
			if result.Lost != 0 {
				t.Fatalf("collection lost %d events", result.Lost)
			}
		})
	}
}

func TestLegacyOpen(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture requires Linux amd64 legacy syscalls")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "legacyopen")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/legacyopen"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	existing, created := filepath.Join(dir, "existing"), filepath.Join(dir, "created")
	if err := os.WriteFile(existing, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target, existing, created)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	for _, path := range []string{existing, created} {
		found := false
		for _, record := range result.Records {
			if record.Event == "open_attempt" && record.Path == path && record.Success != nil && *record.Success {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing successful open for %s", path)
		}
	}
}

func TestExecutableEvents(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector := filepath.Join(dir, "ichnograph")
	build := exec.Command("go", "build", "-o", collector, "../../cmd/ichnograph")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, "/bin/sh", "-c", `/bin/true; :`)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	for _, path := range []string{"/bin/sh", "/bin/true"} {
		found := false
		for _, r := range result.Records {
			if r.Event == "exec_attempt" && r.Path == path && r.Success != nil && *r.Success && r.PID > 0 && r.TID > 0 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing successful execution for %s; records: %s", path, data)
		}
	}
}

func TestExecveat(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture requires Linux amd64")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "execveat")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/execveat"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	missing := filepath.Join(dir, "missing")
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target, missing)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	var failed, succeeded bool
	for _, r := range result.Records {
		if r.Event != "exec_attempt" || r.Success == nil {
			continue
		}
		if r.Path == missing && !*r.Success && r.ExecError == unix.ENOENT.Error() {
			failed = true
		}
		if r.Path == "/bin/true" && *r.Success {
			succeeded = true
		}
	}
	if !failed || !succeeded {
		t.Fatalf("execveat results: failed=%v succeeded=%v; records: %s", failed, succeeded, data)
	}
}

func TestExecveatEmptyPath(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture requires Linux amd64")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "execveatfd")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/execveatfd"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n/bin/sleep 0.5\n"), 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target, script)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	for _, r := range result.Records {
		if r.Event == "exec_attempt" && r.Path == "" && r.ResolvedPath == script && r.DirFD != nil && *r.DirFD >= 0 && r.Success != nil && *r.Success && r.MD5 == "" && r.Note != "" {
			return
		}
	}
	t.Fatalf("missing descriptor-based execveat observation: %s", data)
}

func TestNonLeaderExec(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	collector, target := filepath.Join(dir, "ichnograph"), filepath.Join(dir, "threadexec")
	for _, item := range []struct{ output, pkg string }{{collector, "../../cmd/ichnograph"}, {target, "./testdata/threadexec"}} {
		command := exec.Command("go", "build", "-o", item.output, item.pkg)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", item.pkg, err, out)
		}
	}
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "result.json")
	command := exec.Command(collector, "-o", output, target, input)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Lost != 0 {
		t.Fatalf("collection lost %d events", result.Lost)
	}
	if result.DescendantsRemaining {
		t.Fatal("tracking retained a stale task after non-leader exec")
	}
	var execution, file bool
	for _, r := range result.Records {
		if r.Event == "exec_attempt" && r.Path == "/bin/sh" && r.Success != nil && *r.Success {
			execution = true
		}
		if r.Event == "open_attempt" && r.Path == input && r.Success != nil && *r.Success {
			file = true
		}
	}
	if !execution || !file {
		t.Fatalf("non-leader exec: successful exec=%v, subsequent file=%v; records: %s", execution, file, data)
	}
}

func TestKernelRingBufferLoss(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	spec, err := bpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	spec.Maps["events"].MaxEntries = uint32(os.Getpagesize())
	coll, err := bpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load BPF: %v", err)
	}
	defer coll.Close()
	probe, err := link.Tracepoint("syscalls", "sys_enter_openat", coll.Programs["openat_event"], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid, one := uint32(unix.Gettid()), uint32(1)
	if err := coll.Maps["tracked"].Put(tid, one); err != nil {
		t.Fatal(err)
	}
	// Deliberately do not consume the one-page ring buffer while producing events.
	for i := 0; i < 1000; i++ {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
	}
	var key uint32
	var lost uint64
	if err := coll.Maps["lost"].Lookup(key, &lost); err != nil {
		t.Fatal(err)
	}
	if lost == 0 {
		t.Fatal("expected event loss after filling the ring buffer")
	}
	t.Logf("BPF reported %d lost events", lost)
}

func TestCollectorLoss(t *testing.T) {
	if os.Getenv("ICHNOGRAPH_BPF_TEST") != "1" {
		t.Skip("set ICHNOGRAPH_BPF_TEST=1 on a privileged Linux host")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "ichnograph")
	if out, err := exec.Command("go", "build", "-o", helper, "../../cmd/ichnograph").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	marker := filepath.Join(dir, "done")
	start := make(chan struct{})
	go func() {
		defer close(start)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(marker); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	result, code, err := run([]string{"/bin/sh", "-c", `i=0; while [ "$i" -lt 1000 ]; do : < /dev/null; i=$((i+1)); done; : > "$1"`, "sh", marker}, runOptions{ringSize: uint32(os.Getpagesize()), helper: helper, startReader: start})
	if err != nil || code != 0 {
		t.Fatalf("collect: code=%d err=%v", code, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("workload did not complete: %v", err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Lost == 0 || len(decoded.Records) == 0 {
		t.Fatalf("expected lost events and retained records: %s", data)
	}
	for _, record := range decoded.Records {
		if record.Success != nil || record.BytesRead != nil || record.BytesWritten != nil || record.OpenError != "" || record.ExecError != "" || record.ReadError != "" || record.WriteError != "" || record.MmapError != "" || record.MD5 != "" {
			t.Fatalf("uncertain result retained after loss: %+v", record)
		}
	}
	if !bytes.Contains(data, []byte("event loss makes entry/exit correlation unreliable")) {
		t.Fatalf("missing loss limitation: %s", data)
	}
	t.Logf("collector reported %d lost events and %d retained records", decoded.Lost, len(decoded.Records))
}
