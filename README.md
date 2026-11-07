# ichnograph

Ichnograph helps investigate what a product feature depends on and what might affect it in its execution environment. It aims to connect runtime observations with information about code, libraries, packages, and services in a dependency graph, supporting investigations such as the impact of component updates.

The name combines **ichno** and **graph**. The root *ichno* appears in words such as ichnofossil, ichnite, and ichnology. The name reflects the goal of bringing together different kinds of information and their relationships.

The project is in its early stages. The first milestone is to collect file-access information using eBPF on Linux while running a command. See the [product requirements](docs/prd.md) and [architecture decisions](docs/adr.md) for details.

## Experimental file-open collector

On Linux, build with `go build -o ichnograph ./cmd/ichnograph`, then run with the privileges needed to load BPF programs and attach tracepoints:

```sh
sudo ./ichnograph -o result.json /path/to/command arg
```

After writing the result, ichnograph returns the command’s exit status; for termination by signal it returns 128 plus the signal number. A command that cannot be found returns 127; a command that cannot be executed returns 126.

The JSON contains execve, execveat, open, creat, openat, openat2, read, write, pwrite64, writev, pwritev, pwritev2 and file-backed mmap attempts, a count of known lost events or tracking failures, and collection limitations. Each record includes whether the operation succeeded and, for failures, the error; successful reads include the byte count. Reads and writes may involve non-file descriptors. Successful writes include the byte count; this records the syscall result, not durable storage. Success is null when the exit event is unavailable or known event loss makes correlation unreliable. Read, pread64, readv, preadv and preadv2 are recorded; other read methods are not covered. File-backed mmap attempts are recorded, but a mapping does not establish that mapped bytes were read. Successful exec is recorded using the scheduler exec tracepoint. Exec from a non-leader thread can change TID; tracking follows this transition using the same tracepoint. For execveat with an empty path, the descriptor path is a later approximation and flags are not recorded. Descriptor paths are approximations based on later process state and can be unavailable or inaccurate. When a path cannot be read at syscall entry, the collector retries at exit; a recovered path is marked as a later observation and is not hashed. Remaining path-reading failures include the kernel error in the record. Relative paths are preserved and, when possible, an approximate absolute path is added using a later snapshot of process state; it may be inaccurate or unavailable and is not hashed. Successful executions and opens of absolute paths are hashed after collection when they refer to readable regular files. Procfs files are not hashed, including through symlinks or alternate mounts, because their contents can depend on process or runtime state. Explicit `/proc/self` and `/proc/thread-self` paths are also skipped before opening because they would refer to the collector. Each absolute path is hashed once per run and the result is reused for its records; it reflects the file at hashing time, not necessarily at each access. The collector checks the file type before opening it for reading and uses procfs to reopen the inspected file with nonblocking mode. This does not bound the time needed to read regular or pseudo-files. After the root command exits, collection continues until tracked descendants exit, for up to one second. If any remain at the deadline, `descendants_remaining` is true and later activity is not captured. The embedded BPF object currently targets little-endian Linux and requires kernel BPF ring buffers and all the monitored syscall tracepoints, including `open`, `creat` and `openat2`; architectures without those tracepoints cannot currently run it. Load and attachment failures are reported rather than producing a complete-looking result.

To rebuild the embedded object after changing its source, install Clang with the BPF target and Linux headers, then run on a little-endian machine:

```sh
clang-18 -O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine) -c internal/ebpf/program.c -o internal/ebpf/program.o
```

To verify parent and child process tracking on a host with BPF privileges, run:

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestChildProcess|TestInvalidPath|TestDirectoryFDPath|TestInheritedRead|TestShortLivedChildren|TestThreads|TestDescendantsAfterExit|TestDescendantWaitTimeout|TestCommandExitStatus|TestLegacyOpen|TestExecutableEvents|TestExecveat|TestExecveatEmptyPath|TestNonLeaderExec|TestKernelRingBufferLoss|TestCollectorLoss|TestLongPath|TestMissingFile|TestOpenat2|TestWriteEvents|TestProcSelfHash)$' -count=1 -v
```

The tests check that a shell and its child both generate records for the same file, that an invalid path address is reported, that a relative path can be resolved from an open directory descriptor, and that read, pread64, readv, preadv, preadv2 and file-backed mmap through inherited standard input are recorded. They also check file opens from 20 short-lived child processes and distinct threads within one process, delayed descendants, the descendant wait timeout, execveat success and failure, and loss reporting when a BPF ring buffer fills. They are skipped during ordinary unprivileged tests.

To compare with an existing ichno executable, provide its absolute path on a host with the privileges required by both collectors:

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 ICHNO_BIN=/absolute/path/to/ichno go test ./internal/ebpf -run '^TestCompareIchno$' -count=1 -v
```

The test runs each collector separately against a shell and a child process that remains alive briefly after opening its file. It compares records for known files by path, PID, TID, timestamp and MD5; actual PIDs and timestamps differ between runs. It also reports the available event type, which ichno does not output.

To check non-leader-thread exec tracking on a privileged host, run:

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestNonLeaderExec$' -count=1 -v
```

This test checks for a successful exec record and a subsequent file open.

`TestCollectorLoss` deliberately delays ring-buffer consumption to verify that real event loss invalidates correlated results and is reported in JSON.

`TestLongPath` checks that a successfully opened path exceeding the capture buffer is marked as possibly truncated and is not hashed.

`TestMissingFile` checks the failed open result and command exit status for a nonexistent file.

`TestOpenat2` checks successful and failed direct openat2 calls and their reported results.

If entry events overlap on a thread or an exit does not match its pending entry, affected results and subsequent results for that TID remain unknown for the rest of the run, including if the TID is reused. The result reports this limitation.

`TestWriteEvents` checks successful write, pwrite64, writev, pwritev and pwritev2 operations and a failed write. Other write methods, including memory-mapped writes, are not covered.

`TestProcSelfHash` checks that successful opens of `/proc/self/status` and a symlink to it are recorded without misleading post-run hashes.
