# ichnograph

[日本語](README.ja.md)

Ichnograph helps investigate what a product feature depends on and what might affect it in its execution environment. It aims to connect runtime observations with information about code, libraries, packages, and services in a dependency graph, supporting investigations such as the impact of component updates.

The name combines **ichno** and **graph**. The root *ichno* appears in words such as ichnofossil, ichnite, and ichnology. The name reflects the goal of bringing together different kinds of information and their relationships.

The project is in its early stages. The first milestone is to collect file-access information using eBPF on Linux while running a command. See the [product requirements](docs/prd.md) and [architecture decisions](docs/adr.md) for details.

## Experimental file-open collector

On Linux, build with `go build -o ichnograph ./cmd/ichnograph`, then run with the privileges needed to load BPF programs and attach tracepoints:

```sh
sudo ./ichnograph -o result.json /path/to/command arg
```

By default, output excludes records whose captured or resolved path is under `/var/log` or ends in `.log`. Use `-include-logs` before the command to include them, for example `sudo ./ichnograph -include-logs -o result.json /path/to/command`. Unresolved or inaccurate paths may evade or incorrectly trigger the filter. The filter runs after collection and hashing, so it does not reduce event traffic or loss; rotated names such as `.log.1` are not matched by the suffix rule.

After writing the result, ichnograph returns the command’s exit status; for termination by signal it returns 128 plus the signal number. A command that cannot be found returns 127; a command that cannot be executed returns 126.

After a successful nonzero read of a regular file whose path was resolved, later reads of the same device, inode and available inode generation by the same process are suppressed. Process start time distinguishes reused process IDs; if it is unavailable, reads are not suppressed. After a successful nonzero read whose path is unavailable, subsequent reads can retry path resolution at most once per 100 milliseconds per process and file. Failed and zero-byte reads do not start this interval. Short-lived reads within that interval can be missed; when procfs resolution fails, an earlier open path may be used if a later device and inode check matches. That inference and other resolved paths may still be stale; inode reuse on filesystems without distinguishing generation numbers and concurrent descriptor changes can hide later accesses. If the bounded tracking maps cannot record an identity, subsequent reads are recorded normally. Other descriptor types are not deduplicated.

`fifo_use_attempt` and `pipe_use_attempt` record that a process attempted a read or write on a named FIFO or anonymous pipe. The first attempt per process, kind and direction is recorded when tracking is available, including on standard descriptors. The records do not identify individual pipes, their other process, paths, contents or operation results. Classification and deduplication depend on kernel state, and missing identity or full maps can produce repeated records.

Repeated IPv4 connect records with the same PID, TID, fd, destination, socket type and immediate result are combined after collection. `occurrences` is the number of attempts when more than one is combined; when absent the record represents one attempt. The timestamp is the first observation. PID, TID or fd reuse can combine distinct attempts; IPv6, Unix sockets and connections with TCP state tracking are not aggregated. This output aggregation does not reduce ring-buffer traffic or loss.

`connect_attempt` records the process, descriptor and supplied IPv4 or IPv6 address and port. It includes the immediate syscall result and, when available, the socket type (stream, datagram or seqpacket). For TCP, `tcp_connect_outcome` records an observed transition from SYN_SENT to established or closed before establishment, linked to the attempt by `connection_id`, PID and TID. Closed before establishment can mean cancellation or failure. Without a matching transition the final outcome remains unknown; transitions may precede the syscall return. Socket type does not establish TCP versus UDP; IPv6 scope ID, Unix socket addresses, other network operations, payloads and library attribution are not recorded.

Read and write events on /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom and Linux virtual terminals, serial ttys, controlling tty, console and PTYs are suppressed regardless of descriptor number. Detailed read/write records on standard descriptors 0, 1 and 2 are also suppressed when they are pipes; regular files and unrecognized terminal devices remain observed. Classification can race with descriptor changes in another thread. This requires kernel BTF.

The `loss_breakdown` object separates ring buffer reservation failures from failures updating the tracked, retry paths, mmap pending, write pending and TCP tracking maps. Its counters are read separately and may not sum to `lost` while tracked processes remain active.

The JSON contains execve, execveat, open, creat, openat, openat2, read and file-backed mmap attempts, successful nonzero writes, a count of known lost events or tracking failures, and collection limitations. Read, open, exec and mmap records include the outcome when available; successful reads include the byte count. A write_observed record indicates that write, pwrite64, writev, pwritev or pwritev2 wrote at least one byte; failed and zero-byte writes, byte counts and syscall variants are omitted. For regular files, repeated writes are suppressed per process and file after path resolution; until then, attempts to record another successful write are limited to one per 100 milliseconds after a successful write. Short-lived writes may be missed when the path is unresolved. File identity reuse and concurrent descriptor changes can also hide or misattribute writes. Other descriptor types are not deduplicated. Reads and writes may involve non-file descriptors, and successful writes do not prove durable storage. Success is null when the exit event is unavailable or known event loss makes correlation unreliable. Read, pread64, readv, preadv and preadv2 are recorded; other read methods are not covered. File-backed mmap attempts are recorded, but a mapping does not establish that mapped bytes were read. Successful exec is recorded using the scheduler exec tracepoint. Exec from a non-leader thread can change TID; tracking follows this transition using the same tracepoint. For execveat with an empty path, the descriptor path is a later approximation and flags are not recorded. Descriptor paths are approximations based on later process state and can be unavailable or inaccurate. When a path cannot be read at syscall entry, the collector retries at exit; a recovered path is marked as a later observation and is not hashed. Remaining path-reading failures include the kernel error in the record. Relative paths are preserved and, when possible, an approximate absolute path is added using a later snapshot of process state; it may be inaccurate or unavailable and is not hashed. Successful executions and opens of absolute paths are hashed after collection when they refer to readable regular files. Procfs files are not hashed, including through symlinks or alternate mounts, because their contents can depend on process or runtime state. Explicit `/proc/self` and `/proc/thread-self` paths are also skipped before opening because they would refer to the collector. Each absolute path is hashed once per run and the result is reused for its records; it reflects the file at hashing time, not necessarily at each access. The collector checks the file type before opening it for reading and uses procfs to reopen the inspected file with nonblocking mode. This does not bound the time needed to read regular or pseudo-files. After the root command exits, collection continues until tracked descendants exit, for up to one second. If any remain at the deadline, `descendants_remaining` is true and later activity is not captured. The embedded BPF object currently targets little-endian Linux and requires kernel BPF ring buffers and all the monitored syscall tracepoints, including `open`, `creat`, `openat2` and `sock:inet_sock_set_state`; architectures without those tracepoints cannot currently run it. Load and attachment failures are reported rather than producing a complete-looking result.

To rebuild the embedded object after changing its source, install Clang with the BPF target and Linux headers, then run on a little-endian machine:

```sh
clang-18 -O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine) -c internal/ebpf/program.c -o internal/ebpf/program.o
```

To verify parent and child process tracking on a host with BPF privileges, run:

To check named FIFO and anonymous pipe observations, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestPipeKinds$' -count=1 -v` on a host with BPF access.

To check cancellation of an in-progress TCP connection and a connection using an inherited socket, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTCPConnectInheritedAndCancel$' -count=1 -v` on a host with BPF access.

To verify TCP outcome correlation across concurrent threads, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTCPConnectConcurrent$' -count=1 -v` on a host with BPF access.

To verify TCP outcome correlation when a descriptor is reused for 20 connections, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTCPConnectFDReuse$' -count=1 -v` on a host with BPF access.

To compare immediate connect results with nonblocking TCP completion observed by the target via poll and SO_ERROR, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestNonblockingConnectOutcome$' -count=1 -v`. The test checks the matching TCP state observations; a close before establishment does not by itself identify its cause.

To check Unix stream sockets, datagram sockets, connection errors and nonblocking connection results, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestConnectKinds$' -count=1 -v` on a host with BPF access.

To check special-device reads and loopback connect observations on a host with BPF access, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestSpecialDeviceReadSuppression|TestConnectObservation)$' -count=1 -v`.

To check terminal and selected pseudo-device suppression and that regular-file writes remain recorded, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^TestTerminalIOSuppression$' -count=1 -v` on a host with BPF and PTY access.

To check regular-file write deduplication and descriptor reuse, run `sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestWriteEvents|TestWriteDedupAndFDReuse)$' -count=1 -v` on a host with BPF access.

To check descriptor reuse, inherited file reads, cross-thread descriptor replacement, a failed read immediately followed by a successful read, and a short-lived file, run the following on a host with BPF and tracepoint access. `TestReadCoverage` reports open and resolved-read evidence for each case; a failed subtest identifies missing evidence, including known timing limitations.

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -run '^(TestReadCoverage|TestInheritedRead)$' -count=1 -v
```

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

## Running in Docker

Running `ichnograph` inside a container requires sharing the host PID namespace (`--pid=host` or `pid: "host"`), privileges to load eBPF programs and attach tracepoints, an unlimited or sufficiently high locked-memory limit (`RLIMIT_MEMLOCK`), and access to `tracefs` or `debugfs` (`/sys/kernel/tracing` or `/sys/kernel/debug`).

- If the container uses an isolated PID namespace instead of the host PID namespace, container PIDs do not match the host PIDs observed by eBPF, producing `"records": []` and `"descendants_remaining": true`.
- If container privileges or `RLIMIT_MEMLOCK` are insufficient, startup fails with `load eBPF programs (requires BPF privileges): map ...: map create: operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)`.
- If neither `tracefs` nor `debugfs` is mounted inside the container, tracepoint attachment fails with `attach sched_process_fork: neither debugfs nor tracefs are mounted` even when `privileged` is enabled.

With `docker run` using `--privileged`:

```sh
docker run --rm -it \
  --pid=host \
  --privileged \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  <image> ./ichnograph -o result.json /path/to/command arg
```

With `docker run` using explicit capabilities instead of `--privileged`:

```sh
docker run --rm -it \
  --pid=host \
  --cap-add=BPF \
  --cap-add=PERFMON \
  --cap-add=SYS_ADMIN \
  --cap-add=IPC_LOCK \
  --security-opt seccomp=unconfined \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  <image> ./ichnograph -o result.json /path/to/command arg
```

With Docker Compose (`compose.yaml`):

```yaml
services:
  app:
    pid: "host"
    privileged: true
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing:rw
      - /sys/kernel/debug:/sys/kernel/debug:rw
```

Or with explicit capabilities in `compose.yaml`:

```yaml
services:
  app:
    pid: "host"
    cap_add:
      - BPF
      - PERFMON
      - SYS_ADMIN
      - IPC_LOCK
    security_opt:
      - seccomp:unconfined
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing:rw
      - /sys/kernel/debug:/sys/kernel/debug:rw
```

If `/sys/kernel/tracing` is not mounted on the host (for example, in some VM-backed container environments), mount `tracefs` inside a privileged container before running `ichnograph`:

```sh
mount -t tracefs nodev /sys/kernel/tracing
```
