# Architecture decisions: eBPF collector

[日本語](adr.ja.md)

## Tracepoint and BTF CO-RE architecture

**Status:** Accepted

The collector in `internal/ebpf` attaches to Linux kernel tracepoints across `sched` (`sched_process_fork`, `sched_process_exit`, `sched_process_exec`), `syscalls` (`sys_enter_*` and `sys_exit_*` for `open`, `creat`, `openat`, `openat2`, `execve`, `execveat`, `read`, `pread64`, `readv`, `preadv`, `preadv2`, `write`, `pwrite64`, `writev`, `pwritev`, `pwritev2`, `connect` and `mmap`) and `sock` (`inet_sock_set_state`).

Kernel data structures (`task_struct`, `files_struct`, `fdtable`, `file`, `inode`, `super_block` and `socket`) are read using BTF CO-RE (`__attribute__((preserve_access_index))`). The compiled BPF object (`program.o`) is embedded into the Go binary via `//go:embed` and loaded with `github.com/cilium/ebpf`, keeping runtime execution independent of external C toolchains while requiring BPF privileges at collection time.

## Helper-stop handshake for initial process tracking

**Status:** Accepted

Starting a target command directly and inserting its PID into the `tracked` BPF map from userspace races with the child process's initial execution. To prevent missed startup events, `internal/ebpf.Run` invokes the current executable with `--ichnograph-exec-helper` before running the target command.

The helper raises `SIGSTOP` on itself before calling `execve`. The collector waits for the helper to stop (`Wait4` with `WUNTRACED`), inserts the helper's TID into the `tracked` BPF map while probes are already attached, starts the ring buffer reader, and then resumes the helper with `SIGCONT`.

## Two-size ring buffer events and cooperative deduplication

**Status:** Accepted

To reduce ring buffer bandwidth under realistic workloads, the BPF program emits two fixed event sizes:

- **288-byte events (`struct event`)**: Used for path-bearing or sockaddr-bearing operations (`open` family, `exec` family, `connect`, `mmap` and `exec_transition`), carrying a 256-byte buffer.
- **64-byte events (`struct fd_event`)**: Used for descriptor-only operations (`read` family, `write` exit, pipe/FIFO observations, `connect` exit and TCP state transitions), omitting the path buffer and carrying a 32-byte `read_identity` struct (`ino`, `process_start`, `dev`, `pid`, `generation`).

Noise suppression and deduplication are split between kernel and userspace:

- **Kernel-side device and stdio filtering**: `ignored_io` inspects the descriptor's inode mode and device numbers via CO-RE to drop reads and writes on `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, virtual terminals, serial TTYs, console, PTYs and pipe-backed standard descriptors `0`, `1` and `2` before ring buffer reservation.
- **Write exit filtering**: `handle_write` records pending writes in `write_pending` on syscall entry and emits a single `write_observed` event on syscall exit only when `ret > 0`, avoiding ring buffer traffic for failed or zero-byte writes.
- **Cooperative regular-file deduplication**: Suppressing subsequent regular-file reads or writes in the kernel before userspace has resolved a path would leave the file unidentified if the first `/proc` lookup fails. Therefore, the BPF program rate-limits unresolved retries to one per 100 ms per `read_identity` (`read_retry` and `write_retry` maps), and userspace inserts the `read_identity` into `read_seen` or `write_seen` only after a nonzero read or write achieves a resolved path (and, for reads, unambiguous entry/exit correlation).

## Nonblocking TCP correlation via opaque tokens

**Status:** Accepted

Nonblocking TCP `connect` calls commonly return `-EINPROGRESS` or `-EALREADY` on syscall exit and complete asynchronously. On `sys_enter_connect` for IPv4/IPv6 stream sockets, the BPF program reads `struct socket -> sk` via CO-RE and stores a mapping from the kernel `sk` pointer to a per-attempt token (`ktime_get_ns()`) in `tcp_connects` (and `tcp_entered` for exit cleanup if the syscall fails immediately with another error).

When `sock/inet_sock_set_state` observes a TCP transition from `TCP_SYN_SENT` to `TCP_ESTABLISHED` or `TCP_CLOSE`, it looks up `sk` in `tcp_connects` and emits a `tcp_connect_outcome` event carrying only the opaque token (`connection_id`), avoiding exposing raw kernel pointers to userspace.

## Post-event path resolution and safe file hashing

**Status:** Accepted

Resolving full filesystem paths or computing file hashes inside eBPF is constrained by BPF verifier limits and cannot read arbitrary file contents. Path resolution and hashing are performed in Go userspace with explicit safety guards:

- **Relative and descriptor paths**: Userspace reads `/proc/<pid>/task/<tid>/cwd` and `/proc/<pid>/task/<tid>/fd/<fd>`. Relative paths containing `..` are rejected because joining them in userspace after the fact can misresolve across symbolic links. When `/proc` descriptor lookup fails (for example, after the descriptor is closed), userspace falls back to the path recorded by an earlier successful `open` on the same `(pid, fd)` only if `stat` confirms that the candidate path is still a regular file with matching `(dev, ino)`.
- **Safe MD5 calculation**: Opening observed paths directly with `O_RDONLY` after collection could block on FIFOs, trigger device side effects, or read collector-specific `/proc/self` files. `hashFile` first opens the path with `O_PATH|O_CLOEXEC`, verifies via `fstat` and `fstatfs` that the target is a regular file and not on `procfs` (`PROC_SUPER_MAGIC`), and then reopens the verified inode via `/proc/self/fd/<fd>` with `O_RDONLY|O_NONBLOCK|O_CLOEXEC` to compute the MD5 digest.

## Conservative invalidation on event loss and correlation ambiguity

**Status:** Accepted

Because syscall entry and exit events are correlated per `tid` in userspace, any lost ring buffer event or dropped tracking/pending map update can cause an entry event to be paired with the exit of a different syscall (including after TID reuse).

- The BPF program counts drops in the `lost` array map both in total (index `0`) and by source (`ring_buffer`, `tracked_map`, `retry_paths_map`, `mmap_pending_map`, `write_pending_map`, `tcp_tracking_map`).
- When `lost > 0`, `invalidateOnLoss` clears `Success`, all `*Error` fields, `BytesRead`, `BytesWritten`, and any `Path` or `ResolvedPath` derived from exit-time path retry or `open` descriptor correlation across all records.
- Independently of counter-reported loss, if userspace observes overlapping entry events or mismatched event kinds on a `tid`, it marks that `tid` as `uncertain`, stops correlating further entry/exit pairs for that thread, and adds a limitation to the result.
