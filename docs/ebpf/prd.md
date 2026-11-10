# Product requirements: eBPF collector

[日本語](prd.ja.md)

## Purpose

The `internal/ebpf` collector runs a target command on Linux and captures runtime evidence of file accesses, program execution, descriptor use, pipe/FIFO activity and network connection attempts using eBPF. It produces structured records and completeness metadata for downstream dependency analysis as part of the overall [ichnograph product requirements](../prd.md).

## Process lifecycle and tracking

- Start tracking before the target command executes so initial dynamic linker and startup accesses are captured.
- Track child processes and threads across `fork`, `exec` transitions (including thread-group leader PID changes) and thread exit.
- Return the target command's exit code (including `128 + signal` when terminated by a signal).
- After the root command exits, wait up to 1 second for remaining tracked descendant threads to finish. If tracked descendants remain after the timeout, set `descendants_remaining` to `true` and record a limitation noting that later descendant activity is not captured.

## Observed operations and event granularity

Record observations with `pid`, `tid`, `timestamp`, `event`, operation outcome (`success` and operation-specific error fields where available) and relevant path, descriptor or network fields:

- **File open attempts (`open_attempt`)**: Monitor `open`, `creat`, `openat` and `openat2`. Record the supplied `path`, `dirfd`, `success` and `open_error` on failure. If reading the user-space pathname fails on syscall entry, retry reading the pathname on syscall exit and note that the path was read after the syscall.
- **Execution attempts (`exec_attempt`)**: Monitor `execve` and `execveat`. Record `path`, `dirfd`, `success` and `exec_error` on failure. When `execveat` uses an empty pathname, attempt to resolve the target from `dirfd` and note that flags are not recorded.
- **File-backed memory mappings (`mmap_attempt`)**: Monitor `mmap` calls that do not set `MAP_ANONYMOUS`. Record `fd`, resolved descriptor path when obtainable, `success` and `mmap_error` on failure.
- **Descriptor reads (`read_attempt`, `pread_attempt`, `readv_attempt`, `preadv_attempt`, `preadv2_attempt`)**: Monitor `read`, `pread64`, `readv`, `preadv` and `preadv2`. Record `fd`, `bytes_read` on success or `read_error` on failure, and resolved path information.
- **Descriptor writes (`write_observed`, `write_attempt`, `pwrite_attempt`, `writev_attempt`, `pwritev_attempt`, `pwritev2_attempt`)**: Monitor `write`, `pwrite64`, `writev`, `pwritev` and `pwritev2`. Emit `write_observed` records only when a monitored call writes at least one byte (`bytes_written > 0`); omit zero-byte and failed writes to bound event volume.
- **Pipe and FIFO use (`pipe_use_attempt`, `fifo_use_attempt`)**: When a monitored read or write targets a FIFO or pipe descriptor, record one observation per process, descriptor kind (pipe vs. FIFO) and direction (`read` or `write`), noting that individual pipe identity and syscall result are not recorded.
- **Network connections (`connect_attempt`, `tcp_connect_outcome`)**: Monitor `connect` and record `fd`, `network` (`family` for `ipv4`, `ipv6`, `unix` or raw family number, `address` and `port` for IPv4/IPv6, and `socket_type` when obtainable), `success` and `connect_error`. When a stream IPv4/IPv6 connect returns `EINPROGRESS` or `EALREADY`, leave `success` unset, attach a `connection_id`, and emit a matching `tcp_connect_outcome` record (`established` or `closed_before_established`) if the socket transitions from `TCP_SYN_SENT` to `TCP_ESTABLISHED` or `TCP_CLOSE`.

## Noise suppression, deduplication and aggregation

To support realistic workloads while bounding ring buffer traffic:

- Omit read and write events on `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, Linux virtual terminals, serial TTYs, controlling TTY, console and PTYs, as well as standard descriptors `0`, `1` and `2` when they are pipes.
- For regular files, once a nonzero read or write in a process has a resolved path in userspace, suppress subsequent reads (`read_seen`) or writes (`write_seen`) of the same file identity (`dev`, `ino`, `generation`, `pid`, `process_start`). Before path resolution succeeds, rate-limit retries for the same file identity to at most one per 100 ms.
- After collection, aggregate repeated IPv4 `connect_attempt` records that do not use asynchronous TCP state tracking (`connection_id == 0`) when they share `pid`, `tid`, `fd`, `address`, `port`, `socket_type`, immediate outcome, `connect_error` and `note`, recording the count in `occurrences` and keeping the first timestamp.

## Path resolution and file hashing

- **Relative paths**: For relative `open` or `exec` paths that do not contain `..`, resolve `resolved_path` against `/proc/<pid>/task/<tid>/cwd` (for `AT_FDCWD`) or `/proc/<pid>/task/<tid>/fd/<dirfd>`, and note that resolution uses later process state. Leave paths containing `..` unresolved to avoid symbolic-link traversal inaccuracies.
- **Descriptor paths**: For descriptor-based events (`read`, `write`, `mmap`, empty-path `execveat`), resolve `resolved_path` via `/proc/<pid>/task/<tid>/fd/<fd>` when it yields an available absolute path (excluding `(deleted)` targets). If `/proc` resolution fails, fall back to the path recorded by an earlier successful `open` on the same `(pid, fd)` only when the file's current `(dev, ino)` still matches the regular-file identity captured at the event.
- **MD5 hashing**: After collection, compute `md5` for records with `success == true`, no prior `note`, and an absolute `path`. Skip `/proc/self`, `/proc/thread-self`, non-regular files and `procfs` files, recording an explanatory `note` when a hash cannot be computed.

## Completeness, loss reporting and boundaries

- Report total lost events in `lost` and provide a per-source breakdown in `loss_breakdown` covering `ring_buffer`, `tracked_map`, `retry_paths_map`, `mmap_pending_map`, `write_pending_map` and `tcp_tracking_map`.
- If any event loss occurs (`lost > 0`), clear `success`, error fields, `bytes_read`, `bytes_written`, and paths inferred from `open` correlation or exit retries across all records so that mismatched entry/exit pairs cannot produce false results.
- If overlapping or mismatched entry/exit events occur on a thread (`tid`), disable subsequent entry/exit correlation for that thread and record a limitation.
- Populate `limitations` and per-record `note` fields with the collector's coverage boundaries, deduplication rules, timing caveats and any loss or correlation conditions encountered during the run.
