# Architecture decisions: trace subcommand

[日本語](adr.ja.md)

## Subcommand dispatch and internal helper handshake

**Status:** Accepted

Place runtime trace collection under the `ichnograph trace` subcommand in `cmd/ichnograph` rather than accepting a target command directly at the root CLI. Because `trace` takes arbitrary positional arguments (`command [args...]`) and requires elevated privileges to load eBPF programs, isolating it in a dedicated subcommand prevents positional-argument ambiguity and keeps privileged collection separate from unprivileged post-processing subcommands (such as runtime normalization and external metadata merging; see the root [architecture decisions](../adr.md)).

Before parsing subcommands or flags, `cmd/ichnograph` intercepts the internal `--ichnograph-exec-helper` argument at startup. This preserves the helper-stop handshake required by `internal/ebpf.Run` (documented in the [eBPF architecture decisions](../ebpf/adr.md)) without coupling `internal/ebpf` to the CLI subcommand structure.

## Collector delegation and post-collection filtering

**Status:** Accepted

`ichnograph trace` parses its own flag set (`-o` and `-include-logs`) and invokes `internal/ebpf.Run` with the remaining positional arguments. Keep kernel probe management, event correlation, path resolution and file hashing inside `internal/ebpf`, and keep CLI-level concerns in `cmd/ichnograph`:

- Apply the default `/var/log` and `.log` record exclusion in userspace after `internal/ebpf.Run` returns unless `-include-logs` is set, and append the corresponding limitation note to the result.
- Marshal the resulting `ebpf.Result` as indented JSON with a trailing newline, write it to the `-o` path, and exit the process with the exit code returned by `internal/ebpf.Run`.
