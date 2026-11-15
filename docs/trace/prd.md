# Product requirements: trace subcommand

[日本語](prd.ja.md)

## Purpose

The `ichnograph trace` subcommand runs a target command and captures runtime observations of its file accesses, program executions, descriptor usage, pipe/FIFO activity and network connection attempts into a structured JSON file. It serves as the raw evidence collection entry point in the overall [ichnograph product requirements](../prd.md) and uses the Linux [eBPF collector](../ebpf/prd.md) to gather kernel-level observations.

## Command-line interface

```sh
ichnograph trace [-include-logs] -o output.json command [args...]
```

- **`-o <path>` (required)**: Path to the output JSON file where collected records and completeness metadata (`lost`, `loss_breakdown`, `descendants_remaining` and `limitations`) are written.
- **`-include-logs` (optional)**: Keep records whose `path` or `resolved_path` is under `/var/log` or ends in `.log`.
- **`command [args...]` (required)**: Target executable and its arguments to run under tracing.
- If `-o` is omitted or no target command is supplied, print usage information to standard error and exit with status `2`.

## Post-collection log filtering

- By default (when `-include-logs` is not passed), exclude records whose cleaned `path` or `resolved_path` equals `/var/log`, starts with `/var/log/`, or ends with `.log` after collection finishes.
- When this default filter is applied, append an entry to `limitations` stating that `/var/log` and `.log` records are excluded by default, that relative and descriptor paths may be unresolved or inaccurate, that `-include-logs` includes them, and that filtering occurs after collection and does not reduce kernel event volume or loss.

## Process execution and exit status

- Delegate target process execution and runtime tracing on Linux to the [eBPF collector](../ebpf/prd.md).
- When collection and output file writing succeed, exit with the target command's exit status:
  - The command's normal exit code (`0`–`255`).
  - `128 + signal` when the target command is terminated by a signal.
  - `127` when the target command cannot be found.
  - `126` when the target command is found but cannot be executed.
- If collection fails or the output JSON file cannot be serialized or written, print the error to standard error and exit with status `1`.
