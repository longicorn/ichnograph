# Product requirements: CLI

[日本語](prd.ja.md)

## Purpose

This document defines the overall command-line interface (CLI) specification for `ichnograph`, including its subcommand structure, common conventions, full option reference, and the `help` subcommand and help output requirements. Detailed runtime behavior and schemas for individual subcommands are defined in [trace product requirements](../trace/prd.md) and [clew product requirements](../clew/prd.md).

## Command structure

```sh
ichnograph <subcommand> [options] [arguments]
```

Available public subcommands:

- **`trace`**: Run a target command under privileged eBPF tracing and write structured runtime observations to JSON ([trace PRD](../trace/prd.md)).
- **`clew`**: Perform unprivileged post-processing and grouping on `trace` or `clew` JSON output ([clew PRD](../clew/prd.md)).
- **`help`**: Display top-level or subcommand-specific usage and option help.

> **Note:** The `--ichnograph-exec-helper` flag is an internal startup handshake mechanism used by `trace` execution and is not a public subcommand or user-facing option. It must not appear in user-facing `help` listings.

## Help command and help output

### Top-level help

- Invocations: `ichnograph help`, `ichnograph -h`, `ichnograph --help`.
- Output the top-level usage line, a concise description of each public subcommand (`trace`, `clew`, `help`), and instructions for viewing subcommand help (`ichnograph help <subcommand>`) to **standard output (`stdout`)**, then exit with status `0`.

### Subcommand help

- Invocations: `ichnograph help <subcommand>`, `ichnograph <subcommand> -h`, `ichnograph <subcommand> --help` (where `<subcommand>` is `trace`, `clew`, or `help`).
- Output the subcommand's usage line, a brief description, and all supported options (flag name, argument syntax, default value, and description) to **standard output (`stdout`)**, then exit with status `0`.

### Invalid invocations and error output

- On CLI usage errors—such as invoking `ichnograph` with no arguments, an unknown subcommand (including `ichnograph help <unknown>`), extra unexpected arguments (such as `ichnograph help trace extra`), unknown flags, or missing required arguments—print an error message together with the equivalent `help` output (top-level help for root-level errors, or the target subcommand's help for subcommand-level errors) to **standard error (`stderr`)** and exit with status `2`.

## Subcommands and options reference

### `ichnograph trace`

```sh
ichnograph trace [-include-logs] -o output.json command [args...]
```

- **`-o <path>` (required)**: Path to the output JSON file.
- **`-include-logs` (optional, default: `false`)**: Include records whose `path` or `resolved_path` is under `/var/log` or ends in `.log`.
- **`command [args...]` (required)**: Target executable and its arguments to run under tracing.
- **Exit status**: Target command's exit status (`0`–`255`, `128 + signal`, `127` if not found, `126` if not executable) on successful tracing and output writing; `2` on invalid CLI arguments; `1` on tracing or output failure.

### `ichnograph clew`

```sh
ichnograph clew [-group-by pid,tid] [-o output.json] [input.json]
```

- **`-group-by <keys>` (optional, default: `pid,tid`)**: Grouping keys for input records (currently only `pid,tid` is supported).
- **`-o <path>` (optional, default: `-`)**: Path to the output JSON file (`-` writes to `stdout`).
- **`input.json` (optional, default: `-`)**: Path to the input JSON file (omitted or `-` reads from `stdin`).
- **Exit status**: `0` on success; `2` on invalid CLI arguments or option values; `1` on input read, JSON parse, validation, or output write failure.

### `ichnograph help`

```sh
ichnograph help [subcommand]
```

- **`subcommand` (optional)**: Name of a public subcommand (`trace`, `clew`, or `help`) to show detailed help for. When omitted, displays top-level help.
- **Exit status**: `0` on success; `2` when an unknown subcommand or extra argument is supplied.

## Common conventions

- **Output streams**: Explicit help requests (`help`, `-h`, `--help`) write to `stdout`. CLI usage errors and runtime errors write to `stderr`.
- **Exit codes**:
  - `0`: Success or explicit help output.
  - `2`: CLI syntax error, unknown subcommand/flag, or missing required arguments.
  - `1`: Runtime, I/O, or JSON processing failure.
  - For `trace`, when tracing and JSON output succeed, the target command's exit status is propagated.
