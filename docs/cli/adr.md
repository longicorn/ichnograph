# Architecture decisions: CLI

[日本語](adr.ja.md)

## Subcommand-based CLI dispatch and standard `flag` usage

**Status:** Accepted

Keep `cmd/ichnograph` built on the Go standard library `flag.NewFlagSet` per subcommand without introducing third-party CLI frameworks. This preserves the existing lightweight dependency footprint and subcommand isolation established in [root architecture decisions](../adr.md) and [trace architecture decisions](../trace/adr.md).

Previously, subcommand `FlagSet.Usage` overrides printed only a single-line usage summary and omitted individual option descriptions. Each subcommand must now format both its usage line and its registered flags (`PrintDefaults` or equivalent) so that `ichnograph help <subcommand>` and `<subcommand> -h` / `--help` display consistent, complete option documentation.

The internal `--ichnograph-exec-helper` flag continues to be intercepted at the very beginning of `main()` before subcommand dispatch and remains excluded from public `help` output.

## Help output stream and exit code conventions

**Status:** Accepted

Follow standard POSIX and Go CLI conventions for help vs. error output:

- **Explicit help requests** (`ichnograph help`, `ichnograph help <subcommand>`, `ichnograph -h` / `--help`, and `ichnograph <subcommand> -h` / `--help`) write help text to `stdout` and exit with status `0`, allowing users to pipe help output to pagers such as `less` or `grep`.
- **Usage and argument errors** (no arguments, unknown subcommands, unknown flags, or missing required arguments) write error details together with the equivalent `help` output (top-level or subcommand-specific) to `stderr` and exit with status `2`.

Because Go's `flag.FlagSet` defaults its output writer to `os.Stderr`, `-h` / `--help` (`flag.ErrHelp`) handling must ensure help text is directed to `os.Stdout` (or printed explicitly to `os.Stdout` upon `flag.ErrHelp`) while parse errors remain on `os.Stderr`.

## Centralized CLI reference and delegated subcommand PRDs

**Status:** Accepted

Use [CLI product requirements](prd.md) as the single overview and reference for root CLI dispatch, `help` behavior, shared conventions, and the cross-subcommand option index. Keep domain-specific execution behavior, filtering rules, and JSON schemas in each subcommand's own PRD ([trace](../trace/prd.md), [clew](../clew/prd.md)) to avoid duplicating detailed specifications across documents.
