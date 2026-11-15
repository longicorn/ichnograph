# Architecture decisions: clew subcommand

[日本語](adr.ja.md)

## Unprivileged subcommand placement and option-driven pipeline

**Status:** Accepted

Place post-processing under the unprivileged `ichnograph clew` subcommand in `cmd/ichnograph` (`clew.go`) rather than adding options to `trace` or introducing separate subcommands for each transformation step. Keeping `trace` focused on privileged kernel collection and exposing post-processing capabilities as options on `clew` (starting with `-group-by pid,tid`) establishes a single composable pipeline entry point where future enrichment and external metadata merging steps can be added incrementally. Because the initial grouping logic is self-contained, it resides directly in `cmd/ichnograph` alongside CLI dispatch and can be extracted into an `internal/` package if future pipeline stages require it.

## Format-dispatched input contract (`ichnograph.clew.v1`)

**Status:** Accepted

`clew` distinguishes raw trace logs from previously processed pipeline outputs by inspecting the top-level `format` field of the input JSON object without requiring changes to `ichnograph trace` output:

- When `format` is absent, `clew` treats the input as raw `trace` JSON containing a top-level `records` array, groups records by `pid` and `tid`, removes `records`, and sets `format` to `"ichnograph.clew.v1"`.
- When `format` is `"ichnograph.clew.v1"`, `clew` validates the `processes` -> `threads` -> `records` hierarchy and verifies that every record's `pid` and `tid` match its enclosing group before re-emitting the document. Any other `format` value is rejected.

## Two-level array hierarchy and raw JSON preservation

**Status:** Accepted

When grouping by `pid,tid`, `clew` emits a two-level array hierarchy (`processes` sorted by `pid` ascending -> `threads` sorted by `tid` ascending -> `records` in observed order) rather than maps keyed by ID. Using arrays guarantees deterministic output ordering and provides a direct place to attach per-process or per-thread metadata in future stages.

To support composable pipeline stages without dropping unknown or future fields, `clew` decodes the top-level JSON object and individual records as `json.RawMessage`. This preserves top-level completeness metadata (`lost`, `loss_breakdown`, `descendants_remaining`, `limitations`) and any record-level extensions when grouping raw `trace` input, and preserves group-level extensions and ordering when re-processing an already grouped `"ichnograph.clew.v1"` input.

## Stream-friendly I/O and fail-closed output

**Status:** Accepted

`ichnograph clew` defaults both input and `-o` output to `-` (reading from `/dev/stdin` and writing to `stdout`, formatted as indented JSON with a trailing newline) so stages can be chained via shell pipes or files. Input parsing, schema validation, and grouping complete in memory before any output is written; on invalid CLI flags (exit status `2`) or invalid input/write errors (exit status `1`), `clew` reports the error to standard error without writing partial output to `-o`.
