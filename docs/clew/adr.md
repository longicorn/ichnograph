# Architecture decisions: clew subcommand

[日本語](adr.ja.md)

## Unprivileged subcommand placement and option-driven pipeline

**Status:** Accepted

Place post-processing under the unprivileged `ichnograph clew` subcommand in `cmd/ichnograph` (`clew.go`) rather than adding options to `trace` or introducing separate subcommands for each transformation step. Keeping `trace` focused on privileged kernel collection and exposing post-processing capabilities as options on `clew` (starting with `-group-by pid,tid`) establishes a single composable pipeline entry point where future enrichment and external metadata merging steps can be added incrementally. The CLI dispatch resides in `cmd/ichnograph`, and the pipeline implementation resides in `internal/clew`.

## Format-dispatched input contract (`ichnograph.clew.v1`)

**Status:** Accepted

`clew` distinguishes raw trace logs from previously processed pipeline outputs by inspecting the top-level `format` field of the input JSON object without requiring changes to `ichnograph trace` output:

- When `format` is absent, `clew` treats the input as raw `trace` JSON containing a top-level `records` array, groups records by `pid` and `tid`, removes `records`, and sets `format` to `"ichnograph.clew.v1"`.
- When `format` is `"ichnograph.clew.v1"`, `clew` validates the `processes` -> `threads` -> `records` hierarchy and verifies that every record's `pid` and `tid` match its enclosing group before re-emitting the document. Any other `format` value is rejected.

## Two-level array hierarchy and raw JSON preservation

**Status:** Accepted

When grouping by `pid,tid`, `clew` emits a two-level array hierarchy (`processes` sorted by `pid` ascending -> `threads` sorted by `tid` ascending -> `records` sorted by timestamp) rather than maps keyed by ID. Using arrays guarantees deterministic output ordering and provides a direct place to attach per-process or per-thread metadata in future stages.

To support composable pipeline stages without dropping unknown or future fields, `clew` decodes the top-level JSON object and individual records as `json.RawMessage`. This preserves top-level completeness metadata (`lost`, `loss_breakdown`, `descendants_remaining`, `limitations`) and any record-level extensions when grouping raw `trace` input, and preserves group-level extensions and group ordering when re-processing an already grouped `"ichnograph.clew.v1"` input.

## Stream-friendly I/O and fail-closed output

**Status:** Accepted

`ichnograph clew` defaults both input and `-o` output to `-` (reading from `/dev/stdin` and writing to `stdout`, formatted as indented JSON with a trailing newline) so stages can be chained via shell pipes or files. Input parsing, schema validation, and grouping complete in memory before any output is written; invalid CLI flags (exit status `2`) and invalid input (exit status `1`) are reported without writing to `-o`. Write failures also return status `1`, but may leave partial output.

## Pipeline package extraction (`internal/clew`)

**Status:** Accepted

As `clew` expands beyond initial grouping to include predicate parsing and evaluation, record filtering, conditional tagging, and file-content inspection, the core pipeline logic is extracted from `cmd/ichnograph` into `internal/clew`. `cmd/ichnograph/clew.go` retains CLI flag parsing, usage reporting, exit status handling, and stdin/stdout/file I/O dispatch, while `internal/clew` owns the composable pipeline stages and domain types. This keeps `cmd/ichnograph` focused on CLI wiring and allows pipeline stages to be unit-tested independently.

## Single-invocation stage ordering and filter semantics

**Status:** Accepted

When multiple transformation options are supplied in a single `ichnograph clew` invocation, stages execute in a fixed order:

1. **Input decoding and validation**: Parse raw `trace` JSON or validate `ichnograph.clew.v1` input into a uniform internal representation.
2. **Filtering (`-include` / `-exclude`) and empty-group pruning**: Evaluate `-include` and `-exclude` predicates against each record. When one or more `-include` predicates are given, a record must match at least one `-include` predicate (`OR`); any record matching at least one `-exclude` predicate (`OR`) is dropped (`OR(include) AND NOT OR(exclude)`). After filtering, any `thread` with an empty `records` array is removed from `threads`, and any `process` with an empty `threads` array is removed from `processes`.
3. **Tagging (`-tag` / `-tag-file-type`)**: Apply user-defined conditional tags (`-tag`) and file-content-based type tags (`-tag-file-type`) to the surviving records. Filtering before tagging avoids unnecessary filesystem I/O and tag evaluation for excluded records.
4. **Grouping and emission**: Group raw `trace` records by `pid,tid` (or preserve validated `ichnograph.clew.v1` group structure) and emit indented JSON.

## Unified field/value predicate model

**Status:** Accepted

`-include`, `-exclude`, and `-tag` share a single predicate parser and evaluator operating on top-level fields of each record:

- **Syntax**: Predicates use `<field>=<value>` for exact matching and `<field>~=<value>` for substring or pattern matching (such as path substrings or suffixes). Conditional tagging rules use `<tag>:<predicate>` (e.g., `ruby:path~=.rb`), validating both the tag name and predicate at CLI parse time (exiting with status `2` on invalid syntax).
- **Evaluation**: Field values are inspected from the decoded record's top-level JSON object. Exact matching (`=`) compares against JSON strings, numbers, and booleans; substring/pattern matching (`~=`) applies to string values. Missing fields or incompatible value types evaluate as non-matching rather than errors.

## Record `tags` merging with raw JSON preservation

**Status:** Accepted

To preserve unknown or future record fields across pipeline stages without re-modeling the entire `trace` schema, `clew` continues to store each record as `json.RawMessage`. Records that receive no new tags are emitted unmodified. When one or more tags are attached to a record, `clew` unmarshals only that record's top-level JSON object map, reads any existing `tags` string array, appends new tags while preserving order and deduplicating values, writes the updated `tags` array back into the map, and re-marshals the record without dropping other keys.

## Pure-Go header inspection and caching for `-tag-file-type`

**Status:** Accepted

File-content-based type detection under `-tag-file-type` is implemented in pure Go behind a detector interface so external tool integrations (such as `file`) can be added later without changing pipeline orchestration:

- **Path resolution and bounded reads**: For each record, `clew` inspects `resolved_path` if present and non-empty, falling back to `path`. Only regular files are inspected, reading a bounded prefix (header bytes) to detect magic bytes (such as `\x7fELF` for `elf`) and shebang lines (`#!` interpreter names such as `ruby`, `python`, `sh`, `bash`), combined with built-in path/extension presets.
- **Per-invocation caching and graceful skip**: Results are cached in memory by resolved file path for the duration of a single `clew` invocation to avoid redundant filesystem I/O across repeated references. If a path is missing, not a regular file, or unreadable at post-processing time, content-based tagging is silently skipped for that record without failing the pipeline.

Records in each thread are stably sorted by RFC 3339 timestamp in ascending order. Equal timestamps retain input order; records with missing or invalid timestamps follow valid timestamps, retaining their input order. This applies to raw and previously grouped inputs.
