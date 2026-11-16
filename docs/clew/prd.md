# Product requirements: clew subcommand

[日本語](prd.ja.md)

## Purpose

The `ichnograph clew` subcommand is an unprivileged post-processing entry point that transforms raw `ichnograph trace` JSON logs into more manageable, structured representations. Within the [ichnograph product requirements](../prd.md), `clew` bridges raw kernel-level observation logs from [trace](../trace/prd.md) and higher-level runtime normalization and external metadata integration.

`clew` is designed as a composable pipeline: output produced by one `clew` invocation can be fed back as input to subsequent `clew` invocations—optionally alongside external metadata—to incrementally enrich, filter, normalize, or merge observations. Alongside grouping raw trace records by `pid` and `tid`, `clew` supports unified field/value predicate filtering (`include` / `exclude`), user-defined conditional tagging, and file-content-based type tagging; additional enrichment and metadata-merging steps will be defined and added incrementally via CLI options as development progresses.

## Command-line interface

```sh
ichnograph clew [-group-by pid,tid] [-include <predicate>...] [-exclude <predicate>...] [-tag <tag>:<predicate>...] [-tag-file-type] [-o output.json] [input.json]
```

- **`input.json` (optional)**: Path to the input JSON file. When omitted or `-`, read from standard input (`stdin`).
- **`-o <path>` (optional)**: Path to the output JSON file. When omitted or `-`, write to standard output (`stdout`).
- **`-group-by <keys>` (optional, default: `pid,tid`)**: Grouping strategy for input records. Initially supports `pid,tid`.
- **`-include <predicate>` / `-exclude <predicate>` (optional, repeatable)**: Filter records using a shared field/value predicate model (e.g., exact matches such as `success=true` / `success=false`, or substring/pattern matches against fields such as `path` or `resolved_path`).
- **`-tag <tag>:<predicate>` (optional, repeatable)**: Attach a user-specified tag to records matching the predicate (e.g., tagging `.rb` paths as `ruby`). The syntax is `<tag>:<field>=<value>` for exact matching or `<tag>:<field>~=<value>` for substring matching. Field and tag names start with an ASCII letter or underscore and contain only ASCII letters, digits, and underscores. Values must be nonempty.
- **`-tag-file-type` (optional)**: Detect file types using built-in presets and local file content inspection (such as file headers/magic bytes for ELF or shebang scripts, with optional future integration with external tools such as `file`), attaching corresponding tags (e.g., `elf`, `ruby`).
- Future processing, enrichment, and external metadata merging capabilities are exposed as options on `clew` rather than separate subcommands.
- Exit status:
  - `0` when processing and output succeed.
  - `2` when CLI arguments, option values, or predicate expressions are invalid (with usage printed to standard error).
  - `1` when reading input, parsing JSON, validating input structure, or writing output fails (with the error printed to standard error).

## Input & pipeline contract

- Accept raw `ichnograph trace` JSON output (containing a top-level `records` array and completeness metadata) as well as `clew` output JSON (identified by a top-level format/schema identifier such as `format: "ichnograph.clew.v1"`).
- Apply the same filtering and tagging behavior uniformly whether the input is raw `trace` JSON or `ichnograph.clew.v1` JSON.
- Preserve unknown or extensible fields where appropriate so pipeline stages can pass through or incrementally augment data without breaking downstream consumers.
- Keep all processing unprivileged. Operations that depend solely on the input JSON are deterministic for a given input; optional file-content inspection depends on the local filesystem state at post-processing time.

## Filtering & tagging behavior

- **Unified predicate model**: Filtering (`-include`, `-exclude`) and conditional tagging (`-tag`) share a common predicate evaluation model operating on arbitrary top-level record fields (such as `success`, `path`, `resolved_path`, or `event`). Predicates support exact value matching (booleans, numbers, strings) as well as substring/pattern matching (such as path substring or suffix matching). If the target field is absent on a record, the predicate evaluates to non-matching.
- **Empty group removal**: After filtering, any `thread` whose `records` array becomes empty is omitted from `threads`, and any `process` whose `threads` array becomes empty is omitted from `processes`.
- **Tag representation**: Tags are stored on each record as a `tags` string array. When tagging records that already contain `tags` (for example, across chained `clew` pipeline invocations), existing tags are preserved and new tags are merged without duplicates.
- **File-content-based type detection**: When `-tag-file-type` is enabled, `clew` inspects referenced local files (preferring `resolved_path` when available, or `path`) via header/magic-byte inspection and built-in presets (and optionally external `file` integration if supported). If a referenced file does not exist or cannot be read at post-processing time, `clew` skips content-based tagging for that record without failing the pipeline.

## Grouping behavior & output schema

When grouping by `pid,tid`:

- Organize records into a two-level array hierarchy: `processes` (grouped by `pid`) -> `threads` (grouped by `tid`) -> `records`.
- Using arrays rather than keyed maps allows deterministic ordering (e.g., sorted by `pid` ascending, then `tid` ascending, with records sorted by timestamp within each thread) and straightforward future addition of per-process or per-thread metadata fields.
- Preserve top-level completeness metadata from the input (`lost`, `loss_breakdown`, `descendants_remaining`, and `limitations`).

Example output structure:

```json
{
  "format": "ichnograph.clew.v1",
  "processes": [
    {
      "pid": 1234,
      "threads": [
        {
          "tid": 1234,
          "records": []
        }
      ]
    }
  ],
  "lost": 0,
  "loss_breakdown": {},
  "descendants_remaining": false,
  "limitations": []
}
```

## Error handling & limitations

- If the input is not valid JSON or lacks the expected structure for the requested operation, fail with a clear error on standard error and exit with status `1` without writing partial output to `-o`.
- Post-processing by `clew` operates solely on the supplied input data (and, when file-content type tagging is enabled, readable local files at post-processing time); it does not recover events lost during tracing (`lost` / `loss_breakdown`) and must continue to surface `limitations` and loss metadata so incomplete observations are not mistaken for complete coverage.
- File-content-based type detection reflects the state of local files when `clew` runs, not necessarily their state at trace collection time; missing, deleted, or unreadable files are silently skipped rather than treated as fatal errors.

Records in each thread are stably sorted by RFC 3339 timestamp in ascending order. Equal timestamps retain input order; records with missing or invalid timestamps follow valid timestamps, retaining their input order. This applies to raw and previously grouped inputs.
