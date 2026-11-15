# Product requirements: clew subcommand

[日本語](prd.ja.md)

## Purpose

The `ichnograph clew` subcommand is an unprivileged post-processing entry point that transforms raw `ichnograph trace` JSON logs into more manageable, structured representations. Within the [ichnograph product requirements](../prd.md), `clew` bridges raw kernel-level observation logs from [trace](../trace/prd.md) and higher-level runtime normalization and external metadata integration.

`clew` is designed as a composable pipeline: output produced by one `clew` invocation can be fed back as input to subsequent `clew` invocations—optionally alongside external metadata—to incrementally enrich, normalize, or merge observations. Initial scope focuses on grouping raw trace records by `pid` and `tid`; additional enrichment and metadata-merging steps will be defined and added incrementally via CLI options as development progresses.

## Command-line interface

```sh
ichnograph clew [-group-by pid,tid] [-o output.json] [input.json]
```

- **`input.json` (optional)**: Path to the input JSON file. When omitted or `-`, read from standard input (`stdin`).
- **`-o <path>` (optional)**: Path to the output JSON file. When omitted or `-`, write to standard output (`stdout`).
- **`-group-by <keys>` (optional, default: `pid,tid`)**: Grouping strategy for input records. Initially supports `pid,tid`.
- Future processing, enrichment, and external metadata merging capabilities are exposed as options on `clew` rather than separate subcommands.
- Exit status:
  - `0` when processing and output succeed.
  - `2` when CLI arguments or option values are invalid (with usage printed to standard error).
  - `1` when reading input, parsing JSON, validating input structure, or writing output fails (with the error printed to standard error).

## Input & pipeline contract

- Accept raw `ichnograph trace` JSON output (containing a top-level `records` array and completeness metadata) as well as `clew` output JSON (identified by a top-level format/schema identifier such as `format: "ichnograph.clew.v1"`).
- Preserve unknown or extensible fields where appropriate so pipeline stages can pass through or incrementally augment data without breaking downstream consumers.
- Keep all processing unprivileged and deterministic for a given input.

## Grouping behavior & output schema

When grouping by `pid,tid`:

- Organize records into a two-level array hierarchy: `processes` (grouped by `pid`) -> `threads` (grouped by `tid`) -> `records`.
- Using arrays rather than keyed maps allows deterministic ordering (e.g., sorted by `pid` ascending, then `tid` ascending, while preserving observed record order within each thread) and straightforward future addition of per-process or per-thread metadata fields.
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
- Post-processing by `clew` operates solely on the supplied input data; it does not recover events lost during tracing (`lost` / `loss_breakdown`) and must continue to surface `limitations` and loss metadata so incomplete observations are not mistaken for complete coverage.
