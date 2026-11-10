# Architecture decisions

[日本語](adr.ja.md)

## Go version and project layout

**Status:** Accepted

Ichnograph is implemented in Go. Its minimum Go version follows the oldest release series supported by the Go project. As of 2026-11-05, this is Go 1.26; review and update the minimum as official support changes. Use a supported patch release for development and builds. See the [Go release policy](https://go.dev/doc/devel/release).

Place command entry points under `cmd/` and organize implementation into feature-oriented packages under `internal/`. Start with `internal/ebpf` for eBPF functionality. Internal packages can be reused within this module but are not a public library API. Introduce additional packages as responsibilities become clear.

## Runtime evidence collection and CLI boundary

**Status:** Accepted

Use eBPF on Linux to collect runtime evidence as described in the [product requirements](prd.md). Keep collection in `internal/ebpf` separate from command entry points under `cmd/ichnograph`, and enrich observations in Go with process state, file identity and other metadata when appropriate. Permit cgo for native integration when needed and document its build implications.

The CLI entry point invokes `internal/ebpf`, formats the structured result as JSON, and applies command-level output options. By default, the CLI excludes records whose path or resolved path is under `/var/log` or ends in `.log` after collection unless `-include-logs` is specified, and records this post-collection filter in the output limitations because it does not reduce kernel event volume or loss.

Detailed architectural decisions for eBPF probe selection, process tracking, event filtering, deduplication, path resolution and loss handling are documented in the [eBPF architecture decisions](ebpf/adr.md).

## Separation of runtime normalization and external metadata mapping

**Status:** Accepted

Keep `internal/ebpf` focused on privileged kernel event collection and raw observation output. Implement post-collection normalization and external metadata integration as separate, unprivileged stages:

1. **In-repository runtime normalization:** Summarize raw collector records in Go into a normalized view of observed files (path, hash and access roles), process trees, network endpoints, IPC activity and collection limitations. Keep this stage independent of language-specific package managers so that `ichnograph` alone can produce a self-contained runtime summary for workflows such as test-skipping checks.
2. **Schema-driven external metadata merging:** Rather than embedding parsers for every language package manager, SBOM format, OS package database or middleware directly into the core collector, define a common mapping schema and merging rules. External tools or adapters supply component ownership mappings (matching file paths, binary symbols or network endpoints to components and versions) and declared static dependencies (such as from `Gemfile.lock` or SBOMs).
3. **Explicit attribution states:** When combining the normalized runtime summary with external mappings, preserve whether each component or edge is backed by runtime observation, present only in static declarations, or observed at runtime without a matching component. Carry forward collector loss and limitation metadata so downstream consumers can evaluate confidence.
