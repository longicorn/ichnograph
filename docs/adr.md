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
