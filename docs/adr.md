# Architecture decisions

## Go version and project layout

**Status:** Accepted

Ichnograph is implemented in Go. Its minimum Go version follows the oldest release series supported by the Go project. As of 2026-11-05, this is Go 1.26; review and update the minimum as official support changes. Use a supported patch release for development and builds. See the [Go release policy](https://go.dev/doc/devel/release).

Place command entry points under `cmd/` and organize implementation into feature-oriented packages under `internal/`. Start with `internal/ebpf` for eBPF functionality. Internal packages can be reused within this module but are not a public library API. Introduce additional packages as responsibilities become clear.

## eBPF collection and native integration

**Status:** Accepted

Use eBPF on Linux for the first milestone's file-access collection, as described in the [product requirements](prd.md). Permit cgo when needed for native integration; eBPF itself does not require cgo. The eBPF library, program build approach, probes, privileges and supported kernel versions remain to be selected. Native dependencies and their build implications must be documented when selected.

This approach enables runtime collection while keeping collection code separate from command entry points. The chosen probes and environment will limit what can be observed; collection failures and known event loss must remain visible.
