# Architecture decisions

## Go version and project layout

**Status:** Accepted

Ichnograph is implemented in Go. Its minimum Go version follows the oldest release series supported by the Go project. As of 2026-11-05, this is Go 1.26; review and update the minimum as official support changes. Use a supported patch release for development and builds. See the [Go release policy](https://go.dev/doc/devel/release).

Place command entry points under `cmd/` and organize implementation into feature-oriented packages under `internal/`. Start with `internal/ebpf` for eBPF functionality. Internal packages can be reused within this module but are not a public library API. Introduce additional packages as responsibilities become clear.

## Runtime evidence collection

**Status:** Accepted direction; event selection and implementation require validation

Use eBPF on Linux to collect runtime evidence, starting with file access as described in the [product requirements](prd.md). Keep collection separate from command entry points and enrich observations in Go with executable, debug, package and other information when appropriate. Permit cgo for native integration when needed and document its build implications.

Choose events for dependency evidence rather than recording every descriptor read and write. Replace or remove the current fine-grained descriptor event collection as the design is validated, while retaining evidence of file access and relevant descriptor use. Inherited descriptors, file-backed mappings and other access paths need evaluation before events are removed. Descriptor contents and communication payloads are outside the collection goal. Network attribution is a later capability, not a claim of current coverage.

Design for realistic workloads and bounded resource use. Keep loss and collection failures visible, and distinguish their causes where practical. Validate event selection and loss behavior against representative workloads before declaring the change effective. Exact probes, event representation, buffering, supported kernels and privileges remain implementation decisions. The existing collector may differ from this direction until changed.
