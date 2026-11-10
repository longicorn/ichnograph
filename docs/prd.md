# Product requirements: ichnograph

[日本語](prd.ja.md)

## Purpose

Ichnograph is a foundation for understanding the overall runtime composition and dependencies of a program or feature in its actual execution environment. By recording accessed files, processes, communications and related runtime activity while a command runs, it supports practical workflows such as:

- Optimizing test execution by skipping test cases on subsequent runs when their observed dependencies and execution conditions have not changed.
- Reducing the effort required to investigate dependency relationships and potential impacts when updating frameworks, libraries or OS components.

## Product direction

Users run a target program or feature and use the resulting evidence to understand its overall composition and dependencies. Without locking into specific languages, the product connects runtime observations with package metadata, build artifacts and SBOMs, representing their relationships in a dependency graph.

The desired dependency picture spans multiple layers of a running system: not only package source files, but also built native extensions and the dynamic libraries they link against, network and socket endpoints such as the type and version of a database or external service on the other end of a TCP connection, OS commands and libraries, and kernel functionality.

Target programs fall broadly into two categories:

- **Interpreted and lightweight languages:** Trace composition through accessed scripts, package files, built native extensions and the shared libraries loaded by those extensions at runtime.
- **Compiled languages:** Because file access alone does not reveal which internal packages or functions inside a binary are used, combine runtime observations with debug and symbol metadata such as DWARF, call graphs and stack information to identify what is actually exercised.

## Observation granularity

Capture evidence sufficient to identify used files, code, libraries and relevant descriptor or socket activity. Prefer recording meaningful use and relationships that clarify program composition over logging every read or write. Capturing descriptor contents or communication payloads is not a goal. For external communication, aim to identify the endpoint, protocol, backing service or middleware, and associated libraries where possible; attribution may require additional evidence.

Collection should work under realistic workloads while limiting event loss. Report known loss, failures and unavailable information so that users can assess the evidence. The appropriate granularity must preserve evidence from inherited descriptors and other access paths; it is not defined by a fixed list of syscalls.

## First milestone

Demonstrate eBPF collection on Linux by running a target command and producing file-access information alongside initial process, pipe/FIFO and network connection evidence.

- Record observed file, process, descriptor and network activity with a path where it can be resolved, PID, TID and timestamp; include event type and a file hash where obtainable.
- Track the command and its relevant child processes and threads, and output the records as JSON for subsequent processing.
- Support realistic workloads with appropriately bounded event volume, and make unavailable information and known event loss or collection failures visible so that incomplete results are not mistaken for complete coverage.
- Validate the result against a known command and its file accesses, including a child process.

Detailed collector requirements, covered operations, enrichment, deduplication and loss reporting for the Linux eBPF collector are defined in the [eBPF product requirements](ebpf/prd.md).

## Runtime normalization and external metadata integration

After raw collection, organize and combine evidence in two stages rather than hardcoding every language or package ecosystem into the collector:

1. **Normalized runtime summary:** Aggregate raw event streams within `ichnograph` into a clean summary of observed resources—accessed files (with normalized paths, hashes and usage roles such as execution, memory mapping, read or write), process relationships, network endpoints, pipe/FIFO activity and completeness metadata (`lost` and `limitations`). This normalized summary is sufficient on its own for workflows such as selective test skipping.
2. **External metadata mapping and unified format:** Define a common mapping contract and output format for combining the normalized runtime summary with external ecosystem metadata (such as `Gemfile.lock` and installed package paths, OS package file lists, SBOMs, DWARF/symbol analysis or service endpoint definitions).
   - Represent external metadata through two common primitives: **resource ownership** (which component or service owns a given file path, binary range or network endpoint) and **declared dependencies** (static relationships between components).
   - In the combined output, distinguish components and relationships **observed at runtime**, components **declared statically but unobserved during the run**, and **unattributed runtime activity** that did not match any known component.

To capture the broader composition of target programs over time, expand collection and external integration incrementally to stack and call-graph evidence, executable and debug metadata such as DWARF, and service attribution behind socket connections.

## Interpretation and boundaries

Distinguish observed relationships from relationships inferred from surrounding information, and retain their supporting evidence and limitations. A run shows only activity captured during that run; absence from the result does not prove absence of a dependency. Dynamic loading, missing debug information, event loss, asynchronous or distributed execution, and external services may limit attribution. The product must not present a partial observation as a complete dependency inventory.
