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

## Later capabilities

To capture the broader composition of target programs, expand capabilities incrementally to stack and call-graph collection, executable and debug metadata analysis such as DWARF, identification of databases and services behind socket connections, and correlation against language packages, OS packages and SBOMs. Build a graph that supports traversal from a feature or test case to its dependencies and impact investigation in the reverse direction when components change. Container support and runtime-specific analysis will be defined and expanded incrementally.

## Interpretation and boundaries

Distinguish observed relationships from relationships inferred from surrounding information, and retain their supporting evidence and limitations. A run shows only activity captured during that run; absence from the result does not prove absence of a dependency. Dynamic loading, missing debug information, event loss, asynchronous or distributed execution, and external services may limit attribution. The product must not present a partial observation as a complete dependency inventory.
