# Product requirements: ichnograph

## Purpose

Ichnograph is a foundation for investigating what a product feature depends on and what can affect it in its execution environment. It extends the idea behind ichno, which records files accessed while a command runs. The results should support impact investigation for component updates and may provide a technical capability for Nagi's reverse work.

## Product direction

Users exercise a feature and use the resulting evidence to investigate its dependencies. Over time, the investigation should connect application code, including JavaScript/TSX and Ruby, with libraries and native extensions, databases, third-party services, OS libraries and commands, and kernel functionality. It should connect runtime observations with SBOM and package information and represent relationships in a dependency graph.

## Observation granularity

Capture evidence sufficient to identify files and code used, including interpreted code, and descriptor use relevant to dependencies. Prefer recording meaningful use and relationships over logging every read or write. Capturing descriptor contents or communication payloads is not a goal. For external communication, aim to identify the endpoint, protocol and associated libraries where possible; attribution may require additional evidence.

Collection should work under realistic workloads while limiting event loss. Report known loss, failures and unavailable information so that users can assess the evidence. The appropriate granularity must preserve evidence from inherited descriptors and other access paths; it is not defined by a fixed list of syscalls.

## First milestone

Demonstrate eBPF collection on Linux by running a target command and producing file-access information comparable to ichno's output.

- Record observed file accesses with a path where it can be resolved, PID, TID and timestamp; include event type and a file hash where obtainable.
- Track the command and its relevant child processes and threads, and output the records as JSON for subsequent processing.
- Support realistic workloads with appropriately bounded event volume, and make unavailable information and known event loss or collection failures visible so that incomplete results are not mistaken for complete coverage.
- Validate the result against a known command and its file accesses, including a child process, and compare the available fields with ichno's output.

Exact probe selection, hash timing and algorithms, required privileges, and supported kernel versions remain implementation decisions. A hash describes the content when it is calculated and may not represent the exact bytes accessed if the file changes.

## Later capabilities

Expand collection to process and network activity and stack information as needed. Resolve observations against executable and debug information, language and OS packages, and SBOMs for the relevant environment. Build a graph that supports traversal from a feature to its dependencies and investigation of potential impacts in the other direction. Container support and detailed language-specific attribution require further definition and are not first-milestone commitments.

## Interpretation and boundaries

Distinguish observed relationships from relationships inferred from surrounding information, and retain their supporting evidence and limitations. A run shows only activity captured during that run; absence from the result does not prove absence of a dependency. Dynamic languages, missing debug information, event loss, asynchronous or distributed execution, and external services may limit attribution. The product must not present a partial observation as a complete dependency inventory.
