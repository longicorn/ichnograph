# ichnograph

Ichnograph helps investigate what a product feature depends on and what might affect it in its execution environment. It aims to connect runtime observations with information about code, libraries, packages, and services in a dependency graph, supporting investigations such as the impact of component updates.

The name combines **ichno** and **graph**. The root *ichno* appears in words such as ichnofossil, ichnite, and ichnology. The name reflects the goal of bringing together different kinds of information and their relationships.

The project is in its early stages. The first milestone is to collect file-access information using eBPF on Linux while running a command. See the [product requirements](docs/prd.md) and [architecture decisions](docs/adr.md) for details.
