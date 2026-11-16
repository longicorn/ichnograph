# ichnograph

[日本語](README.ja.md)

Ichnograph is a tool for understanding the runtime composition and dependencies of a program in its execution environment. By connecting runtime observations of files, processes and network activity with information about packages, libraries, build artifacts and services, it supports workflows such as selective test execution and dependency impact investigation during component updates.

The name combines **ichno** (from *ichnofossil*, *ichnite* and *ichnology*) and **graph**, reflecting the goal of connecting runtime traces into a dependency graph.

## Documentation

- Product overview: [Product requirements](docs/prd.md) | [Architecture decisions](docs/adr.md)
- Linux eBPF collector: [eBPF product requirements](docs/ebpf/prd.md) | [eBPF architecture decisions](docs/ebpf/adr.md)

## Build and usage

On Linux, build the CLI and run it with the privileges required to load eBPF programs and attach tracepoints:

```sh
go build -o ichnograph ./cmd/ichnograph
sudo ./ichnograph trace -o result.json /path/to/command arg
```

- By default, records whose path or resolved path is under `/var/log` or ends in `.log` are excluded after collection. Pass `-include-logs` before `-o` to keep them:
  ```sh
  sudo ./ichnograph trace -include-logs -o result.json /path/to/command arg
  ```
- `ichnograph` exits with the target command's exit status (`128 + signal` when terminated by a signal, `127` if the command is not found, or `126` if it cannot be executed).

`clew` processes trace output without elevated privileges. It groups records by process and thread and can filter or tag them:

```sh
./ichnograph clew -include 'success=true' -tag 'gem:path~=/gem/ruby/' -o grouped.json result.json
```

Input and output default to standard input and standard output, so `clew` commands can be chained. Use `field=value` for an exact match and `field~=value` for a substring match. See the [clew product requirements](docs/clew/prd.md) for details.

Use `help` for available subcommands and their options:

```sh
./ichnograph help
./ichnograph help trace
./ichnograph help clew
```

See the [eBPF product requirements](docs/ebpf/prd.md) and [eBPF architecture decisions](docs/ebpf/adr.md) for details on observed events, deduplication, path resolution, hashing and loss reporting.

## Development and testing

To rebuild the embedded eBPF object (`internal/ebpf/program.o`) after modifying `internal/ebpf/program.c`, install Clang with BPF target support and Linux kernel headers on a little-endian Linux host:

```sh
clang-18 -O2 -g -target bpf -I/usr/include/$(gcc -dumpmachine) -c internal/ebpf/program.c -o internal/ebpf/program.o
```

Run unprivileged unit tests:

```sh
go test ./...
```

Run the eBPF integration test suite on a Linux host with BPF and tracepoint privileges:

```sh
sudo env "PATH=$PATH" ICHNOGRAPH_BPF_TEST=1 go test ./internal/ebpf -count=1 -v
```

## Running in Docker

Running `ichnograph` in a container requires sharing the host PID namespace (`--pid=host` or `pid: "host"`), BPF and tracepoint privileges, an unlimited locked-memory limit (`RLIMIT_MEMLOCK`), and access to `/sys/kernel/tracing` (`tracefs`) or `/sys/kernel/debug` (`debugfs`).

With `docker run` using `--privileged`:

```sh
docker run --rm -it \
  --pid=host \
  --privileged \
  --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  <image> ./ichnograph trace -o result.json /path/to/command arg
```

With explicit capabilities in `compose.yaml`:

```yaml
services:
  app:
    pid: "host"
    cap_add:
      - BPF
      - PERFMON
      - SYS_ADMIN
      - IPC_LOCK
    security_opt:
      - seccomp:unconfined
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing:rw
      - /sys/kernel/debug:/sys/kernel/debug:rw
```

If `/sys/kernel/tracing` is not mounted on the host (for example, in some VM-backed container environments), mount `tracefs` inside a privileged container before running `ichnograph`:

```sh
mount -t tracefs nodev /sys/kernel/tracing
```
