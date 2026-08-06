# argo-ebpf

> **Warning**  
> PoC -- not for production use

`argo-ebpf` is a Go-based network analyzer that leverages **eBPF** (Extended Berkeley Packet Filter) to collect and process network statistics at the kernel level, specifically designed for Internet Exchange Point (IXP) environments.

The project monitors network traffic (focusing on broadcast/protocol analysis), maps MAC addresses to Peer information using IX-F member lists, and stores the aggregated results in Redis.

## Features

- **Kernel-level Analysis**: Uses eBPF programs (written in C) to intercept and filter network packets efficiently.
- **IX-F Integration**: Automatically fetches and parses IXP member lists (IX-F JSON schema) to map traffic to specific Autonomous Systems (ASNs).
- **High Performance**: Employs a worker-pool pattern for processing and a Ring Buffer/Map system to bridge the kernel and userspace.
- **Persistence**: Exports real-time peer statistics and alerts to a Redis backend.
- **Cross-Platform Development**: Includes specialized Makefiles for building on Linux and developing/cross-compiling on macOS.

## Project Structure

- `cmd/`: Entry points for the application.
- `internal/domain/`: Core business logic and entities (Peers, Stats, Network protocols).
- `internal/infrastructure/ebpf/`: C source code for eBPF programs, generated Go bindings (`bpf2go`), and the Go loader/poller logic.
- `internal/services/collector/`: Orchestration logic that processes eBPF events and manages the Peer cache.
- `internal/services/ixf/`: Mapper for fetching and resolving IX-F member data.

## Prerequisites

- **Go**: Version 1.26+
- **Clang/LLVM**: For compiling eBPF C code.
- **Linux Kernel**: A modern version (5.4+) supporting eBPF features (if running natively).
- **Redis**: A running instance to store analyzed data.
- **Homebrew (macOS only)**: For installing `llvm` tools during cross-development.

## Building the Project

The project uses `Makefile` to automate the generation of eBPF bindings and the compilation of the Go binary.

### On Linux (Native)
To generate eBPF code and build the binary:

```make -f Makefile.linux all```

### On macOS (Cross-compilation)
To compile for a Linux target from a macOS machine:

```make -f Makefile.osx all```

*Note: this requires `llvm` installed via brew.*

## Configuration

The application expects configuration via environment variables or ```.env``` file. 
Key parameters include:

- `IFACE`: The network interface to attach the eBPF program (e.g., `eth0`).
- `IXF_URL`: The URL of the IX-F member list JSON.
- `REDIS_ADDR`: Address of the Redis server (e.g., `localhost:6379`).

## Usage

Once built, the binary can be found in the `bin/` directory. Running it requires root privileges to load programs 
into the BPF subsystem. You can find a sample systemd service file in the ```assets``` directory.

## License

This project is licensed under the **GPL-2.0-or-later** License. See the `LICENSE` file for details.