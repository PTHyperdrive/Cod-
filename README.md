# Codé — Academic C2 Framework

> [!CAUTION]
> **This project is strictly for ACADEMIC and EDUCATIONAL purposes.**
> It is designed to run exclusively in an isolated lab environment.
> Do **not** use this software outside of a controlled, host-only virtual network.
> Misuse of offensive security tools may violate laws in your jurisdiction.

## Overview

Codé is a cross-platform Command-and-Control (C2) framework built as an
academic exercise to study adversary tradecraft, network protocol design, and
systems programming. It consists of three components:

| Component | Language | Description |
|---|---|---|
| **Team Server** | Go | Central server that manages agent sessions, dispatches tasks, and exposes a gRPC API for operators. Uses goroutine-per-session concurrency. |
| **Operator Console** | Go (CLI) | Command-line gRPC client that operators use to interact with the Team Server — listing sessions, issuing tasks, and reading results. |
| **Agent** | C99 | Lightweight implant that runs on target machines. Uses a Platform Abstraction Layer (PAL) for cross-platform support, communicates over TLS using mbedTLS, and speaks a custom TLV binary protocol. |

```
┌──────────────┐   gRPC/mTLS   ┌──────────────┐  TLV/TLS 1.3  ┌──────────────┐
│   Operator   │◄─────────────►│  Team Server │◄─────────────►│    Agent     │
│   Console    │               │   (Go)       │               │   (C99)      │
└──────────────┘               └──────────────┘               └──────────────┘
```

---

## Safety Measures

> [!IMPORTANT]
> Safety measures are implemented in the **first commit**, not the last.
> They are compile-time enforced and cannot be bypassed at runtime.

The framework enforces multiple layers of safety to ensure it cannot operate
outside a controlled lab environment:

| # | Measure | Description |
|---|---------|-------------|
| 1 | **CIDR Allowlist** | A list of permitted network ranges is compiled into the agent binary at build time. The agent refuses to communicate with any server whose IP falls outside the allowlist. Default: `10.13.37.0/24`. |
| 2 | **Build-Time Expiry** | Each agent binary embeds a hard-coded expiration timestamp set at compile time (default: 30 days from build). After expiry, the agent prints a message and exits immediately. |
| 3 | **No Persistence** | The agent does **not** install any persistence mechanism — no registry keys, no cron jobs, no services, no startup entries. It runs only as long as the process is alive. |
| 4 | **No Self-Propagation** | The agent has no capability to copy itself, spread to other hosts, or download/execute secondary payloads. It is inert beyond its configured task set. |
| 5 | **Visible by Default** | The agent runs as a normal, visible process. It does not hide from the process list, does not unhook APIs, and does not inject into other processes. It is trivially discoverable via `ps` / Task Manager. |
| 6 | **`--lab-agent` Flag** | The agent **requires** the `--lab-agent` command-line flag to start. Without this flag it prints a safety notice and exits. This prevents accidental execution. |
| 7 | **Kill Switch** | The Team Server can issue a `SHUTDOWN` command to any agent at any time. Additionally, the agent watches for a local kill-switch file (`/tmp/.code_killswitch` on Linux, `%TEMP%\.code_killswitch` on Windows) and exits immediately if it appears. |

---

## Lab Environment

The framework is designed for and tested exclusively in the following lab setup:

```
┌─────────────────────────────────────────────────────┐
│                  VMware Host-Only Network            │
│                  Subnet: 10.13.37.0/24               │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  Team Server │  │  Target VM   │  │ Target VM  │ │
│  │  + Operator  │  │  (Linux)     │  │ (Windows)  │ │
│  │  10.13.37.1  │  │  10.13.37.10 │  │ 10.13.37.20│ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
│                                                      │
│  Network: Host-only (no NAT, no bridged)             │
│  No internet access from any VM                      │
└─────────────────────────────────────────────────────┘
```

- **Hypervisor**: VMware Workstation / Fusion with host-only networking
- **Subnet**: `10.13.37.0/24`
- **Isolation**: No NAT adapter, no bridged adapter — VMs cannot reach the
  internet or any network outside the host-only segment.

---

## Build Targets

The agent cross-compiles for the following 7 platform/architecture combinations:

| # | OS | Architecture | Toolchain | Status |
|---|---|---|---|---|
| 1 | Linux | i386 (x86) | `i686-linux-musl` | ✅ Active |
| 2 | Linux | amd64 (x86_64) | `x86_64-linux-musl` | ✅ Active |
| 3 | Linux | armv7 (32-bit ARM) | `arm-linux-musleabihf` | ✅ Active |
| 4 | Linux | aarch64 (64-bit ARM) | `aarch64-linux-musl` | ✅ Active |
| 5 | Windows | i386 (x86) | `i686-w64-mingw32` | ✅ Active |
| 6 | Windows | amd64 (x86_64) | `x86_64-w64-mingw32` | ✅ Active |
| 7 | Windows | aarch64 (64-bit ARM) | `aarch64-w64-mingw32` | ✅ Active |
| — | ~~Windows~~ | ~~armv7~~ | — | ❌ Dropped (no toolchain) |

All Linux targets link against musl libc for fully static binaries.

---

## Build Instructions

### Prerequisites

- **Go 1.22+** — for Team Server and Operator Console
- **GCC / Clang** — for native agent builds
- **Cross-compilation toolchains** — musl-cross for Linux targets, MinGW-w64
  for Windows targets
- **mbedTLS 3.x source** — vendored under `agent/vendor/mbedtls/`
- **protoc + protoc-gen-go + protoc-gen-go-grpc** — for gRPC code generation
- **OpenSSL** — for certificate generation
- **GNU Make 4.0+**

### Quick Start

```bash
# 1. Generate TLS certificates for the lab network
make certs

# 2. Build the Team Server
make server

# 3. Build the Operator Console
make console

# 4. Build the agent for the current platform
make agent

# 5. Or cross-compile for all 7 targets
make agent-all

# 6. Run the test suite
make test
```

### Agent Build Options

The agent build accepts several compile-time options via environment variables
or Make arguments:

```bash
# Set a custom CIDR allowlist (comma-separated)
make agent CIDR_ALLOWLIST="10.13.37.0/24,192.168.100.0/24"

# Set a custom expiry duration (seconds from build time)
make agent EXPIRY_SECONDS=86400    # 24 hours

# Set the Team Server address
make agent SERVER_HOST=10.13.37.1 SERVER_PORT=443

# Set beacon interval and jitter
make agent BEACON_INTERVAL=30 BEACON_JITTER=20
```

---

## Project Structure

```
Codé/
├── README.md                  # This file
├── PROTOCOL.md                # Wire protocol specification
├── Makefile                   # Top-level build orchestration
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI pipeline
├── certs/
│   ├── generate_certs.sh      # Certificate generation script
│   └── README.md              # Certificate usage guide
├── server/
│   ├── cmd/
│   │   └── serverd/
│   │       └── main.go        # Team Server entry point
│   ├── internal/
│   │   ├── audit/
│   │   │   └── audit.go       # Append-only JSON-lines audit logger
│   │   ├── codec/
│   │   │   ├── tlv.go         # TLV wire codec (encode/decode)
│   │   │   └── tlv_test.go    # Codec unit tests
│   │   ├── grpcapi/
│   │   │   └── grpcapi.go     # gRPC API for operators (mTLS)
│   │   ├── listener/
│   │   │   └── listener.go    # TLS listener for agents
│   │   ├── session/
│   │   │   └── session.go     # Session state machine & manager
│   │   └── taskqueue/
│   │       └── taskqueue.go   # Per-session task queue
│   ├── proto/
│   │   ├── c2.proto           # gRPC service definitions
│   │   └── c2.pb.go           # Hand-written protobuf types
│   ├── go.mod
│   └── go.sum
├── console/
│   ├── cmd/
│   │   └── console/
│   │       └── main.go        # Operator Console entry point
│   ├── internal/
│   │   └── client/
│   │       └── client.go      # gRPC client (mTLS)
│   ├── go.mod
│   └── go.sum
└── agent/
    ├── include/
    │   ├── agent.h            # Agent core interface
    │   ├── capabilities.h     # Capability dispatch interface
    │   ├── config.h           # Build-time configuration defaults
    │   ├── pal.h              # Platform Abstraction Layer interface
    │   ├── protocol.h         # Protocol state machine
    │   ├── safety.h           # Safety measures interface
    │   └── tlv.h              # TLV codec interface
    ├── src/
    │   ├── main.c             # Agent entry point
    │   ├── agent.c            # Beacon loop & registration
    │   ├── protocol.c         # Protocol state machine & TLS I/O
    │   ├── tlv.c              # TLV codec implementation
    │   ├── capabilities.c     # Task dispatch & handlers
    │   ├── safety.c           # Safety checks (expiry, CIDR, killswitch)
    │   ├── pal_linux.c        # PAL — Linux/POSIX
    │   └── pal_win32.c        # PAL — Windows/Winsock2
    ├── tests/
    │   ├── test_tlv.c         # TLV codec unit tests
    │   └── test_safety.c      # Safety mechanism tests
    └── Makefile               # Agent-specific Makefile
```

---

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol specification,
including message formats, TLV field definitions, and state machine diagrams.

---

## Contributing

This is an academic project. Contributions should:

1. Maintain or strengthen all safety measures
2. Include tests for new functionality
3. Follow the existing code style (C99, idiomatic Go)
4. Not add persistence, propagation, or evasion capabilities

---

## License

This project is provided for educational purposes only. See individual source
files for license headers.

---

## Disclaimer

This software is provided **as-is** for educational and research purposes in
controlled lab environments. The authors are not responsible for any misuse.
Always obtain proper authorization before conducting security testing. Unauthorized
access to computer systems is illegal.
