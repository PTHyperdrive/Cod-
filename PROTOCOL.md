# Codé — Wire Protocol Specification

## 1. Overview

The Codé protocol is a binary protocol used for communication between agents
and the Team Server. It uses a **length-prefixed TLV (Type-Length-Value)**
encoding transported over **TLS 1.3**.

Key design principles:

- **Simplicity**: Minimal framing overhead, easy to implement in C99
- **Determinism**: Fixed field sizes, no ambiguous encodings
- **Safety**: Sequence numbers prevent replay, TLS 1.3 provides confidentiality

---

## 2. Transport Layer

### 2.1 TLS Configuration

| Property | Value |
|---|---|
| Protocol | TLS 1.3 (minimum) |
| Library (agent) | mbedTLS 3.x |
| Library (server) | Go `crypto/tls` |
| Certificate Pinning | Agent pins the server certificate hash at build time |
| System Trust Store | **Not used** — agent trusts only the pinned certificate |
| Mutual TLS | Used between Operator Console ↔ Team Server (gRPC) |
| Agent Auth | Certificate pinning (server) + REGISTER handshake |

### 2.2 Connection Lifecycle

```
Agent                                          Server
  │                                              │
  │──── TLS ClientHello ────────────────────────►│
  │◄─── TLS ServerHello + Certificate ──────────│
  │     (agent verifies pinned cert hash)        │
  │──── TLS Finished ──────────────────────────►│
  │◄─── TLS Finished ──────────────────────────│
  │                                              │
  │     ═══ TLS 1.3 session established ═══     │
  │                                              │
  │──── REGISTER message ──────────────────────►│
  │◄─── REGISTER response (session_id) ────────│
  │                                              │
  │     ═══ Session ACTIVE ═══                   │
  │                                              │
  │──── BEACON ────────────────────────────────►│
  │◄─── TASK (or empty response) ──────────────│
  │──── RESULT ────────────────────────────────►│
  │     ...                                      │
  │                                              │
  │◄─── SHUTDOWN ──────────────────────────────│
  │     (agent exits cleanly)                    │
  └──────────────────────────────────────────────┘
```

---

## 3. Message Framing

Every message on the wire is framed with a **4-byte big-endian length prefix**
followed by the **TLV body**.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                    Length (4 bytes, big-endian)                    │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                                                                   │
│                    TLV Body (variable length)                     │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

- **Length**: The total byte count of the TLV body that follows. Does **not**
  include the 4-byte length prefix itself.
- **Maximum message size**: 1 MiB (1,048,576 bytes). Messages exceeding this
  limit are rejected and the connection is closed.
- **Byte order**: All multi-byte integer fields are **big-endian** (network
  byte order).

---

## 4. TLV Format

The TLV body consists of a **message header** followed by zero or more
**TLV fields**.

### 4.1 Message Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│  Msg Type (1)  │   Reserved (1)  │       Sequence Number (4)     │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤                               │
│                                  │                               │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                       Session ID (16 bytes, UUID)                 │
│                                                                   │
│                                                                   │
│                                                                   │
├───────────────────────────────────────────────────────────────────┤
│                       TLV Fields ...                              │
└───────────────────────────────────────────────────────────────────┘
```

| Field | Offset | Size | Description |
|---|---|---|---|
| Msg Type | 0 | 1 byte | Message type identifier (see §5) |
| Reserved | 1 | 1 byte | Reserved for future use, must be `0x00` |
| Sequence Number | 2 | 4 bytes | Monotonically increasing counter (big-endian) |
| Session ID | 6 | 16 bytes | UUID v4 in raw bytes (assigned by server on REGISTER) |

**Total header size: 22 bytes**

For the initial `REGISTER` message (before a session ID is assigned), the
Session ID field is set to all zeros (`0x00 × 16`).

### 4.2 TLV Field Structure

Each TLV field within the body has the following format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│         Type (2 bytes)          │         Length (4 bytes)        │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤                               │
│                                  │                               │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                       Value (variable)                            │
│                          ...                                      │
└───────────────────────────────────────────────────────────────────┘
```

| Field | Size | Description |
|---|---|---|
| Type | 2 bytes | TLV field type identifier (big-endian) |
| Length | 4 bytes | Byte length of the Value field (big-endian) |
| Value | variable | Field data (interpretation depends on Type) |

**Minimum TLV field size: 6 bytes** (type + length, with zero-length value)

Multiple TLV fields are concatenated sequentially. The parser reads fields
until the entire message body (as indicated by the framing length) is consumed.

---

## 5. Message Types

| Type ID | Name | Direction | Description |
|---|---|---|---|
| `0x01` | REGISTER | Agent → Server | Initial registration handshake |
| `0x02` | BEACON | Agent → Server | Periodic heartbeat / check-in |
| `0x03` | TASK | Server → Agent | Task assignment |
| `0x04` | RESULT | Agent → Server | Task execution result |
| `0x05` | SHUTDOWN | Server → Agent | Graceful shutdown command |

### 5.1 REGISTER (0x01)

Sent by the agent immediately after TLS establishment. The agent provides
system information for enrollment. The server responds with a REGISTER
message containing the assigned session ID.

**Agent → Server (Request):**

| TLV Type | Name | Value Type | Description |
|---|---|---|---|
| `0x0001` | HOSTNAME | UTF-8 string | Machine hostname |
| `0x0002` | OS_TYPE | UTF-8 string | Operating system (`"linux"` or `"windows"`) |
| `0x0003` | OS_ARCH | UTF-8 string | Architecture (`"i386"`, `"amd64"`, `"armv7"`, `"aarch64"`) |
| `0x0004` | OS_VERSION | UTF-8 string | OS version string |
| `0x0005` | AGENT_VERSION | UTF-8 string | Agent build version |
| `0x0006` | AGENT_PID | uint32 | Agent process ID |
| `0x0007` | USERNAME | UTF-8 string | Current username |

**Server → Agent (Response):**

| TLV Type | Name | Value Type | Description |
|---|---|---|---|
| `0x0010` | SESSION_ID | 16 bytes | Assigned UUID v4 session identifier |
| `0x0011` | SERVER_TIME | uint64 | Server UTC timestamp (Unix epoch seconds) |
| `0x0012` | BEACON_INTERVAL | uint32 | Recommended beacon interval in seconds |
| `0x0013` | BEACON_JITTER | uint8 | Jitter percentage (0–100) |

```
Example REGISTER exchange:

Agent ──► Server:
┌────────┬────────┬──────────┬──────────────────┬──────────────────────┐
│ Length  │ 0x01   │ Seq=1    │ SessionID=0x00…  │ TLVs: HOSTNAME,     │
│ (4B)   │ (type) │ (4B)     │ (16B zeros)      │ OS_TYPE, OS_ARCH,   │
│        │        │          │                  │ OS_VERSION, PID, …  │
└────────┴────────┴──────────┴──────────────────┴──────────────────────┘

Server ──► Agent:
┌────────┬────────┬──────────┬──────────────────┬──────────────────────┐
│ Length  │ 0x01   │ Seq=1    │ SessionID=<uuid> │ TLVs: SESSION_ID,   │
│ (4B)   │ (type) │ (4B)     │ (16B)            │ SERVER_TIME,        │
│        │        │          │                  │ BEACON_INTERVAL, …  │
└────────┴────────┴──────────┴──────────────────┴──────────────────────┘
```

### 5.2 BEACON (0x02)

Sent by the agent at the configured interval (with jitter) to indicate
liveness and to poll for pending tasks.

**Agent → Server:**

| TLV Type | Name | Value Type | Description |
|---|---|---|---|
| `0x0020` | AGENT_UPTIME | uint64 | Seconds since agent start |
| `0x0021` | TASK_SLOTS | uint8 | Number of available concurrent task slots |

**Server → Agent (Response):**

If tasks are pending, the server responds with one or more TASK messages.
If no tasks are pending, the server responds with a BEACON message containing
no TLV fields (header only) to acknowledge.

### 5.3 TASK (0x03)

Sent by the server to assign work to the agent. Each task has a unique
task ID and a task type.

**Server → Agent:**

| TLV Type | Name | Value Type | Description |
|---|---|---|---|
| `0x0030` | TASK_ID | 16 bytes | Unique task identifier (UUID v4) |
| `0x0031` | TASK_TYPE | uint16 | Task type code (see §5.3.1) |
| `0x0032` | TASK_ARGS | bytes | Task-specific argument data |
| `0x0033` | TASK_TIMEOUT | uint32 | Maximum execution time in seconds (0 = no limit) |

#### 5.3.1 Task Type Codes

| Code | Name | Description |
|---|---|---|
| `0x0001` | TASK_SHELL | Execute a shell command |
| `0x0002` | TASK_SYSINFO | Collect system information |
| `0x0003` | TASK_DOWNLOAD | Read a file from the target (agent → server) |
| `0x0004` | TASK_UPLOAD | Write a file to the target (server → agent) |

### 5.4 RESULT (0x04)

Sent by the agent to report the outcome of a completed task.

**Agent → Server:**

| TLV Type | Name | Value Type | Description |
|---|---|---|---|
| `0x0040` | TASK_ID | 16 bytes | Task ID this result corresponds to |
| `0x0041` | RESULT_STATUS | uint8 | Status code: 0=success, 1=error, 2=timeout |
| `0x0042` | RESULT_DATA | bytes | Task output data |
| `0x0043` | RESULT_ERROR | UTF-8 string | Error message (if status ≠ 0) |
| `0x0044` | RESULT_ELAPSED | uint32 | Task execution time in milliseconds |

### 5.5 SHUTDOWN (0x05)

Sent by the server to instruct the agent to terminate gracefully.

**Server → Agent:**

| TLV Type | Name | Value Type | Description |
|---|---|---|---|
| `0x0050` | SHUTDOWN_REASON | UTF-8 string | Human-readable reason for shutdown |

The agent must:
1. Acknowledge with a SHUTDOWN response (header only, no TLV fields)
2. Cancel any running tasks
3. Close the TLS connection
4. Exit the process

---

## 6. Sequence Numbers

Each session maintains an independent, monotonically increasing sequence
number counter.

### Rules

1. The agent starts its sequence counter at `1` with the REGISTER message.
2. Each subsequent message from the agent increments the counter by `1`.
3. The server maintains a per-session expected sequence number.
4. The server **rejects** any message whose sequence number is not strictly
   greater than the last received sequence number for that session.
5. Upon rejection, the server closes the connection (the agent will
   re-register on the next beacon cycle).
6. Server-to-agent messages use a separate, server-side counter per session
   (also starting at `1` and monotonically increasing).

```
Agent                          Server
  │                              │
  │── Seq=1 (REGISTER) ────────►│  last_seen = 1
  │◄── Seq=1 (REGISTER resp) ──│
  │                              │
  │── Seq=2 (BEACON) ──────────►│  2 > 1 ✓  last_seen = 2
  │◄── Seq=2 (BEACON resp) ────│
  │                              │
  │── Seq=3 (BEACON) ──────────►│  3 > 2 ✓  last_seen = 3
  │◄── Seq=3 (TASK) ───────────│
  │                              │
  │── Seq=4 (RESULT) ──────────►│  4 > 3 ✓  last_seen = 4
  │                              │
  │── Seq=2 (REPLAY!) ─────────►│  2 > 4 ✗  REJECTED, conn closed
  │                              │
```

---

## 7. Session Lifecycle

Sessions follow a strict state machine:

```
                    ┌───────────────┐
                    │               │
         TLS conn   │     INIT      │
         opened     │               │
                    └───────┬───────┘
                            │
                   REGISTER │ (agent sends 0x01)
                   accepted │
                            ▼
                    ┌───────────────┐
                    │               │
                    │  REGISTERED   │
                    │               │
                    └───────┬───────┘
                            │
                  First     │ BEACON (agent sends 0x02)
                  beacon    │
                            ▼
                    ┌───────────────┐
                    │               │◄──── BEACON / TASK / RESULT
                    │    ACTIVE     │      (normal operation)
                    │               │────►
                    └───────┬───────┘
                            │
                  SHUTDOWN  │ (server sends 0x05,
                  or        │  timeout, or error)
                  timeout   │
                            ▼
                    ┌───────────────┐
                    │               │
                    │   SHUTDOWN    │
                    │               │
                    └───────────────┘
```

### State Transitions

| From | To | Trigger |
|---|---|---|
| — | INIT | TLS connection established |
| INIT | REGISTERED | Server accepts REGISTER message |
| INIT | SHUTDOWN | Registration rejected or timeout (10s) |
| REGISTERED | ACTIVE | First BEACON received |
| REGISTERED | SHUTDOWN | No BEACON within 30 seconds |
| ACTIVE | ACTIVE | BEACON, TASK, RESULT exchanges |
| ACTIVE | SHUTDOWN | Server sends SHUTDOWN, beacon timeout (3× interval), or protocol error |
| SHUTDOWN | — | Connection closed, session archived |

### Timeouts

| Timeout | Default | Description |
|---|---|---|
| Registration | 10 seconds | Max time from TLS established to REGISTER received |
| First Beacon | 30 seconds | Max time from REGISTERED to first BEACON |
| Beacon Deadline | 3× interval | Agent considered dead if no BEACON received within this window |
| Task Execution | per-task | Set by TASK_TIMEOUT TLV field |

---

## 8. Beacon Interval and Jitter

The agent beacons at a configurable interval with randomized jitter to
avoid deterministic timing patterns.

### Calculation

```
actual_interval = base_interval + random(-jitter_range, +jitter_range)

where:
    jitter_range = base_interval × (jitter_pct / 100)
```

### Example

With `base_interval = 30s` and `jitter_pct = 20`:

```
jitter_range = 30 × 0.20 = 6 seconds
actual_interval = 30 + random(-6, +6)
                = random value in [24, 36] seconds
```

### Defaults

| Parameter | Default | Range |
|---|---|---|
| `base_interval` | 30 seconds | 5–3600 seconds |
| `jitter_pct` | 20% | 0–50% |

The server may override these values in the REGISTER response via the
`BEACON_INTERVAL` (0x0012) and `BEACON_JITTER` (0x0013) TLV fields.

---

## 9. Error Handling

### Protocol Errors

The following conditions are protocol errors that cause the server to close
the connection:

| Error | Description |
|---|---|
| Invalid length prefix | Length is 0 or exceeds 1 MiB |
| Unknown message type | Msg Type is not in {0x01–0x05} |
| Invalid session ID | Session ID does not match any active session (except REGISTER) |
| Sequence violation | Sequence number is not strictly greater than last seen |
| Malformed TLV | TLV field extends beyond the message body |
| Unexpected message | Message type not valid for current session state |

### Agent Recovery

When the connection is lost or closed by the server:

1. The agent waits for the next beacon interval (with jitter)
2. Re-establishes the TLS connection
3. Sends a new REGISTER message (receives a new session ID)
4. Resumes normal beacon loop

---

## 10. Complete Message Layout Example

A fully encoded BEACON message from an agent:

```
Byte offset   Hex              Description
──────────    ──────────────   ─────────────────────────────────
Frame:
0x0000        00 00 00 33      Length prefix: 51 bytes follow
                               
Header:                        
0x0004        02               Msg Type: BEACON (0x02)
0x0005        00               Reserved
0x0006        00 00 00 05      Sequence Number: 5
0x000A        a1 b2 c3 d4      Session ID (16 bytes, UUID)
              e5 f6 a7 b8
              c9 d0 e1 f2
              a3 b4 c5 d6

TLV Field 1 — AGENT_UPTIME:
0x001A        00 20            Type: 0x0020 (AGENT_UPTIME)
0x001C        00 00 00 08      Length: 8 bytes
0x0020        00 00 00 00      Value: 3600 seconds (1 hour)
              00 00 0E 10

TLV Field 2 — TASK_SLOTS:
0x0028        00 21            Type: 0x0021 (TASK_SLOTS)
0x002A        00 00 00 01      Length: 1 byte
0x002E        03               Value: 3 available slots

Total wire size: 4 (frame) + 51 (body) = 55 bytes
```

---

## 11. TLV Type Registry

### Common Types (0x0001–0x000F)

| Type | Name | Value Format |
|---|---|---|
| `0x0001` | HOSTNAME | UTF-8 string |
| `0x0002` | OS_TYPE | UTF-8 string |
| `0x0003` | OS_ARCH | UTF-8 string |
| `0x0004` | OS_VERSION | UTF-8 string |
| `0x0005` | AGENT_VERSION | UTF-8 string |
| `0x0006` | AGENT_PID | uint32 (4 bytes, big-endian) |
| `0x0007` | USERNAME | UTF-8 string |

### Registration Response Types (0x0010–0x001F)

| Type | Name | Value Format |
|---|---|---|
| `0x0010` | SESSION_ID | 16 bytes (UUID v4, raw) |
| `0x0011` | SERVER_TIME | uint64 (8 bytes, big-endian, Unix epoch) |
| `0x0012` | BEACON_INTERVAL | uint32 (4 bytes, big-endian, seconds) |
| `0x0013` | BEACON_JITTER | uint8 (1 byte, percentage 0–100) |

### Beacon Types (0x0020–0x002F)

| Type | Name | Value Format |
|---|---|---|
| `0x0020` | AGENT_UPTIME | uint64 (8 bytes, big-endian, seconds) |
| `0x0021` | TASK_SLOTS | uint8 (1 byte) |

### Task Types (0x0030–0x003F)

| Type | Name | Value Format |
|---|---|---|
| `0x0030` | TASK_ID | 16 bytes (UUID v4, raw) |
| `0x0031` | TASK_TYPE | uint16 (2 bytes, big-endian) |
| `0x0032` | TASK_ARGS | bytes (task-specific) |
| `0x0033` | TASK_TIMEOUT | uint32 (4 bytes, big-endian, seconds) |

### Result Types (0x0040–0x004F)

| Type | Name | Value Format |
|---|---|---|
| `0x0040` | TASK_ID | 16 bytes (UUID v4, raw) |
| `0x0041` | RESULT_STATUS | uint8 (0=OK, 1=error, 2=timeout) |
| `0x0042` | RESULT_DATA | bytes |
| `0x0043` | RESULT_ERROR | UTF-8 string |
| `0x0044` | RESULT_ELAPSED | uint32 (4 bytes, big-endian, milliseconds) |

### Shutdown Types (0x0050–0x005F)

| Type | Name | Value Format |
|---|---|---|
| `0x0050` | SHUTDOWN_REASON | UTF-8 string |

### Reserved Ranges

| Range | Purpose |
|---|---|
| `0x0000` | Invalid / padding |
| `0x0001–0x00FF` | Core protocol fields |
| `0x0100–0x0FFF` | Reserved for future protocol extensions |
| `0x1000–0xFFFE` | Available for custom task payloads |
| `0xFFFF` | Reserved / sentinel |
