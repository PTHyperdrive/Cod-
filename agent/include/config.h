/* ==========================================================================
 * config.h - Build-time Configuration
 * ==========================================================================
 * All configuration values are compiled into the binary.  They are set via
 * CMake -D flags and injected as preprocessor defines.  This header provides
 * sensible defaults so that the code compiles even without explicit defines
 * (e.g., during unit testing or IDE indexing).
 *
 * IMPORTANT: These values are intentionally baked in at compile time so that
 * the agent cannot be trivially re-pointed at arbitrary targets.
 * ========================================================================== */
#ifndef CONFIG_H
#define CONFIG_H

/* ---- Agent identity ---------------------------------------------------- */
#ifndef AGENT_NAME
#define AGENT_NAME "lab-c2-agent"
#endif

#ifndef AGENT_VERSION
#define AGENT_VERSION "1.0.0"
#endif

/* ---- Network configuration -------------------------------------------- */
/* SERVER_HOST: IP address of the team server.  Must fall within LAB_CIDR. */
#ifndef SERVER_HOST
#define SERVER_HOST "10.13.37.1"
#endif

#ifndef SERVER_PORT
#define SERVER_PORT 443
#endif

/* ---- Safety: CIDR allowlist ------------------------------------------- */
/* LAB_CIDR: Only IPs within this range are valid targets.  The agent will
 * refuse to connect to any server outside this prefix.  Format: "A.B.C.D/N" */
#ifndef LAB_CIDR
#define LAB_CIDR "10.13.37.0/24"
#endif

/* ---- Safety: build expiry --------------------------------------------- */
/* BUILD_EXPIRY: Unix timestamp after which the agent refuses to run.
 * Default is 0 which means "always expired" - forces the builder to set it. */
#ifndef BUILD_EXPIRY
#define BUILD_EXPIRY 0
#endif

/* ---- Beacon timing ---------------------------------------------------- */
/* BEACON_INTERVAL: seconds between heartbeat beacons to the team server.   */
#ifndef BEACON_INTERVAL
#define BEACON_INTERVAL 30
#endif

/* BEACON_JITTER: percentage (0-100) of random jitter applied to the
 * interval so that beacons are not perfectly periodic.                      */
#ifndef BEACON_JITTER
#define BEACON_JITTER 20
#endif

/* ---- Kill switch sentinel --------------------------------------------- */
/* The agent checks for this file before each beacon.  If the file exists,
 * the agent shuts down immediately.  This is the kill switch mechanism.     */
#ifndef SENTINEL_PATH_LINUX
#define SENTINEL_PATH_LINUX "/tmp/.lab-c2-stop"
#endif

#ifndef SENTINEL_PATH_WIN32
#define SENTINEL_PATH_WIN32 "C:\\Temp\\.lab-c2-stop"
#endif

/* ---- Protocol constants ----------------------------------------------- */
/* Length-prefix size: 4 bytes, big-endian, prefixed to every TLV message.  */
#define LENGTH_PREFIX_SIZE 4

/* Maximum message size: 10 MiB.  Prevents memory exhaustion from malformed
 * length prefixes.                                                          */
#define MAX_MESSAGE_SIZE (10 * 1024 * 1024)

/* Maximum TLV value size: 8 MiB.  Individual TLV fields cannot exceed this. */
#define MAX_TLV_VALUE_SIZE (8 * 1024 * 1024)

/* ---- Capability output limits ----------------------------------------- */
/* Maximum output buffer for process execution (stdout + stderr).           */
#define MAX_EXEC_OUTPUT (1 * 1024 * 1024)

/* Maximum file size for upload/download operations.                        */
#define MAX_FILE_SIZE (8 * 1024 * 1024)

/* ---- Banner ----------------------------------------------------------- */
#define AGENT_BANNER \
    "=======================================================\n" \
    "  " AGENT_NAME " v" AGENT_VERSION "\n" \
    "  ACADEMIC/LAB USE ONLY - NOT FOR UNAUTHORIZED ACCESS\n"  \
    "  Target scope: " LAB_CIDR "\n" \
    "  Server: " SERVER_HOST "\n" \
    "=======================================================\n"

#endif /* CONFIG_H */
