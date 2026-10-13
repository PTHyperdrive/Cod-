/* ==========================================================================
 * safety.h - Safety Measures Interface
 * ==========================================================================
 * Every safety check MUST pass before the agent operates.  If any check
 * fails, the agent logs the reason and exits immediately.  These are
 * defence-in-depth mechanisms to prevent misuse outside a lab environment.
 *
 * Safety measures:
 *   1. CIDR allowlist    - Server IP must be within LAB_CIDR
 *   2. Build expiry      - Current time must be before BUILD_EXPIRY
 *   3. --lab-agent flag  - CLI flag must be present
 *   4. Sentinel file     - Kill switch file must NOT exist
 *   5. Startup banner    - Visible announcement of agent activity
 *
 * Additional:
 *   - No persistence mechanism (agent does not survive reboot)
 *   - No self-propagation capability
 *   - Visible process name and banner output
 * ========================================================================== */
#ifndef SAFETY_H
#define SAFETY_H

#include <stdint.h>

/**
 * Check that `server_ip` falls within the compiled-in CIDR allowlist.
 * Parses LAB_CIDR (e.g., "10.13.37.0/24") and verifies the server IP.
 * Returns 0 if the IP is within range, -1 otherwise.
 */
int check_cidr_allowlist(const char *server_ip);

/**
 * Check that the current system time is before BUILD_EXPIRY.
 * Returns 0 if the build has not expired, -1 if expired.
 */
int check_build_expiry(void);

/**
 * Check that the --lab-agent flag was passed.
 * `flag_present` should be non-zero if the flag was found in argv.
 * Returns 0 if present, -1 if absent.
 */
int check_lab_agent_flag(int flag_present);

/**
 * Check for the kill switch sentinel file.
 * Returns 0 if the sentinel does NOT exist (safe to continue),
 * -1 if it exists (agent must shut down).
 */
int check_sentinel_file(void);

/**
 * Display the startup banner to stdout and log it via PAL.
 * This ensures the agent's presence is visible to anyone on the system.
 * Always returns 0.
 */
int display_banner(void);

/**
 * Run all pre-flight safety checks.
 * Calls each check in order; returns 0 if all pass, -1 on first failure.
 * `lab_flag` indicates whether --lab-agent was on the command line.
 */
int safety_preflight(int lab_flag);

/**
 * Parse a CIDR string into a network address and prefix length.
 * `cidr` format: "A.B.C.D/N"
 * On success, stores the network address in `*net_addr` and prefix
 * length in `*prefix_len`.  Returns 0 on success, -1 on parse error.
 *
 * Exposed for unit testing.
 */
int parse_cidr(const char *cidr, uint32_t *net_addr, int *prefix_len);

/**
 * Parse a dotted-quad IPv4 address into a uint32 in host byte order.
 * Returns 0 on success, -1 on parse error.
 *
 * Exposed for unit testing.
 */
int parse_ipv4(const char *ip_str, uint32_t *addr);

#endif /* SAFETY_H */
