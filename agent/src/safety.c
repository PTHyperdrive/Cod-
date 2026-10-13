/* ==========================================================================
 * safety.c — Safety Measures Implementation
 * ==========================================================================
 * Implements all compile-time safety checks that prevent the agent from
 * operating outside a controlled lab environment.
 *
 * Checks (all must pass before the agent operates):
 *   1. CIDR allowlist    — Server IP must be within LAB_CIDR
 *   2. Build expiry      — Current time must be before BUILD_EXPIRY
 *   3. --lab-agent flag  — CLI flag must be present
 *   4. Sentinel file     — Kill switch file must NOT exist
 *   5. Startup banner    — Visible announcement of agent activity
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "safety.h"
#include "config.h"
#include "pal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- IPv4 parsing ----------------------------------------------------- */

int parse_ipv4(const char *ip_str, uint32_t *addr)
{
    if (ip_str == NULL || addr == NULL) {
        return -1;
    }

    unsigned int a, b, c, d;
    char trailing;

    /* sscanf with %c at the end catches trailing junk like "1.2.3.4x". */
    int n = sscanf(ip_str, "%u.%u.%u.%u%c", &a, &b, &c, &d, &trailing);
    if (n != 4) {
        return -1;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return -1;
    }

    *addr = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

/* ---- CIDR parsing ----------------------------------------------------- */

int parse_cidr(const char *cidr, uint32_t *net_addr, int *prefix_len)
{
    if (cidr == NULL || net_addr == NULL || prefix_len == NULL) {
        return -1;
    }

    /* Find the '/' separator. */
    const char *slash = strchr(cidr, '/');
    if (slash == NULL || slash == cidr) {
        return -1;
    }

    /* Parse prefix length. */
    char *end = NULL;
    long plen = strtol(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0') {
        return -1;
    }
    if (plen < 0 || plen > 32) {
        return -1;
    }

    /* Extract and parse the IP portion. */
    size_t ip_len = (size_t)(slash - cidr);
    if (ip_len >= 16) { /* max IPv4 string is 15 chars */
        return -1;
    }

    char ip_buf[16];
    memcpy(ip_buf, cidr, ip_len);
    ip_buf[ip_len] = '\0';

    if (parse_ipv4(ip_buf, net_addr) != 0) {
        return -1;
    }

    *prefix_len = (int)plen;

    /* Mask off host bits. */
    if (*prefix_len < 32) {
        uint32_t mask = 0xFFFFFFFF << (32 - *prefix_len);
        *net_addr &= mask;
    }

    return 0;
}

/* ---- Safety check: CIDR allowlist ------------------------------------- */

int check_cidr_allowlist(const char *server_ip)
{
    if (server_ip == NULL) {
        fprintf(stderr, "[SAFETY] Server IP is NULL.\n");
        return -1;
    }

    uint32_t ip_addr;
    if (parse_ipv4(server_ip, &ip_addr) != 0) {
        fprintf(stderr, "[SAFETY] Failed to parse server IP: %s\n", server_ip);
        return -1;
    }

    uint32_t net_addr;
    int prefix_len;
    if (parse_cidr(LAB_CIDR, &net_addr, &prefix_len) != 0) {
        fprintf(stderr, "[SAFETY] Failed to parse CIDR: %s\n", LAB_CIDR);
        return -1;
    }

    /* Build the mask and compare. */
    uint32_t mask = 0;
    if (prefix_len > 0) {
        mask = 0xFFFFFFFF << (32 - prefix_len);
    }

    if ((ip_addr & mask) != (net_addr & mask)) {
        fprintf(stderr, "[SAFETY] Server IP %s is outside allowed CIDR %s.\n",
                server_ip, LAB_CIDR);
        return -1;
    }

    return 0;
}

/* ---- Safety check: build expiry --------------------------------------- */

int check_build_expiry(void)
{
    int64_t now = pal_time_unix();

    if (BUILD_EXPIRY == 0) {
        fprintf(stderr, "[SAFETY] BUILD_EXPIRY not set (0).  Agent expired.\n");
        return -1;
    }

    if (now > (int64_t)BUILD_EXPIRY) {
        fprintf(stderr,
                "[SAFETY] Build expired.  Current time: %lld, expiry: %lld\n",
                (long long)now, (long long)BUILD_EXPIRY);
        return -1;
    }

    return 0;
}

/* ---- Safety check: --lab-agent flag ----------------------------------- */

int check_lab_agent_flag(int flag_present)
{
    if (!flag_present) {
        fprintf(stderr,
                "=============================================================\n"
                "  SAFETY NOTICE\n"
                "=============================================================\n"
                "  This is an ACADEMIC C2 agent for LAB USE ONLY.\n"
                "  To run, you MUST pass the --lab-agent flag.\n"
                "\n"
                "  Usage:  ./code_agent --lab-agent\n"
                "\n"
                "  Unauthorized use of offensive security tools may violate\n"
                "  laws in your jurisdiction.\n"
                "=============================================================\n");
        return -1;
    }
    return 0;
}

/* ---- Safety check: sentinel / kill switch ----------------------------- */

int check_sentinel_file(void)
{
    const char *path;

#ifdef _WIN32
    path = SENTINEL_PATH_WIN32;
#else
    path = SENTINEL_PATH_LINUX;
#endif

    if (pal_check_sentinel(path)) {
        fprintf(stderr, "[SAFETY] Kill switch file detected: %s\n", path);
        fprintf(stderr, "[SAFETY] Shutting down immediately.\n");
        return -1;
    }

    return 0;
}

/* ---- Banner display --------------------------------------------------- */

int display_banner(void)
{
    printf("%s", AGENT_BANNER);
    pal_log("Agent started: %s v%s", AGENT_NAME, AGENT_VERSION);
    return 0;
}

/* ---- Pre-flight: run all checks --------------------------------------- */

int safety_preflight(int lab_flag)
{
    /* 1. Check --lab-agent flag. */
    if (check_lab_agent_flag(lab_flag) != 0) {
        return -1;
    }

    /* 2. Check build expiry. */
    if (check_build_expiry() != 0) {
        return -1;
    }

    /* 3. Check CIDR allowlist for the configured server. */
    if (check_cidr_allowlist(SERVER_HOST) != 0) {
        return -1;
    }

    /* 4. Check kill switch sentinel file. */
    if (check_sentinel_file() != 0) {
        return -1;
    }

    /* 5. Display the startup banner. */
    display_banner();

    return 0;
}
