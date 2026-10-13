/* ==========================================================================
 * test_safety.c — Safety Mechanism Unit Tests
 * ==========================================================================
 * Tests the safety check functions:
 *   - IPv4 address parsing
 *   - CIDR parsing and masking
 *   - CIDR allowlist verification
 *   - Build expiry check
 *   - --lab-agent flag check
 *   - Sentinel file (kill switch) check
 *
 * Uses a minimal test harness (no external dependencies).
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "safety.h"
#include "config.h"

#include <stdio.h>
#include <string.h>

/* ---- Minimal test harness --------------------------------------------- */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(actual, expected, msg)                                    \
    do {                                                                    \
        tests_run++;                                                        \
        if ((actual) == (expected)) {                                       \
            tests_passed++;                                                 \
        } else {                                                            \
            tests_failed++;                                                 \
            printf("  FAIL [%s:%d] %s: expected %lld, got %lld\n",          \
                   __FILE__, __LINE__, (msg),                               \
                   (long long)(expected), (long long)(actual));             \
        }                                                                   \
    } while (0)

#define ASSERT_TRUE(cond, msg)                                              \
    do {                                                                    \
        tests_run++;                                                        \
        if (cond) {                                                         \
            tests_passed++;                                                 \
        } else {                                                            \
            tests_failed++;                                                 \
            printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, (msg));       \
        }                                                                   \
    } while (0)

#define TEST(name) static void name(void)
#define RUN_TEST(name)                                                      \
    do {                                                                    \
        printf("  Running: %s\n", #name);                                   \
        name();                                                             \
    } while (0)

/* ---- Tests: IPv4 parsing ---------------------------------------------- */

TEST(test_parse_ipv4_valid)
{
    uint32_t addr;

    ASSERT_EQ(parse_ipv4("10.13.37.1", &addr), 0, "parse 10.13.37.1");
    ASSERT_EQ(addr, (uint32_t)((10 << 24) | (13 << 16) | (37 << 8) | 1),
              "10.13.37.1 value");

    ASSERT_EQ(parse_ipv4("192.168.1.100", &addr), 0, "parse 192.168.1.100");
    ASSERT_EQ(addr, (uint32_t)((192 << 24) | (168 << 16) | (1 << 8) | 100),
              "192.168.1.100 value");

    ASSERT_EQ(parse_ipv4("0.0.0.0", &addr), 0, "parse 0.0.0.0");
    ASSERT_EQ(addr, 0, "0.0.0.0 value");

    ASSERT_EQ(parse_ipv4("255.255.255.255", &addr), 0,
              "parse 255.255.255.255");
    ASSERT_EQ(addr, 0xFFFFFFFF, "255.255.255.255 value");
}

TEST(test_parse_ipv4_invalid)
{
    uint32_t addr;

    ASSERT_EQ(parse_ipv4(NULL, &addr), -1, "NULL ip");
    ASSERT_EQ(parse_ipv4("", &addr), -1, "empty ip");
    ASSERT_EQ(parse_ipv4("not-an-ip", &addr), -1, "non-numeric");
    ASSERT_EQ(parse_ipv4("256.1.1.1", &addr), -1, "octet > 255");
    ASSERT_EQ(parse_ipv4("1.2.3", &addr), -1, "too few octets");
    ASSERT_EQ(parse_ipv4("1.2.3.4.5", &addr), -1, "too many octets");
}

/* ---- Tests: CIDR parsing ---------------------------------------------- */

TEST(test_parse_cidr_valid)
{
    uint32_t net;
    int plen;

    ASSERT_EQ(parse_cidr("10.13.37.0/24", &net, &plen), 0,
              "parse 10.13.37.0/24");
    ASSERT_EQ(plen, 24, "prefix len 24");
    /* net should be 10.13.37.0 with host bits masked */
    ASSERT_EQ(net, (uint32_t)((10 << 24) | (13 << 16) | (37 << 8)),
              "10.13.37.0 net addr");

    ASSERT_EQ(parse_cidr("192.168.0.0/16", &net, &plen), 0,
              "parse 192.168.0.0/16");
    ASSERT_EQ(plen, 16, "prefix len 16");

    ASSERT_EQ(parse_cidr("0.0.0.0/0", &net, &plen), 0,
              "parse 0.0.0.0/0");
    ASSERT_EQ(plen, 0, "prefix len 0");
    ASSERT_EQ(net, 0, "0.0.0.0/0 net addr");

    ASSERT_EQ(parse_cidr("10.0.0.1/32", &net, &plen), 0,
              "parse 10.0.0.1/32");
    ASSERT_EQ(plen, 32, "prefix len 32");
}

TEST(test_parse_cidr_invalid)
{
    uint32_t net;
    int plen;

    ASSERT_EQ(parse_cidr(NULL, &net, &plen), -1, "NULL cidr");
    ASSERT_EQ(parse_cidr("", &net, &plen), -1, "empty cidr");
    ASSERT_EQ(parse_cidr("10.0.0.0", &net, &plen), -1, "no slash");
    ASSERT_EQ(parse_cidr("/24", &net, &plen), -1, "no ip");
    ASSERT_EQ(parse_cidr("10.0.0.0/33", &net, &plen), -1, "prefix > 32");
    ASSERT_EQ(parse_cidr("10.0.0.0/-1", &net, &plen), -1, "prefix < 0");
}

/* ---- Tests: CIDR allowlist -------------------------------------------- */

TEST(test_cidr_allowlist)
{
    /* 10.13.37.1 should be within 10.13.37.0/24 (compiled-in default). */
    ASSERT_EQ(check_cidr_allowlist("10.13.37.1"), 0, "10.13.37.1 in range");
    ASSERT_EQ(check_cidr_allowlist("10.13.37.254"), 0,
              "10.13.37.254 in range");

    /* Out of range. */
    ASSERT_EQ(check_cidr_allowlist("10.13.38.1"), -1,
              "10.13.38.1 out of range");
    ASSERT_EQ(check_cidr_allowlist("192.168.1.1"), -1,
              "192.168.1.1 out of range");

    /* Invalid. */
    ASSERT_EQ(check_cidr_allowlist(NULL), -1, "NULL server ip");
    ASSERT_EQ(check_cidr_allowlist("not-an-ip"), -1, "invalid ip");
}

/* ---- Tests: --lab-agent flag ------------------------------------------ */

TEST(test_lab_agent_flag)
{
    ASSERT_EQ(check_lab_agent_flag(1), 0, "flag present");
    ASSERT_EQ(check_lab_agent_flag(0), -1, "flag absent");
}

/* ---- Tests: sentinel file --------------------------------------------- */

TEST(test_sentinel_nonexistent)
{
    /* Assuming /tmp/.lab-c2-stop doesn't exist during tests. */
    /* We can't create it because that would affect the test host,
     * so we just test that the check returns 0 (no kill switch). */
    ASSERT_EQ(check_sentinel_file(), 0, "no sentinel file");
}

/* ---- Main ------------------------------------------------------------- */

int main(void)
{
    printf("=== Safety Mechanism Unit Tests ===\n\n");

    /* IPv4 parsing */
    RUN_TEST(test_parse_ipv4_valid);
    RUN_TEST(test_parse_ipv4_invalid);

    /* CIDR parsing */
    RUN_TEST(test_parse_cidr_valid);
    RUN_TEST(test_parse_cidr_invalid);

    /* CIDR allowlist */
    RUN_TEST(test_cidr_allowlist);

    /* --lab-agent flag */
    RUN_TEST(test_lab_agent_flag);

    /* Sentinel file */
    RUN_TEST(test_sentinel_nonexistent);

    /* Summary */
    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(" (%d FAILED)", tests_failed);
    }
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
