/* ==========================================================================
 * test_tlv.c — TLV Codec Unit Tests
 * ==========================================================================
 * Tests the TLV encoding/decoding functions:
 *   - Wire helpers (big-endian read/write)
 *   - Buffer init, add, free
 *   - Single field encode/decode round-trip
 *   - Multi-field encode/decode
 *   - Edge cases (empty value, max field, truncated data)
 *   - Field search
 *
 * Uses a minimal test harness (no external dependencies).
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "tlv.h"

#include <stdio.h>
#include <stdlib.h>
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

#define ASSERT_NULL(ptr, msg)   ASSERT_TRUE((ptr) == NULL, msg)
#define ASSERT_NOT_NULL(ptr, msg) ASSERT_TRUE((ptr) != NULL, msg)

#define TEST(name) static void name(void)
#define RUN_TEST(name)                                                      \
    do {                                                                    \
        printf("  Running: %s\n", #name);                                   \
        name();                                                             \
    } while (0)

/* ---- Tests: wire helpers ---------------------------------------------- */

TEST(test_write_read_u16)
{
    uint8_t buf[2];
    tlv_write_u16_be(buf, 0x1234);
    ASSERT_EQ(buf[0], 0x12, "u16 high byte");
    ASSERT_EQ(buf[1], 0x34, "u16 low byte");
    ASSERT_EQ(tlv_read_u16_be(buf), 0x1234, "u16 round-trip");
}

TEST(test_write_read_u32)
{
    uint8_t buf[4];
    tlv_write_u32_be(buf, 0xDEADBEEF);
    ASSERT_EQ(buf[0], 0xDE, "u32 byte 0");
    ASSERT_EQ(buf[1], 0xAD, "u32 byte 1");
    ASSERT_EQ(buf[2], 0xBE, "u32 byte 2");
    ASSERT_EQ(buf[3], 0xEF, "u32 byte 3");
    ASSERT_EQ(tlv_read_u32_be(buf), 0xDEADBEEF, "u32 round-trip");
}

TEST(test_read_i64)
{
    /* 0x0000000000000001 = 1 */
    uint8_t buf[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    ASSERT_EQ(tlv_read_i64_be(buf), 1, "i64 value=1");

    /* 0x00000000FFFFFFFF = 4294967295 */
    uint8_t buf2[8] = {0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF};
    ASSERT_EQ(tlv_read_i64_be(buf2), 4294967295LL, "i64 value=4294967295");
}

TEST(test_u16_boundary)
{
    uint8_t buf[2];
    tlv_write_u16_be(buf, 0);
    ASSERT_EQ(tlv_read_u16_be(buf), 0, "u16 zero");

    tlv_write_u16_be(buf, 0xFFFF);
    ASSERT_EQ(tlv_read_u16_be(buf), 0xFFFF, "u16 max");
}

TEST(test_u32_boundary)
{
    uint8_t buf[4];
    tlv_write_u32_be(buf, 0);
    ASSERT_EQ(tlv_read_u32_be(buf), 0, "u32 zero");

    tlv_write_u32_be(buf, 0xFFFFFFFF);
    ASSERT_EQ(tlv_read_u32_be(buf), 0xFFFFFFFF, "u32 max");
}

/* ---- Tests: buffer operations ----------------------------------------- */

TEST(test_buffer_init_free)
{
    tlv_buffer_t buf;
    ASSERT_EQ(tlv_buffer_init(&buf, 128), 0, "buffer init");
    ASSERT_NOT_NULL(buf.data, "buffer data not null");
    ASSERT_EQ(buf.size, 0, "buffer size == 0");
    ASSERT_TRUE(buf.capacity >= 128, "buffer capacity >= 128");
    tlv_buffer_free(&buf);
    ASSERT_NULL(buf.data, "buffer freed");
}

TEST(test_buffer_init_default)
{
    tlv_buffer_t buf;
    ASSERT_EQ(tlv_buffer_init(&buf, 0), 0, "buffer init default");
    ASSERT_TRUE(buf.capacity > 0, "default capacity > 0");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_raw)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);

    uint8_t data[] = {0x41, 0x42, 0x43}; /* "ABC" */
    ASSERT_EQ(tlv_buffer_add(&buf, 0x0011, 3, data), 0, "add raw field");

    /* Expected: type(2) + length(4) + value(3) = 9 bytes */
    ASSERT_EQ(buf.size, 9, "buffer size after add");

    /* Check type. */
    ASSERT_EQ(tlv_read_u16_be(buf.data), 0x0011, "field type");

    /* Check length. */
    ASSERT_EQ(tlv_read_u32_be(buf.data + 2), 3, "field length");

    /* Check value. */
    ASSERT_EQ(buf.data[6], 0x41, "value byte 0");
    ASSERT_EQ(buf.data[7], 0x42, "value byte 1");
    ASSERT_EQ(buf.data[8], 0x43, "value byte 2");

    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_u16)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    ASSERT_EQ(tlv_buffer_add_u16(&buf, 0x0021, 0xBEEF), 0, "add u16");
    ASSERT_EQ(buf.size, TLV_HEADER_SIZE + 2, "u16 total size");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_u32)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    ASSERT_EQ(tlv_buffer_add_u32(&buf, 0x0022, 42), 0, "add u32");
    ASSERT_EQ(buf.size, TLV_HEADER_SIZE + 4, "u32 total size");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_i64)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    ASSERT_EQ(tlv_buffer_add_i64(&buf, 0x0003, 1700000000LL), 0, "add i64");
    ASSERT_EQ(buf.size, TLV_HEADER_SIZE + 8, "i64 total size");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_str)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    ASSERT_EQ(tlv_buffer_add_str(&buf, 0x0011, "hello"), 0, "add string");
    ASSERT_EQ(buf.size, TLV_HEADER_SIZE + 5, "string total size");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_empty_str)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    ASSERT_EQ(tlv_buffer_add_str(&buf, 0x0011, ""), 0, "add empty string");
    ASSERT_EQ(buf.size, TLV_HEADER_SIZE + 0, "empty string total size");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_add_null_str)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    ASSERT_EQ(tlv_buffer_add_str(&buf, 0x0011, NULL), 0, "add NULL string");
    ASSERT_EQ(buf.size, TLV_HEADER_SIZE + 0, "null string total size");
    tlv_buffer_free(&buf);
}

TEST(test_buffer_growth)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 16); /* Start small. */

    /* Add enough data to force multiple growths. */
    char big_str[200];
    memset(big_str, 'X', sizeof(big_str) - 1);
    big_str[sizeof(big_str) - 1] = '\0';

    ASSERT_EQ(tlv_buffer_add_str(&buf, 0x0011, big_str), 0, "add big string");
    ASSERT_TRUE(buf.capacity >= buf.size, "capacity >= size after growth");
    tlv_buffer_free(&buf);
}

/* ---- Tests: decode ---------------------------------------------------- */

TEST(test_decode_single)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 64);
    tlv_buffer_add_str(&buf, TLV_HOSTNAME, "testhost");

    tlv_field_t field;
    int consumed = tlv_decode(buf.data, buf.size, &field);

    ASSERT_TRUE(consumed > 0, "decode consumed > 0");
    ASSERT_EQ(field.type, TLV_HOSTNAME, "decoded type");
    ASSERT_EQ(field.length, 8, "decoded length");
    ASSERT_TRUE(memcmp(field.value, "testhost", 8) == 0, "decoded value");

    tlv_buffer_free(&buf);
}

TEST(test_decode_all_multiple)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 256);
    tlv_buffer_add_str(&buf, TLV_HOSTNAME, "myhost");
    tlv_buffer_add_u32(&buf, TLV_SEQUENCE, 42);
    tlv_buffer_add_str(&buf, TLV_ARCH, "x86_64");

    tlv_field_t *fields = NULL;
    size_t count = 0;

    ASSERT_EQ(tlv_decode_all(buf.data, buf.size, &fields, &count), 0,
              "decode_all success");
    ASSERT_EQ(count, 3, "decoded 3 fields");
    ASSERT_NOT_NULL(fields, "fields not null");

    ASSERT_EQ(fields[0].type, TLV_HOSTNAME, "field 0 type");
    ASSERT_EQ(fields[1].type, TLV_SEQUENCE, "field 1 type");
    ASSERT_EQ(fields[2].type, TLV_ARCH, "field 2 type");

    free(fields);
    tlv_buffer_free(&buf);
}

TEST(test_decode_empty)
{
    tlv_field_t *fields = NULL;
    size_t count = 0;

    ASSERT_EQ(tlv_decode_all(NULL, 0, &fields, &count), 0,
              "decode_all empty");
    ASSERT_EQ(count, 0, "count == 0 for empty");
    ASSERT_NULL(fields, "fields null for empty");
}

TEST(test_decode_truncated_header)
{
    uint8_t short_data[4] = {0x00, 0x11, 0x00, 0x00}; /* Only 4 bytes. */
    tlv_field_t field;
    ASSERT_EQ(tlv_decode(short_data, 4, &field), -1,
              "truncated header returns -1");
}

TEST(test_decode_overflow)
{
    /* Header claiming 100 bytes of value, but only 2 bytes follow. */
    uint8_t data[8];
    tlv_write_u16_be(data, 0x0011);
    tlv_write_u32_be(data + 2, 100);
    data[6] = 0x41;
    data[7] = 0x42;

    tlv_field_t field;
    ASSERT_EQ(tlv_decode(data, 8, &field), -1, "overflow returns -1");
}

/* ---- Tests: find_field ------------------------------------------------ */

TEST(test_find_field)
{
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 256);
    tlv_buffer_add_str(&buf, TLV_HOSTNAME, "host1");
    tlv_buffer_add_u32(&buf, TLV_SEQUENCE, 7);
    tlv_buffer_add_str(&buf, TLV_ARCH, "arm");

    tlv_field_t *fields = NULL;
    size_t count = 0;
    tlv_decode_all(buf.data, buf.size, &fields, &count);

    const tlv_field_t *found = tlv_find_field(fields, count, TLV_SEQUENCE);
    ASSERT_NOT_NULL(found, "found SEQUENCE");
    ASSERT_EQ(tlv_read_u32_be(found->value), 7, "SEQUENCE value");

    const tlv_field_t *missing = tlv_find_field(fields, count, 0xFFFF);
    ASSERT_NULL(missing, "missing field is NULL");

    const tlv_field_t *null_search = tlv_find_field(NULL, 0, TLV_HOSTNAME);
    ASSERT_NULL(null_search, "null fields returns NULL");

    free(fields);
    tlv_buffer_free(&buf);
}

/* ---- Tests: round-trip ------------------------------------------------ */

TEST(test_round_trip_multi)
{
    /* Encode multiple fields. */
    tlv_buffer_t buf;
    tlv_buffer_init(&buf, 512);
    tlv_buffer_add_u16(&buf, TLV_MSG_TYPE, MSG_REGISTER);
    tlv_buffer_add_u32(&buf, TLV_SEQUENCE, 1);
    tlv_buffer_add_str(&buf, TLV_HOSTNAME, "lab-victim");
    tlv_buffer_add_str(&buf, TLV_OS_INFO, "Linux 5.15");
    tlv_buffer_add_str(&buf, TLV_ARCH, "x86_64");
    tlv_buffer_add_str(&buf, TLV_AGENT_NAME, "lab-c2-agent");
    tlv_buffer_add_str(&buf, TLV_AGENT_VERSION, "1.0.0");

    /* Decode. */
    tlv_field_t *fields = NULL;
    size_t count = 0;
    ASSERT_EQ(tlv_decode_all(buf.data, buf.size, &fields, &count), 0,
              "round-trip decode");
    ASSERT_EQ(count, 7, "round-trip field count");

    /* Verify message type. */
    const tlv_field_t *mt = tlv_find_field(fields, count, TLV_MSG_TYPE);
    ASSERT_NOT_NULL(mt, "MSG_TYPE found");
    ASSERT_EQ(tlv_read_u16_be(mt->value), MSG_REGISTER, "MSG_TYPE value");

    /* Verify hostname. */
    const tlv_field_t *hn = tlv_find_field(fields, count, TLV_HOSTNAME);
    ASSERT_NOT_NULL(hn, "HOSTNAME found");
    ASSERT_EQ(hn->length, 10, "HOSTNAME length");
    ASSERT_TRUE(memcmp(hn->value, "lab-victim", 10) == 0, "HOSTNAME value");

    free(fields);
    tlv_buffer_free(&buf);
}

/* ---- Main ------------------------------------------------------------- */

int main(void)
{
    printf("=== TLV Codec Unit Tests ===\n\n");

    /* Wire helpers */
    RUN_TEST(test_write_read_u16);
    RUN_TEST(test_write_read_u32);
    RUN_TEST(test_read_i64);
    RUN_TEST(test_u16_boundary);
    RUN_TEST(test_u32_boundary);

    /* Buffer operations */
    RUN_TEST(test_buffer_init_free);
    RUN_TEST(test_buffer_init_default);
    RUN_TEST(test_buffer_add_raw);
    RUN_TEST(test_buffer_add_u16);
    RUN_TEST(test_buffer_add_u32);
    RUN_TEST(test_buffer_add_i64);
    RUN_TEST(test_buffer_add_str);
    RUN_TEST(test_buffer_add_empty_str);
    RUN_TEST(test_buffer_add_null_str);
    RUN_TEST(test_buffer_growth);

    /* Decode */
    RUN_TEST(test_decode_single);
    RUN_TEST(test_decode_all_multiple);
    RUN_TEST(test_decode_empty);
    RUN_TEST(test_decode_truncated_header);
    RUN_TEST(test_decode_overflow);

    /* Find field */
    RUN_TEST(test_find_field);

    /* Round-trip */
    RUN_TEST(test_round_trip_multi);

    /* Summary */
    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf(" (%d FAILED)", tests_failed);
    }
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
