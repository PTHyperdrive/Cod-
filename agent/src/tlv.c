/* ==========================================================================
 * tlv.c — Type-Length-Value Codec Implementation
 * ==========================================================================
 * Implements the TLV encoding/decoding functions declared in tlv.h.
 *
 * Wire format for each TLV field:
 *   [Type: 2 bytes BE] [Length: 4 bytes BE] [Value: Length bytes]
 *
 * All multi-byte integers are serialized byte-by-byte in big-endian order.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "tlv.h"

#include <stdlib.h>
#include <string.h>

#include "compat.h"

/* ---- Wire helpers ----------------------------------------------------- */

void tlv_write_u16_be(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val >> 8);
    buf[1] = (uint8_t)(val & 0xFF);
}

void tlv_write_u32_be(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)(val >> 16);
    buf[2] = (uint8_t)(val >>  8);
    buf[3] = (uint8_t)(val & 0xFF);
}

uint16_t tlv_read_u16_be(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
}

uint32_t tlv_read_u32_be(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] <<  8) |
           ((uint32_t)buf[3]);
}

int64_t tlv_read_i64_be(const uint8_t *buf)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 8) | (uint64_t)buf[i];
    }
    return (int64_t)val;
}

/* ---- Internal: write int64 big-endian --------------------------------- */

static void write_i64_be(uint8_t *buf, int64_t val)
{
    uint64_t u = (uint64_t)val;
    for (int i = 7; i >= 0; i--) {
        buf[i] = (uint8_t)(u & 0xFF);
        u >>= 8;
    }
}

/* ---- Buffer management ------------------------------------------------ */

/**
 * Ensure the buffer has at least `needed` bytes of free capacity.
 * Grows by doubling when necessary.
 */
static int ensure_capacity(tlv_buffer_t *buf, size_t needed)
{
    size_t avail = buf->capacity - buf->size;
    if (avail >= needed) {
        return 0;
    }

    size_t new_cap = buf->capacity;
    while (new_cap - buf->size < needed) {
        new_cap = (new_cap == 0) ? 256 : new_cap * 2;
    }

    uint8_t *new_data = (uint8_t *)realloc(buf->data, new_cap);
    if (new_data == NULL) {
        return -1;
    }

    buf->data     = new_data;
    buf->capacity = new_cap;
    return 0;
}

int tlv_buffer_init(tlv_buffer_t *buf, size_t cap)
{
    if (cap == 0) {
        cap = 256;
    }

    buf->data = (uint8_t *)malloc(cap);
    if (buf->data == NULL) {
        buf->size     = 0;
        buf->capacity = 0;
        return -1;
    }

    buf->size     = 0;
    buf->capacity = cap;
    return 0;
}

void tlv_buffer_free(tlv_buffer_t *buf)
{
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->size     = 0;
    buf->capacity = 0;
}

/* ---- Encoding --------------------------------------------------------- */

int tlv_buffer_add(tlv_buffer_t *buf, uint16_t type,
                   uint32_t length, const void *value)
{
    size_t total = TLV_HEADER_SIZE + (size_t)length;

    if (ensure_capacity(buf, total) != 0) {
        return -1;
    }

    uint8_t *dst = buf->data + buf->size;

    /* Type (2 bytes, big-endian) */
    tlv_write_u16_be(dst, type);

    /* Length (4 bytes, big-endian) */
    tlv_write_u32_be(dst + TLV_TYPE_SIZE, length);

    /* Value */
    if (length > 0 && value != NULL) {
        memcpy(dst + TLV_HEADER_SIZE, value, length);
    }

    buf->size += total;
    return 0;
}

int tlv_buffer_add_u16(tlv_buffer_t *buf, uint16_t type, uint16_t val)
{
    uint8_t tmp[2];
    tlv_write_u16_be(tmp, val);
    return tlv_buffer_add(buf, type, 2, tmp);
}

int tlv_buffer_add_u32(tlv_buffer_t *buf, uint16_t type, uint32_t val)
{
    uint8_t tmp[4];
    tlv_write_u32_be(tmp, val);
    return tlv_buffer_add(buf, type, 4, tmp);
}

int tlv_buffer_add_i64(tlv_buffer_t *buf, uint16_t type, int64_t val)
{
    uint8_t tmp[8];
    write_i64_be(tmp, val);
    return tlv_buffer_add(buf, type, 8, tmp);
}

int tlv_buffer_add_str(tlv_buffer_t *buf, uint16_t type, const char *str)
{
    if (str == NULL) {
        return tlv_buffer_add(buf, type, 0, NULL);
    }
    uint32_t len = (uint32_t)strlen(str);
    return tlv_buffer_add(buf, type, len, str);
}

/* ---- Decoding --------------------------------------------------------- */

int tlv_decode(const uint8_t *data, size_t data_len, tlv_field_t *field)
{
    if (data == NULL || field == NULL) {
        return -1;
    }

    /* Need at least the header (type + length = 6 bytes). */
    if (data_len < TLV_HEADER_SIZE) {
        return -1;
    }

    field->type   = tlv_read_u16_be(data);
    field->length = tlv_read_u32_be(data + TLV_TYPE_SIZE);

    /* Ensure the value fits within the available data. */
    if ((size_t)field->length > data_len - TLV_HEADER_SIZE) {
        return -1;
    }

    /* Point value into the input buffer (zero-copy). */
    field->value = (uint8_t *)(data + TLV_HEADER_SIZE);

    return (int)(TLV_HEADER_SIZE + field->length);
}

int tlv_decode_all(const uint8_t *data, size_t data_len,
                   tlv_field_t **fields, size_t *count)
{
    if (fields == NULL || count == NULL) {
        return -1;
    }

    *fields = NULL;
    *count  = 0;

    if (data == NULL || data_len == 0) {
        return 0; /* Empty message — valid but no fields. */
    }

    /* First pass: count the fields. */
    size_t n      = 0;
    size_t offset = 0;
    while (offset < data_len) {
        tlv_field_t tmp;
        int consumed = tlv_decode(data + offset, data_len - offset, &tmp);
        if (consumed < 0) {
            return -1;
        }
        n++;
        offset += (size_t)consumed;
    }

    if (n == 0) {
        return 0;
    }

    /* Allocate the output array. */
    *fields = (tlv_field_t *)calloc(n, sizeof(tlv_field_t));
    if (*fields == NULL) {
        return -1;
    }

    /* Second pass: populate the fields. */
    offset = 0;
    for (size_t i = 0; i < n; i++) {
        int consumed = tlv_decode(data + offset, data_len - offset,
                                  &(*fields)[i]);
        if (consumed < 0) {
            free(*fields);
            *fields = NULL;
            return -1;
        }
        offset += (size_t)consumed;
    }

    *count = n;
    return 0;
}

const tlv_field_t *tlv_find_field(const tlv_field_t *fields, size_t count,
                                  uint16_t type)
{
    if (fields == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if (fields[i].type == type) {
            return &fields[i];
        }
    }

    return NULL;
}
