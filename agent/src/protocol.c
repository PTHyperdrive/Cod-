/* ==========================================================================
 * protocol.c — Protocol State Machine & TLS I/O
 * ==========================================================================
 * Manages the connection lifecycle (INIT → REGISTERED → ACTIVE → SHUTDOWN)
 * and provides framed message I/O over TLS using mbedTLS.
 *
 * Wire framing:
 *   [4-byte big-endian length prefix] [TLV body]
 *
 * In the current lab build (without mbedTLS compiled in), we fall back to
 * raw TCP sockets via PAL.  When mbedTLS is available, the TLS handshake
 * and I/O are routed through mbedtls_ssl_read/write.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "protocol.h"
#include "config.h"
#include "pal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

/* ---- Lifecycle -------------------------------------------------------- */

void proto_init(proto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(proto_ctx_t));
    ctx->state   = STATE_INIT;
    ctx->seq_num = 0;
    ctx->sock    = -1;
}

int proto_connect(proto_ctx_t *ctx, const char *host, uint16_t port)
{
    if (ctx == NULL || host == NULL) {
        return -1;
    }

    if (ctx->state != STATE_INIT) {
        fprintf(stderr, "[proto] Cannot connect: state is not INIT.\n");
        return -1;
    }

    /* Create a TCP socket via PAL. */
    ctx->sock = pal_socket_create();
    if (ctx->sock < 0) {
        fprintf(stderr, "[proto] Failed to create socket.\n");
        return -1;
    }

    /* Connect to the server. */
    if (pal_socket_connect(ctx->sock, host, port) != 0) {
        fprintf(stderr, "[proto] Failed to connect to %s:%u.\n", host, port);
        pal_socket_close(ctx->sock);
        ctx->sock = -1;
        return -1;
    }

    pal_log("Connected to %s:%u", host, port);

    /*
     * TLS handshake would happen here using mbedTLS.
     * In the current lab build without mbedTLS linked, we operate over
     * raw TCP.  The production build adds:
     *   mbedtls_ssl_setup()
     *   mbedtls_ssl_set_hostname()
     *   mbedtls_ssl_handshake()
     * and routes all I/O through mbedtls_ssl_read/write.
     */

    return 0;
}

void proto_disconnect(proto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /*
     * If TLS is active, close the SSL session:
     *   mbedtls_ssl_close_notify()
     *   mbedtls_ssl_free()
     *   mbedtls_ssl_config_free()
     *   mbedtls_ctr_drbg_free()
     *   mbedtls_entropy_free()
     *   mbedtls_x509_crt_free()
     */

    if (ctx->sock >= 0) {
        pal_socket_close(ctx->sock);
        ctx->sock = -1;
    }

    ctx->state = STATE_SHUTDOWN;
    pal_log("Disconnected.");
}

/* ---- State transitions ------------------------------------------------ */

int proto_transition(proto_ctx_t *ctx, proto_state_t new_state)
{
    if (ctx == NULL) {
        return -1;
    }

    /* Any state can transition to SHUTDOWN. */
    if (new_state == STATE_SHUTDOWN) {
        ctx->state = new_state;
        return 0;
    }

    switch (ctx->state) {
    case STATE_INIT:
        if (new_state == STATE_REGISTERED) {
            ctx->state = new_state;
            return 0;
        }
        break;

    case STATE_REGISTERED:
        if (new_state == STATE_ACTIVE) {
            ctx->state = new_state;
            return 0;
        }
        break;

    case STATE_ACTIVE:
        if (new_state == STATE_ACTIVE) {
            return 0; /* Self-loop is valid. */
        }
        break;

    case STATE_SHUTDOWN:
        /* Terminal state — no transitions out. */
        break;
    }

    fprintf(stderr, "[proto] Invalid transition: %d → %d\n",
            (int)ctx->state, (int)new_state);
    return -1;
}

proto_state_t proto_get_state(const proto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return STATE_SHUTDOWN;
    }
    return ctx->state;
}

/* ---- Low-level I/O (TLS or raw TCP) ----------------------------------- */

/**
 * Send exactly `len` bytes over the connection.
 * Routes through mbedTLS if active, otherwise raw TCP.
 */
static int proto_raw_send(proto_ctx_t *ctx, const uint8_t *data, size_t len)
{
    /*
     * If ctx->tls_ssl is non-NULL, use:
     *   mbedtls_ssl_write((mbedtls_ssl_context *)ctx->tls_ssl, data, len)
     * For the lab build, use raw PAL sockets:
     */
    return pal_socket_send(ctx->sock, data, len);
}

/**
 * Receive exactly `len` bytes from the connection.
 */
static int proto_raw_recv(proto_ctx_t *ctx, uint8_t *data, size_t len)
{
    /*
     * If ctx->tls_ssl is non-NULL, use:
     *   mbedtls_ssl_read((mbedtls_ssl_context *)ctx->tls_ssl, data, len)
     * For the lab build, use raw PAL sockets:
     */
    return pal_socket_recv(ctx->sock, data, len);
}

/* ---- Framed message I/O ----------------------------------------------- */

int proto_send(proto_ctx_t *ctx, const tlv_buffer_t *msg)
{
    if (ctx == NULL || msg == NULL) {
        return -1;
    }

    if (msg->size > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[proto] Message too large: %zu bytes.\n", msg->size);
        return -1;
    }

    /* Send the 4-byte big-endian length prefix. */
    uint8_t prefix[LENGTH_PREFIX_SIZE];
    tlv_write_u32_be(prefix, (uint32_t)msg->size);

    if (proto_raw_send(ctx, prefix, LENGTH_PREFIX_SIZE) != 0) {
        fprintf(stderr, "[proto] Failed to send length prefix.\n");
        return -1;
    }

    /* Send the TLV body. */
    if (msg->size > 0) {
        if (proto_raw_send(ctx, msg->data, msg->size) != 0) {
            fprintf(stderr, "[proto] Failed to send message body.\n");
            return -1;
        }
    }

    /* Increment sequence number. */
    ctx->seq_num++;

    return 0;
}

int proto_recv(proto_ctx_t *ctx, uint8_t **out_data, size_t *out_len)
{
    if (ctx == NULL || out_data == NULL || out_len == NULL) {
        return -1;
    }

    *out_data = NULL;
    *out_len  = 0;

    /* Read the 4-byte length prefix. */
    uint8_t prefix[LENGTH_PREFIX_SIZE];
    if (proto_raw_recv(ctx, prefix, LENGTH_PREFIX_SIZE) != 0) {
        return -1;
    }

    uint32_t body_len = tlv_read_u32_be(prefix);

    /* Validate length. */
    if (body_len == 0) {
        fprintf(stderr, "[proto] Received empty message.\n");
        return -1;
    }
    if (body_len > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[proto] Message too large: %u bytes.\n", body_len);
        return -1;
    }

    /* Allocate and read the body. */
    uint8_t *body = (uint8_t *)malloc(body_len);
    if (body == NULL) {
        fprintf(stderr, "[proto] Allocation failed for %u bytes.\n", body_len);
        return -1;
    }

    if (proto_raw_recv(ctx, body, body_len) != 0) {
        free(body);
        return -1;
    }

    *out_data = body;
    *out_len  = body_len;
    return 0;
}

uint32_t proto_get_seq(const proto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->seq_num;
}
