/* ==========================================================================
 * protocol.h - Protocol State Machine
 * ==========================================================================
 * Manages the connection lifecycle and enforces valid state transitions.
 *
 * State diagram:
 *   INIT ──register──▶ REGISTERED ──first beacon──▶ ACTIVE
 *     │                    │                          │
 *     └────────────────────┴──────────────────────────┘
 *                          │
 *                       SHUTDOWN (terminal)
 *
 * Each message sent increments a sequence number.  The protocol layer
 * handles framing (4-byte big-endian length prefix) and delegates
 * TLS I/O to the PAL socket functions wrapped by mbedTLS.
 * ========================================================================== */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "tlv.h"

/* ---- Protocol states -------------------------------------------------- */
typedef enum {
    STATE_INIT       = 0,   /* Initial state, not yet connected       */
    STATE_REGISTERED = 1,   /* REGISTER sent and ACK received         */
    STATE_ACTIVE     = 2,   /* Beaconing / executing tasks            */
    STATE_SHUTDOWN   = 3    /* Terminal state, shutting down           */
} proto_state_t;

/* ---- Protocol context ------------------------------------------------- */
typedef struct {
    proto_state_t state;        /* Current state                       */
    uint32_t      seq_num;      /* Next sequence number to use         */
    int           sock;         /* Underlying socket handle            */

    /* mbedTLS context pointers (opaque here, cast in protocol.c).
     * We store them as void* to avoid pulling mbedTLS headers into
     * every translation unit. */
    void         *tls_ssl;      /* mbedtls_ssl_context*                */
    void         *tls_conf;     /* mbedtls_ssl_config*                 */
    void         *tls_ctr_drbg; /* mbedtls_ctr_drbg_context*           */
    void         *tls_entropy;  /* mbedtls_entropy_context*            */
    void         *tls_cacert;   /* mbedtls_x509_crt* (CA cert)         */

    /* Agent identity (set during initialisation) */
    char          agent_id[64]; /* UUID or unique identifier           */
} proto_ctx_t;

/* ---- Lifecycle functions ---------------------------------------------- */

/**
 * Initialise the protocol context.  Sets state to STATE_INIT,
 * sequence number to 0, and zeroes TLS pointers.
 */
void proto_init(proto_ctx_t *ctx);

/**
 * Establish a TLS connection to `host:port`.
 * - Creates a socket via PAL
 * - Initialises mbedTLS and performs the TLS handshake
 * Returns 0 on success, -1 on failure.
 * State must be STATE_INIT.
 */
int proto_connect(proto_ctx_t *ctx, const char *host, uint16_t port);

/**
 * Clean up TLS resources and close the socket.
 * Transitions to STATE_SHUTDOWN.
 */
void proto_disconnect(proto_ctx_t *ctx);

/* ---- State transitions ------------------------------------------------ */

/**
 * Attempt a state transition.
 * Returns 0 if the transition is valid, -1 otherwise.
 * Valid transitions:
 *   INIT       -> REGISTERED
 *   REGISTERED -> ACTIVE
 *   *          -> SHUTDOWN
 */
int proto_transition(proto_ctx_t *ctx, proto_state_t new_state);

/**
 * Return the current state.
 */
proto_state_t proto_get_state(const proto_ctx_t *ctx);

/* ---- Message I/O ------------------------------------------------------ */

/**
 * Send a framed TLV message.
 * Prepends a 4-byte big-endian length prefix, then sends the TLV body
 * over TLS.  Increments the sequence number.
 * Returns 0 on success, -1 on failure.
 */
int proto_send(proto_ctx_t *ctx, const tlv_buffer_t *msg);

/**
 * Receive a framed TLV message.
 * Reads the 4-byte length prefix, allocates a buffer, reads the body.
 * On success, `*out_data` is a malloc'd buffer, `*out_len` is its size.
 * Caller must free `*out_data`.
 * Returns 0 on success, -1 on failure.
 */
int proto_recv(proto_ctx_t *ctx, uint8_t **out_data, size_t *out_len);

/**
 * Get the current sequence number (for building messages).
 */
uint32_t proto_get_seq(const proto_ctx_t *ctx);

#endif /* PROTOCOL_H */
