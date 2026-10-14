/* ==========================================================================
 * agent.h - Agent Core Interface
 * ==========================================================================
 * The agent context ties together the protocol layer, beacon timing, and
 * capability dispatch.  The main beacon loop lives in agent.c.
 *
 * Lifecycle:
 *   agent_init()  →  agent_run()  →  agent_shutdown()
 * ========================================================================== */
#ifndef AGENT_H
#define AGENT_H

#include <stdint.h>
#include "protocol.h"

/* ---- Agent context ---------------------------------------------------- */
typedef struct {
    proto_ctx_t proto;              /* Protocol / TLS state               */
    uint32_t    beacon_interval;    /* Current interval in seconds        */
    uint32_t    beacon_jitter;      /* Jitter percentage (0-100)          */
    int         lab_agent_flag;     /* Non-zero if --lab-agent was passed */
    int         running;            /* Loop control flag                  */
    int         self_preserve;      /* Non-zero if self-preservation is on*/
} agent_ctx_t;

/* ---- Lifecycle functions ---------------------------------------------- */

/**
 * Initialise the agent context with default configuration values.
 * Does NOT connect to the server yet.
 */
void agent_init(agent_ctx_t *ctx);

/**
 * Run the agent: connect, register, and enter the beacon loop.
 * This function blocks until the agent shuts down (kill switch,
 * expiry, or server-initiated shutdown).
 * Returns 0 on clean shutdown, -1 on error.
 */
int agent_run(agent_ctx_t *ctx);

/**
 * Initiate a graceful shutdown.
 * Sends a SHUTDOWN message to the server, disconnects, and cleans up.
 */
void agent_shutdown(agent_ctx_t *ctx);

/* ---- Internal helpers (used by agent.c) ------------------------------- */

/**
 * Build and send a REGISTER message.
 * Returns 0 on success, -1 on failure.
 */
int agent_send_register(agent_ctx_t *ctx);

/**
 * Build and send a BEACON message.
 * Returns 0 on success, -1 on failure.
 */
int agent_send_beacon(agent_ctx_t *ctx);

/**
 * Receive and dispatch incoming tasks.
 * Returns 0 on success (even if no tasks), -1 on connection error.
 */
int agent_handle_tasks(agent_ctx_t *ctx);

/**
 * Sleep for the beacon interval with jitter applied.
 */
void agent_sleep_with_jitter(const agent_ctx_t *ctx);

#endif /* AGENT_H */
