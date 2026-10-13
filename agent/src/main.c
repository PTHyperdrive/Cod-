/* ==========================================================================
 * main.c — Agent Entry Point
 * ==========================================================================
 * Parses the --lab-agent command-line flag, initialises the PAL, runs all
 * safety pre-flight checks, and enters the agent run loop.
 *
 * Usage:
 *   ./code_agent --lab-agent
 *
 * Without --lab-agent, the agent prints a safety notice and exits.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "agent.h"
#include "config.h"
#include "pal.h"
#include "safety.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Command-line parsing --------------------------------------------- */

/**
 * Check if --lab-agent is present in argv.
 */
static int has_lab_agent_flag(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lab-agent") == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---- Main ------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    /* Step 1: Initialise the PAL (Winsock on Windows, no-op on Linux). */
    if (pal_init() != 0) {
        fprintf(stderr, "[main] PAL initialisation failed.\n");
        return 1;
    }

    /* Step 2: Check for --lab-agent flag. */
    int lab_flag = has_lab_agent_flag(argc, argv);

    /* Step 3: Run all safety pre-flight checks.
     * This includes --lab-agent, build expiry, CIDR allowlist,
     * kill switch sentinel, and banner display. */
    if (safety_preflight(lab_flag) != 0) {
        pal_cleanup();
        return 1;
    }

    /* Step 4: Initialise and run the agent. */
    agent_ctx_t agent;
    agent_init(&agent);
    agent.lab_agent_flag = lab_flag;

    pal_log("Starting agent run loop...");

    int rc = agent_run(&agent);

    /* Step 5: Clean shutdown. */
    agent_shutdown(&agent);
    pal_cleanup();

    pal_log("Agent exited with code %d.", rc);
    return rc;
}
