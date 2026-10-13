/* ==========================================================================
 * pal.h - Platform Abstraction Layer Interface
 * ==========================================================================
 * The PAL isolates every OS-specific operation behind a portable C99 API.
 * Two implementations exist:
 *   - pal_linux.c : POSIX (Linux, macOS)
 *   - pal_win32.c : Win32 / Winsock2
 *
 * Only one PAL source is compiled per build (selected by CMakeLists.txt).
 *
 * Design decisions:
 *   - Socket handles are abstracted as plain `int`.  On Windows, SOCKET is
 *     typedef'd to UINT_PTR which fits in int for typical usage.  We cast
 *     carefully inside pal_win32.c.
 *   - All functions return 0 on success, -1 on failure (unless documented
 *     otherwise).
 *   - Buffers are caller-allocated unless documented otherwise (e.g.,
 *     pal_read_file allocates via malloc).
 * ========================================================================== */
#ifndef PAL_H
#define PAL_H

#include <stdint.h>
#include <stddef.h>

/* ---- Platform initialisation / teardown -------------------------------- */

/**
 * Initialise platform-specific subsystems (e.g., Winsock on Windows).
 * Must be called once before any other PAL function.
 * Returns 0 on success, -1 on failure.
 */
int pal_init(void);

/**
 * Clean up platform-specific subsystems.
 * Called once during shutdown.
 */
void pal_cleanup(void);

/* ---- Sockets ---------------------------------------------------------- */

/**
 * Create a TCP socket.
 * Returns a non-negative socket handle on success, -1 on failure.
 */
int pal_socket_create(void);

/**
 * Connect socket `sock` to `host:port`.
 * `host` is a dotted-quad IPv4 address (e.g., "10.13.37.1").
 * Returns 0 on success, -1 on failure.
 */
int pal_socket_connect(int sock, const char *host, uint16_t port);

/**
 * Send exactly `len` bytes from `buf` over `sock`.
 * Handles partial sends internally.
 * Returns 0 on success, -1 on failure.
 */
int pal_socket_send(int sock, const void *buf, size_t len);

/**
 * Receive exactly `len` bytes into `buf` from `sock`.
 * Blocks until all bytes are received or an error occurs.
 * Returns 0 on success, -1 on failure (including connection closed).
 */
int pal_socket_recv(int sock, void *buf, size_t len);

/**
 * Close socket `sock` and release resources.
 */
void pal_socket_close(int sock);

/* ---- Process execution ------------------------------------------------ */

/**
 * Spawn a child process running `cmd` (shell command string).
 * Captures combined stdout/stderr into `out_buf` (up to `out_size - 1` bytes,
 * NUL-terminated).  Stores the child's exit code in `*exit_code`.
 * Returns 0 on success, -1 on failure.
 */
int pal_spawn_process(const char *cmd, char *out_buf, size_t out_size,
                      int *exit_code);

/* ---- File I/O --------------------------------------------------------- */

/**
 * Read the entire contents of `path` into a newly-allocated buffer.
 * On success, `*buf` points to a malloc'd buffer and `*size` holds its
 * length.  Caller must free `*buf`.
 * Returns 0 on success, -1 on failure.
 */
int pal_read_file(const char *path, uint8_t **buf, size_t *size);

/**
 * Write `size` bytes from `buf` to file at `path`.
 * Creates or overwrites the file.
 * Returns 0 on success, -1 on failure.
 */
int pal_write_file(const char *path, const uint8_t *buf, size_t size);

/* ---- Time ------------------------------------------------------------- */

/**
 * Return the current time as a Unix timestamp (seconds since epoch).
 */
int64_t pal_time_unix(void);

/**
 * Sleep for `ms` milliseconds.
 */
void pal_sleep_ms(uint32_t ms);

/* ---- Process control -------------------------------------------------- */

/**
 * Terminate the agent process with exit code `code`.
 * This function does not return.
 */
void pal_exit(int code);

/* ---- System information ----------------------------------------------- */

/**
 * Write the hostname into `buf` (up to `size - 1` chars, NUL-terminated).
 * Returns 0 on success, -1 on failure.
 */
int pal_get_hostname(char *buf, size_t size);

/**
 * Write a human-readable OS description into `buf`
 * (e.g., "Linux 5.15.0-86-generic").
 * Returns 0 on success, -1 on failure.
 */
int pal_get_os_info(char *buf, size_t size);

/**
 * Write the CPU architecture into `buf` (e.g., "x86_64", "aarch64").
 * Returns 0 on success, -1 on failure.
 */
int pal_get_arch(char *buf, size_t size);

/* ---- Logging ---------------------------------------------------------- */

/**
 * Log a message.  On Linux this goes to syslog; on Windows to the Event Log.
 * Also prints to stderr in debug builds.
 * Format string follows printf conventions.
 */
void pal_log(const char *fmt, ...);

/* ---- Kill switch ------------------------------------------------------ */

/**
 * Check whether the sentinel file at `path` exists.
 * Returns 1 if the file exists (kill switch triggered), 0 otherwise.
 */
int pal_check_sentinel(const char *path);

#endif /* PAL_H */
