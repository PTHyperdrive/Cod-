/* ==========================================================================
 * compat.h — Cross-Platform Compatibility Macros
 * ==========================================================================
 * Redirects libc functions (malloc, free, memset, etc.) to our
 * syscall-based replacements on BOTH Linux and Windows:
 *
 *   Linux:   syscall_linux.h (raw x86_64 SYSCALL) + nolibc.h
 *   Windows: syscall_win32.h (ntdll.dll native API) + nolibc.h
 *
 * NO libc, NO CRT, NO kernel32, NO ws2_32 — pure syscall only.
 *
 * Usage: Include this header AFTER the standard library headers in every
 * shared .c file (tlv.c, protocol.c, capabilities.c, safety.c, agent.c,
 * main.c).  It #defines the standard names to our replacements, so all
 * existing code works without modification.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */
#ifndef COMPAT_H
#define COMPAT_H

#ifdef __linux__

#include "syscall_linux.h"
#include "nolibc.h"

/* ---- Memory allocation ------------------------------------------------ */
/* Redirect malloc/free/realloc/calloc to our mmap-based allocator.        */

#ifdef malloc
#undef malloc
#endif
#define malloc(sz)          sc_malloc(sz)

#ifdef free
#undef free
#endif
#define free(ptr)           sc_free(ptr)

#ifdef realloc
#undef realloc
#endif
#define realloc(ptr, sz)    sc_realloc(ptr, sz)

/* calloc: allocate + zero.  mmap(MAP_ANONYMOUS) returns zeroed pages. */
static inline void *_compat_calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void *p = sc_malloc(total);
    /* mmap already zeroes the pages, but for safety with small
     * allocations that might reuse a partially-used page: */
    if (p) _nc_memset(p, 0, total);
    return p;
}

#ifdef calloc
#undef calloc
#endif
#define calloc(n, sz)       _compat_calloc(n, sz)

/* ---- String / memory operations --------------------------------------- */

#ifdef memset
#undef memset
#endif
#define memset(d, c, n)     _nc_memset(d, c, n)

#ifdef memcpy
#undef memcpy
#endif
#define memcpy(d, s, n)     _nc_memcpy(d, s, n)

#ifdef memmove
#undef memmove
#endif
#define memmove(d, s, n)    _nc_memmove(d, s, n)

#ifdef strlen
#undef strlen
#endif
#define strlen(s)           _nc_strlen(s)

#ifdef strcmp
#undef strcmp
#endif
#define strcmp(a, b)         _nc_strcmp(a, b)

#ifdef strncmp
#undef strncmp
#endif
#define strncmp(a, b, n)    _nc_strncmp(a, b, n)

#ifdef strncpy
#undef strncpy
#endif
#define strncpy(d, s, n)    _nc_strncpy(d, s, n)

#ifdef strchr
#undef strchr
#endif
#define strchr(s, c)        _nc_strchr(s, c)

#ifdef strtol
#undef strtol
#endif
#define strtol(s, e, b)     ((long)_nc_strtoul(s, e, b))

/* ---- I/O -------------------------------------------------------------- */
/* Replace fprintf/printf/snprintf with our minimal implementations.
 * For fprintf to stderr, we write directly via syscall.
 * For sprintf/snprintf, we use _nc_snprintf.
 *
 * NOTE: We can't perfectly replace fprintf/printf with a macro because
 * they have different signatures (FILE* vs not).  Instead, the shared
 * source files should be updated to use pal_log() where possible.
 * For remaining fprintf(stderr, ...) calls, we provide a compat shim. */

#ifdef snprintf
#undef snprintf
#endif
#define snprintf            _nc_snprintf

/* fprintf shim — only supports stderr (fd 2) */
static inline int _compat_fprintf(void *stream, const char *fmt, ...)
{
    (void)stream; /* We always write to fd 2 */
    char buf[1024];

    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    /* We need to manually format since _nc_snprintf is variadic.
     * Simple pass-through: use the pre-formatted message. */
    size_t pos = 0;
    while (*fmt && pos < sizeof(buf) - 1) {
        if (*fmt != '%') {
            buf[pos++] = *fmt++;
            continue;
        }
        fmt++;

        int is_long = 0;
        if (*fmt == 'l') { is_long = 1; fmt++; }
        if (*fmt == 'l') { fmt++; } /* skip second 'l' */

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos < sizeof(buf) - 1) buf[pos++] = *s++;
            break;
        }
        case 'd': {
            long v = is_long ? __builtin_va_arg(ap, long)
                             : (long)__builtin_va_arg(ap, int);
            char *p = _nc_i64_to_dec((int64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'u': {
            unsigned long v = is_long
                ? __builtin_va_arg(ap, unsigned long)
                : (unsigned long)__builtin_va_arg(ap, unsigned int);
            char *p = _nc_u64_to_dec((uint64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'z':
            fmt++; /* skip 'z', treat 'zu' as unsigned long */
            if (*fmt == 'u') {
                unsigned long v = __builtin_va_arg(ap, unsigned long);
                char *p = _nc_u64_to_dec((uint64_t)v, numbuf, sizeof(numbuf));
                while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            }
            break;
        case 'x': case 'X': {
            unsigned long v = is_long
                ? __builtin_va_arg(ap, unsigned long)
                : (unsigned long)__builtin_va_arg(ap, unsigned int);
            char *p = _nc_u32_to_hex((uint32_t)v, numbuf, sizeof(numbuf));
            /* Pad to 4 digits for 04x */
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'p': {
            void *ptr = __builtin_va_arg(ap, void *);
            buf[pos++] = '0';
            if (pos < sizeof(buf) - 1) buf[pos++] = 'x';
            char *p = _nc_u32_to_hex((uint32_t)(uintptr_t)ptr,
                                     numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'c':
            buf[pos++] = (char)__builtin_va_arg(ap, int);
            break;
        case '%':
            buf[pos++] = '%';
            break;
        default:
            buf[pos++] = '%';
            if (pos < sizeof(buf) - 1) buf[pos++] = *fmt;
            break;
        }
        fmt++;
    }
    buf[pos] = '\0';

    __builtin_va_end(ap);

    sc_write(2, buf, pos);
    return (int)pos;
}

#ifdef fprintf
#undef fprintf
#endif
#define fprintf(stream, ...)    _compat_fprintf(stream, __VA_ARGS__)

/* printf shim — writes to stdout (fd 1) */
static inline int _compat_printf(const char *fmt, ...)
{
    char buf[1024];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    /* Simplified: just write the format string if no args,
     * or use _nc_snprintf for basic formatting */
    size_t pos = 0;
    while (*fmt && pos < sizeof(buf) - 1) {
        if (*fmt != '%') {
            buf[pos++] = *fmt++;
            continue;
        }
        fmt++;

        int is_long = 0;
        if (*fmt == 'l') { is_long = 1; fmt++; }
        if (*fmt == 'l') { fmt++; }

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos < sizeof(buf) - 1) buf[pos++] = *s++;
            break;
        }
        case 'd': {
            long v = is_long ? __builtin_va_arg(ap, long)
                             : (long)__builtin_va_arg(ap, int);
            char *p = _nc_i64_to_dec((int64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case '%':
            buf[pos++] = '%';
            break;
        default:
            buf[pos++] = '%';
            if (pos < sizeof(buf) - 1) buf[pos++] = *fmt;
            break;
        }
        fmt++;
    }
    buf[pos] = '\0';

    __builtin_va_end(ap);

    sc_write(1, buf, pos);
    return (int)pos;
}

#ifdef printf
#undef printf
#endif
#define printf(...)     _compat_printf(__VA_ARGS__)

/* sscanf shim — only supports the pattern used in safety.c:
 * sscanf(str, "%u.%u.%u.%u%c", &a, &b, &c, &d, &trailing)
 * We provide a purpose-built parser instead. */
static inline int _compat_sscanf_ipv4(const char *str,
                                       unsigned int *a, unsigned int *b,
                                       unsigned int *c, unsigned int *d,
                                       char *trailing)
{
    int count = 0;
    unsigned int *parts[] = { a, b, c, d };

    for (int i = 0; i < 4; i++) {
        if (*str < '0' || *str > '9') return count;
        unsigned int val = 0;
        while (*str >= '0' && *str <= '9') {
            val = val * 10 + (unsigned int)(*str - '0');
            str++;
        }
        *parts[i] = val;
        count++;
        if (i < 3) {
            if (*str != '.') return count;
            str++;
        }
    }

    if (*str != '\0') {
        *trailing = *str;
        count++;
    }

    return count;
}

/* ---- Process exit ----------------------------------------------------- */
#ifdef exit
#undef exit
#endif
#define exit(code)      sc_exit_group(code)

/* ---- Random number generation ----------------------------------------- */
/* Simple LCG PRNG — no libc rand/srand needed.                            */

static unsigned int _compat_rand_state = 1;

static inline void _compat_srand(unsigned int seed)
{
    _compat_rand_state = seed;
}

static inline int _compat_rand(void)
{
    _compat_rand_state = _compat_rand_state * 1103515245 + 12345;
    return (int)(_compat_rand_state >> 16) & 0x7FFF;
}

#ifdef srand
#undef srand
#endif
#define srand(s)    _compat_srand(s)

#ifdef rand
#undef rand
#endif
#define rand()      _compat_rand()

/* ---- getenv shim ------------------------------------------------------ */
/* Read environment from /proc/self/environ */
static inline const char *_compat_getenv(const char *name)
{
    /* For simplicity, return NULL.  The only getenv usage is in
     * safety.c for the Windows TEMP path, which is #ifdef _WIN32. */
    (void)name;
    return (const char *)0;
}

#ifdef getenv
#undef getenv
#endif
#define getenv(n)   _compat_getenv(n)

/* ---- time() shim ------------------------------------------------------ */
static inline long _compat_time(void *t)
{
    struct sc_timespec ts;
    sc_clock_gettime(SC_CLOCK_REALTIME, &ts);
    if (t) *(long *)t = ts.tv_sec;
    return ts.tv_sec;
}

/* Avoid conflict with time_t time(time_t*) */
/* time() calls in shared code should use pal_time_unix() instead */

#endif /* __linux__ */

/* ========================================================================
 * Windows: redirect libc to syscall_win32.h + nolibc.h
 * ======================================================================== */

#ifdef _WIN32

#include "syscall_win32.h"
#include "nolibc.h"

/* ---- Memory allocation ------------------------------------------------ */

#ifdef malloc
#undef malloc
#endif
#define malloc(sz)          nt_malloc(sz)

#ifdef free
#undef free
#endif
#define free(ptr)           nt_free(ptr)

#ifdef realloc
#undef realloc
#endif
#define realloc(ptr, sz)    nt_realloc(ptr, sz)

/* calloc: allocate + zero.  NtAllocateVirtualMemory returns zeroed pages. */
static inline void *_compat_win_calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void *p = nt_malloc(total);
    if (p) _nc_memset(p, 0, total);
    return p;
}

#ifdef calloc
#undef calloc
#endif
#define calloc(n, sz)       _compat_win_calloc(n, sz)

/* ---- String / memory operations --------------------------------------- */

#ifdef memset
#undef memset
#endif
#define memset(d, c, n)     _nc_memset(d, c, n)

#ifdef memcpy
#undef memcpy
#endif
#define memcpy(d, s, n)     _nc_memcpy(d, s, n)

#ifdef memmove
#undef memmove
#endif
#define memmove(d, s, n)    _nc_memmove(d, s, n)

#ifdef strlen
#undef strlen
#endif
#define strlen(s)           _nc_strlen(s)

#ifdef strcmp
#undef strcmp
#endif
#define strcmp(a, b)         _nc_strcmp(a, b)

#ifdef strncmp
#undef strncmp
#endif
#define strncmp(a, b, n)    _nc_strncmp(a, b, n)

#ifdef strncpy
#undef strncpy
#endif
#define strncpy(d, s, n)    _nc_strncpy(d, s, n)

#ifdef strchr
#undef strchr
#endif
#define strchr(s, c)        _nc_strchr(s, c)

#ifdef strtol
#undef strtol
#endif
#define strtol(s, e, b)     ((long)_nc_strtoul(s, e, b))

/* ---- I/O -------------------------------------------------------------- */

#ifdef snprintf
#undef snprintf
#endif
#define snprintf            _nc_snprintf

/* fprintf shim — writes to stderr via NtWriteFile */
static inline int _compat_win_fprintf(void *stream, const char *fmt, ...)
{
    (void)stream;
    char buf[1024];

    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    size_t pos = 0;
    while (*fmt && pos < sizeof(buf) - 1) {
        if (*fmt != '%') {
            buf[pos++] = *fmt++;
            continue;
        }
        fmt++;

        int is_long = 0;
        if (*fmt == 'l') { is_long = 1; fmt++; }
        if (*fmt == 'l') { fmt++; }

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos < sizeof(buf) - 1) buf[pos++] = *s++;
            break;
        }
        case 'd': {
            long v = is_long ? __builtin_va_arg(ap, long)
                             : (long)__builtin_va_arg(ap, int);
            char *p = _nc_i64_to_dec((int64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'u': {
            unsigned long v = is_long
                ? __builtin_va_arg(ap, unsigned long)
                : (unsigned long)__builtin_va_arg(ap, unsigned int);
            char *p = _nc_u64_to_dec((uint64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'z':
            fmt++;
            if (*fmt == 'u') {
                unsigned long v = __builtin_va_arg(ap, unsigned long);
                char *p = _nc_u64_to_dec((uint64_t)v, numbuf, sizeof(numbuf));
                while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            }
            break;
        case 'x': case 'X': {
            unsigned long v = is_long
                ? __builtin_va_arg(ap, unsigned long)
                : (unsigned long)__builtin_va_arg(ap, unsigned int);
            char *p = _nc_u32_to_hex((uint32_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'p': {
            void *ptr = __builtin_va_arg(ap, void *);
            buf[pos++] = '0';
            if (pos < sizeof(buf) - 1) buf[pos++] = 'x';
            char *p = _nc_u32_to_hex((uint32_t)(uintptr_t)ptr,
                                     numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case 'c':
            buf[pos++] = (char)__builtin_va_arg(ap, int);
            break;
        case '%':
            buf[pos++] = '%';
            break;
        default:
            buf[pos++] = '%';
            if (pos < sizeof(buf) - 1) buf[pos++] = *fmt;
            break;
        }
        fmt++;
    }
    buf[pos] = '\0';

    __builtin_va_end(ap);

    /* Write via NtWriteFile to stderr handle from PEB */
    if (g_nt.initialized && g_nt.NtWriteFile) {
        NT_PEB *peb = _nt_get_peb();
        if (peb && peb->ProcessParameters) {
            NT_HANDLE hStderr = peb->ProcessParameters->StandardError;
            if (hStderr != NT_INVALID_HANDLE && hStderr != NT_NULL_HANDLE) {
                NT_IO_STATUS_BLOCK iosb;
                _nc_memset(&iosb, 0, sizeof(iosb));
                g_nt.NtWriteFile(hStderr, NT_NULL_HANDLE, (NT_PVOID)0,
                                 (NT_PVOID)0, &iosb, (NT_PVOID)buf,
                                 (NT_ULONG)pos, (NT_LARGE_INTEGER *)0,
                                 (NT_PVOID)0);
            }
        }
    }
    return (int)pos;
}

#ifdef fprintf
#undef fprintf
#endif
#define fprintf(stream, ...)    _compat_win_fprintf(stream, __VA_ARGS__)

/* printf shim — writes to stdout via NtWriteFile */
static inline int _compat_win_printf(const char *fmt, ...)
{
    char buf[1024];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    size_t pos = 0;
    while (*fmt && pos < sizeof(buf) - 1) {
        if (*fmt != '%') {
            buf[pos++] = *fmt++;
            continue;
        }
        fmt++;

        int is_long = 0;
        if (*fmt == 'l') { is_long = 1; fmt++; }
        if (*fmt == 'l') { fmt++; }

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && pos < sizeof(buf) - 1) buf[pos++] = *s++;
            break;
        }
        case 'd': {
            long v = is_long ? __builtin_va_arg(ap, long)
                             : (long)__builtin_va_arg(ap, int);
            char *p = _nc_i64_to_dec((int64_t)v, numbuf, sizeof(numbuf));
            while (*p && pos < sizeof(buf) - 1) buf[pos++] = *p++;
            break;
        }
        case '%':
            buf[pos++] = '%';
            break;
        default:
            buf[pos++] = '%';
            if (pos < sizeof(buf) - 1) buf[pos++] = *fmt;
            break;
        }
        fmt++;
    }
    buf[pos] = '\0';

    __builtin_va_end(ap);

    /* Write via NtWriteFile to stdout handle from PEB */
    if (g_nt.initialized && g_nt.NtWriteFile) {
        NT_PEB *peb = _nt_get_peb();
        if (peb && peb->ProcessParameters) {
            NT_HANDLE hStdout = peb->ProcessParameters->StandardOutput;
            if (hStdout != NT_INVALID_HANDLE && hStdout != NT_NULL_HANDLE) {
                NT_IO_STATUS_BLOCK iosb;
                _nc_memset(&iosb, 0, sizeof(iosb));
                g_nt.NtWriteFile(hStdout, NT_NULL_HANDLE, (NT_PVOID)0,
                                 (NT_PVOID)0, &iosb, (NT_PVOID)buf,
                                 (NT_ULONG)pos, (NT_LARGE_INTEGER *)0,
                                 (NT_PVOID)0);
            }
        }
    }
    return (int)pos;
}

#ifdef printf
#undef printf
#endif
#define printf(...)     _compat_win_printf(__VA_ARGS__)

/* sscanf shim — same purpose-built IPv4 parser as Linux version */
static inline int _compat_win_sscanf_ipv4(const char *str,
                                            unsigned int *a, unsigned int *b,
                                            unsigned int *c, unsigned int *d,
                                            char *trailing)
{
    int count = 0;
    unsigned int *parts[] = { a, b, c, d };

    for (int i = 0; i < 4; i++) {
        if (*str < '0' || *str > '9') return count;
        unsigned int val = 0;
        while (*str >= '0' && *str <= '9') {
            val = val * 10 + (unsigned int)(*str - '0');
            str++;
        }
        *parts[i] = val;
        count++;
        if (i < 3) {
            if (*str != '.') return count;
            str++;
        }
    }

    if (*str != '\0') {
        *trailing = *str;
        count++;
    }

    return count;
}

/* ---- Process exit ----------------------------------------------------- */
#ifdef exit
#undef exit
#endif
#define exit(code) do { \
    if (g_nt.NtTerminateProcess) \
        g_nt.NtTerminateProcess(NT_CURRENT_PROCESS, (NT_NTSTATUS)(code)); \
    for (;;) {} \
} while(0)

/* ---- Random number generation ----------------------------------------- */

static unsigned int _compat_win_rand_state = 1;

static inline void _compat_win_srand(unsigned int seed)
{
    _compat_win_rand_state = seed;
}

static inline int _compat_win_rand(void)
{
    _compat_win_rand_state = _compat_win_rand_state * 1103515245 + 12345;
    return (int)(_compat_win_rand_state >> 16) & 0x7FFF;
}

#ifdef srand
#undef srand
#endif
#define srand(s)    _compat_win_srand(s)

#ifdef rand
#undef rand
#endif
#define rand()      _compat_win_rand()

/* ---- getenv shim ------------------------------------------------------ */
static inline const char *_compat_win_getenv(const char *name)
{
    (void)name;
    return (const char *)0;
}

#ifdef getenv
#undef getenv
#endif
#define getenv(n)   _compat_win_getenv(n)

/* ---- time() shim ------------------------------------------------------ */
static inline long _compat_win_time(void *t)
{
    if (!g_nt.NtQuerySystemTime) return 0;
    NT_LARGE_INTEGER sys_time;
    g_nt.NtQuerySystemTime(&sys_time);
    long sec = (long)((sys_time.QuadPart - 116444736000000000LL) / 10000000LL);
    if (t) *(long *)t = sec;
    return sec;
}

#endif /* _WIN32 */

#endif /* COMPAT_H */

