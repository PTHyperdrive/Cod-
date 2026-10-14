/* ==========================================================================
 * nolibc.h — Libc-free String / Memory Utilities
 * ==========================================================================
 * Standalone implementations of common libc functions so that the agent
 * can operate without linking against glibc/musl.  Every function is
 * prefixed with `_nc_` (no-libc) to avoid symbol collisions if libc
 * happens to be present during development builds.
 *
 * All functions are `static inline` so they can be included in multiple
 * translation units without linker conflicts.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */
#ifndef NOLIBC_H
#define NOLIBC_H

#include <stdint.h>
#include <stddef.h>

/* ---- Memory operations ------------------------------------------------ */

static inline void *_nc_memset(void *dst, int c, size_t n)
{
    unsigned char *p = (unsigned char *)dst;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return dst;
}

static inline void *_nc_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

static inline void *_nc_memmove(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else if (d > s) {
        d += n;
        s += n;
        while (n--) {
            *(--d) = *(--s);
        }
    }
    return dst;
}

static inline int _nc_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    while (n--) {
        if (*pa != *pb) {
            return (int)*pa - (int)*pb;
        }
        pa++;
        pb++;
    }
    return 0;
}

/* ---- String operations ------------------------------------------------ */

static inline size_t _nc_strlen(const char *s)
{
    const char *p = s;
    while (*p) {
        p++;
    }
    return (size_t)(p - s);
}

static inline int _nc_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static inline int _nc_strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) {
        a++;
        b++;
        n--;
    }
    if (n == 0) {
        return 0;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static inline char *_nc_strcpy(char *dst, const char *src)
{
    char *d = dst;
    while ((*d++ = *src++) != '\0')
        ;
    return dst;
}

static inline char *_nc_strncpy(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    for (; i < n; i++) {
        dst[i] = '\0';
    }
    return dst;
}

static inline char *_nc_strcat(char *dst, const char *src)
{
    char *d = dst;
    while (*d) {
        d++;
    }
    while ((*d++ = *src++) != '\0')
        ;
    return dst;
}

static inline const char *_nc_strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c) {
            return s;
        }
        s++;
    }
    return (c == '\0') ? s : NULL;
}

/* ---- Number formatting ------------------------------------------------ */

/**
 * Convert an unsigned 64-bit integer to a decimal string.
 * Writes into `buf` (must be at least 21 bytes).
 * Returns a pointer to the first digit within `buf`.
 */
static inline char *_nc_u64_to_dec(uint64_t val, char *buf, size_t bufsz)
{
    char *end = buf + bufsz - 1;
    *end = '\0';
    char *p = end;

    if (val == 0) {
        *(--p) = '0';
        return p;
    }

    while (val > 0 && p > buf) {
        *(--p) = '0' + (char)(val % 10);
        val /= 10;
    }
    return p;
}

/**
 * Convert a signed 64-bit integer to a decimal string.
 * Returns pointer to the first character within `buf`.
 */
static inline char *_nc_i64_to_dec(int64_t val, char *buf, size_t bufsz)
{
    if (val < 0) {
        char *p = _nc_u64_to_dec((uint64_t)(-val), buf + 1, bufsz - 1);
        *(--p) = '-';
        return p;
    }
    return _nc_u64_to_dec((uint64_t)val, buf, bufsz);
}

/**
 * Convert an unsigned 32-bit integer to a hex string (no 0x prefix).
 * Writes into `buf` (must be at least 9 bytes).
 * Returns pointer to the first hex digit within `buf`.
 */
static inline char *_nc_u32_to_hex(uint32_t val, char *buf, size_t bufsz)
{
    static const char hex[] = "0123456789abcdef";
    char *end = buf + bufsz - 1;
    *end = '\0';
    char *p = end;

    if (val == 0) {
        *(--p) = '0';
        return p;
    }

    while (val > 0 && p > buf) {
        *(--p) = hex[val & 0xF];
        val >>= 4;
    }
    return p;
}

/**
 * Simple decimal string to unsigned long conversion.
 * Stops at first non-digit character.  Returns the parsed value.
 */
static inline unsigned long _nc_strtoul(const char *s, char **endp, int base)
{
    unsigned long result = 0;
    (void)base; /* We only support base 10 for now */

    while (*s >= '0' && *s <= '9') {
        result = result * 10 + (unsigned long)(*s - '0');
        s++;
    }

    if (endp) {
        *endp = (char *)s;
    }
    return result;
}

/**
 * Simple snprintf-like formatter supporting %s, %d, %u, %x, %ld, %lu, %p.
 * Returns the number of characters written (excluding NUL).
 * This is intentionally minimal — not a full printf replacement.
 */
static inline int _nc_snprintf(char *buf, size_t bufsz, const char *fmt, ...)
{
    /* We implement this with a simple va_list walk.
     * NOTE: This requires compiler builtins for va_list, which are
     * available even without libc headers via __builtin_va_*. */
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    size_t pos = 0;

#define _NC_PUTC(c) do { if (pos < bufsz - 1) buf[pos] = (c); pos++; } while(0)
#define _NC_PUTS(s) do { const char *_s = (s); while (*_s) { _NC_PUTC(*_s); _s++; } } while(0)

    while (*fmt && pos < bufsz - 1) {
        if (*fmt != '%') {
            _NC_PUTC(*fmt);
            fmt++;
            continue;
        }
        fmt++; /* skip '%' */

        /* Handle flags/width (simplified — skip them) */
        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
        }

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (s == NULL) s = "(null)";
            _NC_PUTS(s);
            break;
        }
        case 'd': {
            long v;
            if (is_long) {
                v = __builtin_va_arg(ap, long);
            } else {
                v = (long)__builtin_va_arg(ap, int);
            }
            char *p = _nc_i64_to_dec((int64_t)v, numbuf, sizeof(numbuf));
            _NC_PUTS(p);
            break;
        }
        case 'u': {
            unsigned long v;
            if (is_long) {
                v = __builtin_va_arg(ap, unsigned long);
            } else {
                v = (unsigned long)__builtin_va_arg(ap, unsigned int);
            }
            char *p = _nc_u64_to_dec((uint64_t)v, numbuf, sizeof(numbuf));
            _NC_PUTS(p);
            break;
        }
        case 'x': {
            unsigned long v;
            if (is_long) {
                v = __builtin_va_arg(ap, unsigned long);
            } else {
                v = (unsigned long)__builtin_va_arg(ap, unsigned int);
            }
            char *p = _nc_u32_to_hex((uint32_t)v, numbuf, sizeof(numbuf));
            _NC_PUTS(p);
            break;
        }
        case 'p': {
            void *ptr = __builtin_va_arg(ap, void *);
            _NC_PUTC('0');
            _NC_PUTC('x');
            char *p = _nc_u32_to_hex((uint32_t)(uintptr_t)ptr, numbuf, sizeof(numbuf));
            _NC_PUTS(p);
            break;
        }
        case '%':
            _NC_PUTC('%');
            break;
        default:
            _NC_PUTC('%');
            _NC_PUTC(*fmt);
            break;
        }
        fmt++;
    }

#undef _NC_PUTC
#undef _NC_PUTS

    if (bufsz > 0) {
        buf[pos < bufsz ? pos : bufsz - 1] = '\0';
    }

    __builtin_va_end(ap);
    return (int)pos;
}

/* ---- IP address helpers ----------------------------------------------- */

/**
 * Parse a dotted-quad IPv4 address into a uint32 in network byte order
 * (big-endian), suitable for sockaddr_in.sin_addr.s_addr.
 * Returns 0 on success, -1 on failure.
 */
static inline int _nc_inet_pton4(const char *src, uint32_t *dst)
{
    uint32_t result = 0;
    int octets = 0;

    while (octets < 4) {
        if (*src < '0' || *src > '9') return -1;
        unsigned int val = 0;
        while (*src >= '0' && *src <= '9') {
            val = val * 10 + (unsigned int)(*src - '0');
            src++;
        }
        if (val > 255) return -1;
        result = (result << 8) | val;
        octets++;
        if (octets < 4) {
            if (*src != '.') return -1;
            src++;
        }
    }
    if (*src != '\0') return -1;

    /* Convert to network byte order (big-endian) */
    *dst = ((result >> 24) & 0xFF)       |
           (((result >> 16) & 0xFF) << 8)  |
           (((result >> 8)  & 0xFF) << 16) |
           ((result & 0xFF) << 24);
    return 0;
}

/**
 * Host-to-network short (uint16_t).
 */
static inline uint16_t _nc_htons(uint16_t val)
{
    return (uint16_t)((val >> 8) | (val << 8));
}

#endif /* NOLIBC_H */
