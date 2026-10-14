/* ==========================================================================
 * syscall_linux.h — Raw Linux Syscall Wrappers (x86_64)
 * ==========================================================================
 * Inline wrappers around the Linux system call interface.  These use
 * GCC/Clang inline assembly to invoke syscalls directly via the SYSCALL
 * instruction — no libc wrappers, no dynamic linker, no external
 * dependencies.
 *
 * Architecture:  x86_64 (System V ABI)
 * Syscall ABI:   rax = NR, args in rdi, rsi, rdx, r10, r8, r9
 *                Return value in rax; negative = -errno
 *
 * All wrappers are `static inline` to avoid linker issues when included
 * in multiple translation units.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */
#ifndef SYSCALL_LINUX_H
#define SYSCALL_LINUX_H

#ifdef __linux__

#include <stdint.h>
#include <stddef.h>

/* ---- Syscall numbers (x86_64) ----------------------------------------- */
/* We define these ourselves to avoid depending on <sys/syscall.h>.         */

#define __NR_read            0
#define __NR_write           1
#define __NR_open            2
#define __NR_close           3
#define __NR_fstat           5
#define __NR_lseek           8
#define __NR_mmap            9
#define __NR_mprotect       10
#define __NR_munmap         11
#define __NR_brk            12
#define __NR_dup2           33
#define __NR_nanosleep      35
#define __NR_getpid         39
#define __NR_socket         41
#define __NR_connect        42
#define __NR_sendto         44
#define __NR_recvfrom       45
#define __NR_clone          56
#define __NR_fork           57
#define __NR_execve         59
#define __NR_exit           60
#define __NR_wait4          61
#define __NR_uname          63
#define __NR_flock          73
#define __NR_pipe2         293
#define __NR_prctl         157
#define __NR_clock_gettime 228
#define __NR_exit_group    231
#define __NR_openat        257
#define __NR_newfstatat    262
#define __NR_readlinkat    267

/* ---- Kernel ABI constants --------------------------------------------- */
/* These are kernel-level constants that normally come from libc headers.
 * We define them ourselves to be fully self-contained.                     */

/* Socket domains */
#define SC_AF_INET          2

/* Socket types */
#define SC_SOCK_STREAM      1

/* open/openat flags */
#define SC_O_RDONLY         0x0000
#define SC_O_WRONLY         0x0001
#define SC_O_RDWR           0x0002
#define SC_O_CREAT          0x0040
#define SC_O_TRUNC          0x0200
#define SC_O_CLOEXEC     0x80000

/* AT_FDCWD — "current directory" sentinel for *at() syscalls */
#define SC_AT_FDCWD         (-100)

/* mmap protection flags */
#define SC_PROT_NONE        0x0
#define SC_PROT_READ        0x1
#define SC_PROT_WRITE       0x2
#define SC_PROT_EXEC        0x4

/* mmap flags */
#define SC_MAP_PRIVATE      0x02
#define SC_MAP_ANONYMOUS    0x20
#define SC_MAP_FIXED        0x10

/* mmap failure sentinel */
#define SC_MAP_FAILED       ((void *)-1)

/* flock operations */
#define SC_LOCK_EX          2
#define SC_LOCK_NB          4
#define SC_LOCK_UN          8

/* prctl operations */
#define SC_PR_SET_DUMPABLE  4

/* lseek whence */
#define SC_SEEK_SET         0
#define SC_SEEK_CUR         1
#define SC_SEEK_END         2

/* pipe2 flags */
#define SC_O_NONBLOCK    0x0800

/* wait4 options */
#define SC_WNOHANG          1

/* file mode for create (0644) */
#define SC_MODE_0644      0644
#define SC_MODE_0755      0755

/* clock IDs */
#define SC_CLOCK_REALTIME   0

/* signal numbers */
#define SC_SIGCHLD         17

/* clone flags (for fork equivalent) */
#define SC_CLONE_CHILD_SETTID   0x01000000
#define SC_CLONE_CHILD_CLEARTID 0x00200000

/* ---- Kernel structures ------------------------------------------------ */

/* struct sockaddr_in layout (matches kernel) */
struct sc_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

/* struct timespec layout */
struct sc_timespec {
    long tv_sec;
    long tv_nsec;
};

/* struct utsname layout (65-byte fields on Linux) */
struct sc_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

/* struct stat (x86_64 — kernel stat structure) */
struct sc_stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    unsigned int  st_mode;
    unsigned int  st_uid;
    unsigned int  st_gid;
    unsigned int  __pad0;
    unsigned long st_rdev;
    long          st_size;
    long          st_blksize;
    long          st_blocks;
    unsigned long st_atime_sec;
    unsigned long st_atime_nsec;
    unsigned long st_mtime_sec;
    unsigned long st_mtime_nsec;
    unsigned long st_ctime_sec;
    unsigned long st_ctime_nsec;
    long          __unused[3];
};

/* ---- Raw syscall interface -------------------------------------------- */
/* Direct inline-asm syscall invocation.  We provide variants for 0-6 args. */

static inline long _sc_syscall0(long nr)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _sc_syscall1(long nr, long a1)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _sc_syscall2(long nr, long a1, long a2)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _sc_syscall3(long nr, long a1, long a2, long a3)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _sc_syscall4(long nr, long a1, long a2, long a3, long a4)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _sc_syscall5(long nr, long a1, long a2, long a3,
                                long a4, long a5)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long _sc_syscall6(long nr, long a1, long a2, long a3,
                                long a4, long a5, long a6)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* ---- High-level syscall wrappers -------------------------------------- */
/* Thin wrappers that provide C-typed signatures over the raw interface.    */

/* -- File descriptor I/O -- */

static inline long sc_read(int fd, void *buf, size_t count)
{
    return _sc_syscall3(__NR_read, (long)fd, (long)buf, (long)count);
}

static inline long sc_write(int fd, const void *buf, size_t count)
{
    return _sc_syscall3(__NR_write, (long)fd, (long)buf, (long)count);
}

static inline int sc_open(const char *path, int flags, int mode)
{
    return (int)_sc_syscall3(__NR_open, (long)path, (long)flags, (long)mode);
}

static inline int sc_openat(int dirfd, const char *path, int flags, int mode)
{
    return (int)_sc_syscall4(__NR_openat, (long)dirfd, (long)path,
                             (long)flags, (long)mode);
}

static inline int sc_close(int fd)
{
    return (int)_sc_syscall1(__NR_close, (long)fd);
}

static inline long sc_lseek(int fd, long offset, int whence)
{
    return _sc_syscall3(__NR_lseek, (long)fd, offset, (long)whence);
}

static inline int sc_fstat(int fd, struct sc_stat *st)
{
    return (int)_sc_syscall2(__NR_fstat, (long)fd, (long)st);
}

static inline long sc_readlinkat(int dirfd, const char *path,
                                 char *buf, size_t bufsz)
{
    return _sc_syscall4(__NR_readlinkat, (long)dirfd, (long)path,
                        (long)buf, (long)bufsz);
}

/* -- Memory mapping -- */

static inline void *sc_mmap(void *addr, size_t len, int prot,
                            int flags, int fd, long offset)
{
    return (void *)_sc_syscall6(__NR_mmap, (long)addr, (long)len,
                                (long)prot, (long)flags, (long)fd, offset);
}

static inline int sc_mprotect(void *addr, size_t len, int prot)
{
    return (int)_sc_syscall3(__NR_mprotect, (long)addr, (long)len, (long)prot);
}

static inline int sc_munmap(void *addr, size_t len)
{
    return (int)_sc_syscall2(__NR_munmap, (long)addr, (long)len);
}

/* -- Sockets -- */

static inline int sc_socket(int domain, int type, int protocol)
{
    return (int)_sc_syscall3(__NR_socket, (long)domain, (long)type,
                             (long)protocol);
}

static inline int sc_connect(int fd, const void *addr, int addrlen)
{
    return (int)_sc_syscall3(__NR_connect, (long)fd, (long)addr, (long)addrlen);
}

static inline long sc_sendto(int fd, const void *buf, size_t len,
                              int flags, const void *addr, int addrlen)
{
    return _sc_syscall6(__NR_sendto, (long)fd, (long)buf, (long)len,
                        (long)flags, (long)addr, (long)addrlen);
}

static inline long sc_recvfrom(int fd, void *buf, size_t len,
                                int flags, void *addr, int *addrlen)
{
    return _sc_syscall6(__NR_recvfrom, (long)fd, (long)buf, (long)len,
                        (long)flags, (long)addr, (long)addrlen);
}

/* -- Process control -- */

static inline int sc_fork(void)
{
    return (int)_sc_syscall0(__NR_fork);
}

static inline int sc_execve(const char *path, char *const argv[],
                             char *const envp[])
{
    return (int)_sc_syscall3(__NR_execve, (long)path, (long)argv, (long)envp);
}

static inline long sc_wait4(int pid, int *status, int options, void *rusage)
{
    return _sc_syscall4(__NR_wait4, (long)pid, (long)status,
                        (long)options, (long)rusage);
}

static inline void sc_exit_group(int code)
{
    _sc_syscall1(__NR_exit_group, (long)code);
    __builtin_unreachable();
}

static inline void sc_exit(int code)
{
    _sc_syscall1(__NR_exit, (long)code);
    __builtin_unreachable();
}

static inline int sc_getpid(void)
{
    return (int)_sc_syscall0(__NR_getpid);
}

/* -- File locking / process hardening -- */

static inline int sc_flock(int fd, int operation)
{
    return (int)_sc_syscall2(__NR_flock, (long)fd, (long)operation);
}

static inline int sc_prctl(int option, unsigned long a2, unsigned long a3,
                           unsigned long a4, unsigned long a5)
{
    return (int)_sc_syscall5(__NR_prctl, (long)option, (long)a2,
                             (long)a3, (long)a4, (long)a5);
}

/* -- Pipe / dup -- */

static inline int sc_pipe2(int pipefd[2], int flags)
{
    return (int)_sc_syscall2(__NR_pipe2, (long)pipefd, (long)flags);
}

static inline int sc_dup2(int oldfd, int newfd)
{
    return (int)_sc_syscall2(__NR_dup2, (long)oldfd, (long)newfd);
}

/* -- Time -- */

static inline int sc_clock_gettime(int clk_id, struct sc_timespec *tp)
{
    return (int)_sc_syscall2(__NR_clock_gettime, (long)clk_id, (long)tp);
}

static inline int sc_nanosleep(const struct sc_timespec *req,
                               struct sc_timespec *rem)
{
    return (int)_sc_syscall2(__NR_nanosleep, (long)req, (long)rem);
}

/* -- System info -- */

static inline int sc_uname(struct sc_utsname *buf)
{
    return (int)_sc_syscall1(__NR_uname, (long)buf);
}

/* ---- Simple mmap-based allocator -------------------------------------- */
/* These replace malloc/free/realloc using anonymous mmap pages.
 * Each allocation is preceded by a size_t header storing the total
 * mapped size (header + payload).  This is simple and wasteful for
 * small allocations but requires zero external dependencies.            */

static inline void *sc_malloc(size_t size)
{
    if (size == 0) size = 1;

    /* Round up to page boundary for mmap */
    size_t total = size + sizeof(size_t);
    size_t page_size = 4096;
    total = (total + page_size - 1) & ~(page_size - 1);

    void *ptr = sc_mmap(NULL, total,
                        SC_PROT_READ | SC_PROT_WRITE,
                        SC_MAP_PRIVATE | SC_MAP_ANONYMOUS,
                        -1, 0);
    if (ptr == SC_MAP_FAILED) {
        return NULL;
    }

    /* Store the total mapped size at the start */
    *(size_t *)ptr = total;
    return (void *)((size_t *)ptr + 1);
}

static inline void sc_free(void *ptr)
{
    if (ptr == NULL) return;
    size_t *header = (size_t *)ptr - 1;
    size_t total = *header;
    sc_munmap(header, total);
}

static inline void *sc_realloc(void *ptr, size_t new_size)
{
    if (ptr == NULL) {
        return sc_malloc(new_size);
    }
    if (new_size == 0) {
        sc_free(ptr);
        return NULL;
    }

    size_t *header = (size_t *)ptr - 1;
    size_t old_total = *header;
    size_t old_payload = old_total - sizeof(size_t);

    void *new_ptr = sc_malloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }

    /* Copy the smaller of old and new payload sizes */
    size_t copy_size = old_payload < new_size ? old_payload : new_size;
    /* Inline memcpy */
    unsigned char *d = (unsigned char *)new_ptr;
    const unsigned char *s = (const unsigned char *)ptr;
    for (size_t i = 0; i < copy_size; i++) {
        d[i] = s[i];
    }

    sc_free(ptr);
    return new_ptr;
}

/* ---- PIC base address calculation ------------------------------------- */

/**
 * Get the runtime base address of the current PIC binary.
 * This reads /proc/self/maps to find the first mapping that contains
 * our own code.  Works for PIE executables and shared objects.
 */
static inline uintptr_t sc_get_pic_base(void)
{
    /* Simple approach: our own function address gives us a pointer
     * within the loaded image.  We read /proc/self/maps to find
     * which mapping contains this address. */
    uintptr_t self_addr = (uintptr_t)&sc_get_pic_base;

    int fd = sc_openat(SC_AT_FDCWD, "/proc/self/maps", SC_O_RDONLY, 0);
    if (fd < 0) {
        return 0;
    }

    char buf[4096];
    long n = sc_read(fd, buf, sizeof(buf) - 1);
    sc_close(fd);

    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';

    /* Parse lines like: "55f8a3400000-55f8a3401000 r-xp ..." */
    const char *line = buf;
    while (*line) {
        /* Parse start address */
        uintptr_t start = 0;
        while (*line && *line != '-') {
            unsigned char c = (unsigned char)*line;
            if (c >= '0' && c <= '9')      start = (start << 4) | (uintptr_t)(c - '0');
            else if (c >= 'a' && c <= 'f') start = (start << 4) | (uintptr_t)(c - 'a' + 10);
            else break;
            line++;
        }
        if (*line == '-') line++;

        /* Parse end address */
        uintptr_t end = 0;
        while (*line && *line != ' ') {
            unsigned char c = (unsigned char)*line;
            if (c >= '0' && c <= '9')      end = (end << 4) | (uintptr_t)(c - '0');
            else if (c >= 'a' && c <= 'f') end = (end << 4) | (uintptr_t)(c - 'a' + 10);
            else break;
            line++;
        }

        /* Check if our address falls in this range */
        if (self_addr >= start && self_addr < end) {
            sc_close(fd);
            return start;
        }

        /* Skip to next line */
        while (*line && *line != '\n') line++;
        if (*line == '\n') line++;
    }

    return 0;
}

#endif /* __linux__ */
#endif /* SYSCALL_LINUX_H */
