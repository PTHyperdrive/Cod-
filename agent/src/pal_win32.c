/* ==========================================================================
 * pal_win32.c — Platform Abstraction Layer (Windows)
 * ==========================================================================
 * Win32 / Winsock2 implementation of the PAL interface defined in pal.h.
 * Covers sockets (Winsock2), process spawning (CreateProcess), file I/O,
 * timing, and system information.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#ifdef _WIN32

#include "pal.h"
#include "config.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>

/* MSVC links ws2_32 via this pragma; MinGW links it with -lws2_32 (see
 * the Makefile) and does not understand #pragma comment, so guard it. */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

/* ---- Platform initialisation ------------------------------------------ */

int pal_init(void)
{
    WSADATA wsa;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (result != 0) {
        fprintf(stderr, "[PAL] WSAStartup failed: %d\n", result);
        return -1;
    }
    return 0;
}

void pal_cleanup(void)
{
    WSACleanup();
}

/* ---- Sockets ---------------------------------------------------------- */

int pal_socket_create(void)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[PAL] socket failed: %d\n", WSAGetLastError());
        return -1;
    }
    return (int)sock;
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

    if (connect((SOCKET)sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[PAL] connect failed: %d\n", WSAGetLastError());
        return -1;
    }

    return 0;
}

int pal_socket_send(int sock, const void *buf, size_t len)
{
    const char *ptr = (const char *)buf;
    int remaining = (int)len;

    while (remaining > 0) {
        int sent = send((SOCKET)sock, ptr, remaining, 0);
        if (sent == SOCKET_ERROR) {
            fprintf(stderr, "[PAL] send failed: %d\n", WSAGetLastError());
            return -1;
        }
        ptr       += sent;
        remaining -= sent;
    }

    return 0;
}

int pal_socket_recv(int sock, void *buf, size_t len)
{
    char *ptr = (char *)buf;
    int remaining = (int)len;

    while (remaining > 0) {
        int received = recv((SOCKET)sock, ptr, remaining, 0);
        if (received <= 0) {
            if (received == 0) {
                fprintf(stderr, "[PAL] Connection closed by peer.\n");
            } else {
                fprintf(stderr, "[PAL] recv failed: %d\n", WSAGetLastError());
            }
            return -1;
        }
        ptr       += received;
        remaining -= received;
    }

    return 0;
}

void pal_socket_close(int sock)
{
    if (sock >= 0) {
        closesocket((SOCKET)sock);
    }
}

/* ---- Process execution ------------------------------------------------ */

int pal_spawn_process(const char *cmd, char *out_buf, size_t out_size,
                      int *exit_code)
{
    if (cmd == NULL || out_buf == NULL || exit_code == NULL) {
        return -1;
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    /* Create a pipe for stdout. */
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "[PAL] CreatePipe failed: %lu\n", GetLastError());
        *exit_code = -1;
        return -1;
    }

    /* Ensure the read handle is not inherited. */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* Build the command line: cmd.exe /C <command> */
    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /C %s", cmd);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessA(
        NULL,       /* lpApplicationName */
        cmdline,    /* lpCommandLine */
        NULL,       /* lpProcessAttributes */
        NULL,       /* lpThreadAttributes */
        TRUE,       /* bInheritHandles */
        0,          /* dwCreationFlags */
        NULL,       /* lpEnvironment */
        NULL,       /* lpCurrentDirectory */
        &si,        /* lpStartupInfo */
        &pi         /* lpProcessInformation */
    );

    /* Close the write end in this process — child has it. */
    CloseHandle(hWritePipe);

    if (!ok) {
        fprintf(stderr, "[PAL] CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hReadPipe);
        *exit_code = -1;
        return -1;
    }

    /* Read child output. */
    size_t total = 0;
    while (total < out_size - 1) {
        DWORD bytesRead = 0;
        BOOL result = ReadFile(hReadPipe, out_buf + total,
                               (DWORD)(out_size - 1 - total),
                               &bytesRead, NULL);
        if (!result || bytesRead == 0) {
            break;
        }
        total += bytesRead;
    }
    out_buf[total] = '\0';

    /* Wait for process to exit. */
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    *exit_code = (int)code;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

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
        fprintf(stderr, "[PAL] Cannot open file for reading: %s\n", path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
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
        fprintf(stderr, "[PAL] Cannot open file for writing: %s\n", path);
        return -1;
    }

    if (size > 0) {
        size_t written = fwrite(buf, 1, size, fp);
        if (written != size) {
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
    Sleep((DWORD)ms);
}

/* ---- Process control -------------------------------------------------- */

void pal_exit(int code)
{
    ExitProcess((UINT)code);
}

/* ---- System information ----------------------------------------------- */

int pal_get_hostname(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    DWORD buf_size = (DWORD)size;
    if (!GetComputerNameA(buf, &buf_size)) {
        fprintf(stderr, "[PAL] GetComputerName failed: %lu\n", GetLastError());
        strncpy(buf, "unknown", size - 1);
        buf[size - 1] = '\0';
        return -1;
    }

    return 0;
}

int pal_get_os_info(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    /* Use the version info available via GetVersionExA.
     * Note: On modern Windows (8.1+) this may be compatibility-shimmed,
     * but it's sufficient for lab identification purposes. */
    snprintf(buf, size, "Windows");
    return 0;
}

int pal_get_arch(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            snprintf(buf, size, "x86_64");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            snprintf(buf, size, "i386");
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            snprintf(buf, size, "aarch64");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            snprintf(buf, size, "armv7");
            break;
        default:
            snprintf(buf, size, "unknown");
            break;
    }

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

    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
}

#endif /* _WIN32 */
