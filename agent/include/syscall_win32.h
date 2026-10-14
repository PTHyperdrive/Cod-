/* ==========================================================================
 * syscall_win32.h — Native NT API Wrappers (ntdll-only, no CRT)
 * ==========================================================================
 * Pure ntdll.dll implementation — zero dependencies on kernel32.dll,
 * ws2_32.dll, ucrtbase.dll, or any C runtime library.
 *
 * All NT function pointers are resolved at runtime via PEB → LDR walk.
 * This header is the Windows counterpart of syscall_linux.h.
 *
 * Architecture:  x86_64 (Windows x64 calling convention)
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */
#ifndef SYSCALL_WIN32_H
#define SYSCALL_WIN32_H

#ifdef _WIN32

/* We deliberately avoid including <windows.h> and all CRT headers.
 * Every type is defined from scratch using only stdint/stddef which
 * are freestanding headers available without a CRT.                         */
#include <stdint.h>
#include <stddef.h>

/* ========================================================================
 * Section 1: NT Type Definitions (from-scratch, no windows.h)
 * ======================================================================== */

/* Basic Windows typedefs */
typedef int32_t     NT_LONG;
typedef uint32_t    NT_ULONG;
typedef int32_t     NT_NTSTATUS;
typedef uint16_t    NT_USHORT;
typedef int16_t     NT_SHORT;
typedef uint8_t     NT_UCHAR;
typedef int8_t      NT_CHAR;
typedef uint8_t     NT_BOOLEAN;
typedef void       *NT_HANDLE;
typedef void       *NT_PVOID;
typedef NT_ULONG    NT_ACCESS_MASK;
typedef uint16_t    NT_WCHAR;

#ifdef _WIN64
typedef uint64_t    NT_ULONG_PTR;
typedef int64_t     NT_LONG_PTR;
typedef uint64_t    NT_SIZE_T;
#else
typedef uint32_t    NT_ULONG_PTR;
typedef int32_t     NT_LONG_PTR;
typedef uint32_t    NT_SIZE_T;
#endif

/* NT status macros */
#define NT_SUCCESS(s)               ((NT_NTSTATUS)(s) >= 0)
#define NT_STATUS_SUCCESS           ((NT_NTSTATUS)0x00000000)
#define NT_STATUS_PENDING           ((NT_NTSTATUS)0x00000103)
#define NT_STATUS_BUFFER_OVERFLOW   ((NT_NTSTATUS)0x80000005)
#define NT_STATUS_NO_MORE_FILES     ((NT_NTSTATUS)0x80000006)
#define NT_STATUS_END_OF_FILE       ((NT_NTSTATUS)0xC0000011)
#define NT_STATUS_PIPE_BROKEN       ((NT_NTSTATUS)0xC000014B)

/* Handle constants */
#define NT_INVALID_HANDLE       ((NT_HANDLE)(NT_LONG_PTR)-1)
#define NT_NULL_HANDLE          ((NT_HANDLE)0)
#define NT_CURRENT_PROCESS      ((NT_HANDLE)(NT_LONG_PTR)-1)
#define NT_CURRENT_THREAD       ((NT_HANDLE)(NT_LONG_PTR)-2)

/* Object attributes flags */
#define NT_OBJ_CASE_INSENSITIVE     0x00000040UL
#define NT_OBJ_INHERIT              0x00000002UL

/* File access rights */
#define NT_FILE_READ_DATA           0x00000001UL
#define NT_FILE_WRITE_DATA          0x00000002UL
#define NT_FILE_READ_ATTRIBUTES     0x00000080UL
#define NT_FILE_WRITE_ATTRIBUTES    0x00000100UL
#define NT_FILE_APPEND_DATA         0x00000004UL
#define NT_SYNCHRONIZE              0x00100000UL
#define NT_GENERIC_READ             0x80000000UL
#define NT_GENERIC_WRITE            0x40000000UL
#define NT_DELETE_ACCESS            0x00010000UL

/* File share modes */
#define NT_FILE_SHARE_READ          0x00000001UL
#define NT_FILE_SHARE_WRITE         0x00000002UL
#define NT_FILE_SHARE_DELETE        0x00000004UL

/* File creation disposition */
#define NT_FILE_SUPERSEDE           0x00000000UL
#define NT_FILE_OPEN                0x00000001UL
#define NT_FILE_CREATE              0x00000002UL
#define NT_FILE_OPEN_IF             0x00000003UL
#define NT_FILE_OVERWRITE           0x00000004UL
#define NT_FILE_OVERWRITE_IF        0x00000005UL

/* File create options */
#define NT_FILE_SYNCHRONOUS_IO_NONALERT  0x00000020UL
#define NT_FILE_NON_DIRECTORY_FILE       0x00000040UL
#define NT_FILE_DIRECTORY_FILE           0x00000001UL

/* File information classes */
#define NT_FileStandardInformation       5
#define NT_FilePositionInformation      14

/* Process creation flags */
#define NT_PROCESS_ALL_ACCESS       0x001FFFFFUL
#define NT_THREAD_ALL_ACCESS        0x001FFFFFUL

/* Memory allocation */
#define NT_MEM_COMMIT               0x00001000UL
#define NT_MEM_RESERVE              0x00002000UL
#define NT_MEM_RELEASE              0x00008000UL
#define NT_PAGE_READWRITE           0x00000004UL
#define NT_PAGE_EXECUTE_READWRITE   0x00000040UL

/* NtSetInformationProcess classes */
#define NT_ProcessBreakOnTermination    29UL

/* Privilege IDs */
#define NT_SE_DEBUG_PRIVILEGE           20UL

/* IOCTL codes for AFD (Ancillary Function Driver) — Winsock's kernel driver */
#define AFD_BIND                    0x00012003UL
#define AFD_CONNECT                 0x00012007UL
#define AFD_SEND                    0x0001201FUL
#define AFD_RECV                    0x00012017UL
#define AFD_DISCONNECT              0x0001202BUL
#define AFD_SET_INFO                0x0001203BUL

/* Address families */
#define NT_AF_INET                  2
#define NT_AF_INET6                 23

/* Socket types */
#define NT_SOCK_STREAM              1
#define NT_SOCK_DGRAM               2

/* IPPROTO */
#define NT_IPPROTO_TCP              6
#define NT_IPPROTO_UDP              17

/* System information classes */
#define NT_SystemTimeOfDayInformation   3
#define NT_SystemBasicInformation       0

/* Process information class for NtQueryInformationProcess */
#define NT_ProcessBasicInformation      0
#define NT_ProcessImageFileName         27

/* ========================================================================
 * Section 2: NT Structures
 * ======================================================================== */

typedef struct _NT_UNICODE_STRING {
    NT_USHORT   Length;
    NT_USHORT   MaximumLength;
    NT_WCHAR   *Buffer;
} NT_UNICODE_STRING;

typedef struct _NT_OBJECT_ATTRIBUTES {
    NT_ULONG                Length;
    NT_HANDLE               RootDirectory;
    NT_UNICODE_STRING      *ObjectName;
    NT_ULONG                Attributes;
    NT_PVOID                SecurityDescriptor;
    NT_PVOID                SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES;

typedef struct _NT_IO_STATUS_BLOCK {
    union {
        NT_NTSTATUS Status;
        NT_PVOID    Pointer;
    } u;
    NT_ULONG_PTR Information;
} NT_IO_STATUS_BLOCK;

typedef struct _NT_LARGE_INTEGER {
    union {
        struct {
            NT_ULONG LowPart;
            NT_LONG  HighPart;
        } s;
        int64_t QuadPart;
    };
} NT_LARGE_INTEGER;

typedef struct _NT_FILE_STANDARD_INFORMATION {
    NT_LARGE_INTEGER AllocationSize;
    NT_LARGE_INTEGER EndOfStream;
    NT_ULONG         NumberOfLinks;
    NT_BOOLEAN       DeletePending;
    NT_BOOLEAN       Directory;
} NT_FILE_STANDARD_INFORMATION;

typedef struct _NT_FILE_POSITION_INFORMATION {
    NT_LARGE_INTEGER CurrentByteOffset;
} NT_FILE_POSITION_INFORMATION;

/* sockaddr_in equivalent */
typedef struct _NT_SOCKADDR_IN {
    NT_SHORT    sin_family;
    NT_USHORT   sin_port;
    uint32_t    sin_addr;
    NT_CHAR     sin_zero[8];
} NT_SOCKADDR_IN;

/* AFD structures for socket operations */
typedef struct _AFD_CONNECT_INFO {
    NT_BOOLEAN          UseSAN;
    NT_ULONG            Root;
    NT_ULONG            Unknown;
    NT_SOCKADDR_IN      RemoteAddress;
} AFD_CONNECT_INFO;

typedef struct _AFD_WSABUF {
    NT_ULONG    len;
    NT_PVOID    buf;
} AFD_WSABUF;

typedef struct _AFD_SEND_INFO {
    AFD_WSABUF *BufferArray;
    NT_ULONG    BufferCount;
    NT_ULONG    AfdFlags;
    NT_ULONG    TdiFlags;
} AFD_SEND_INFO;

#define AFD_SEND_FLAGS_NONE 0

typedef struct _AFD_RECV_INFO {
    AFD_WSABUF *BufferArray;
    NT_ULONG    BufferCount;
    NT_ULONG    AfdFlags;
    NT_ULONG    TdiFlags;
} AFD_RECV_INFO;

#define TDI_RECEIVE_NORMAL  0x00000000UL

typedef struct _AFD_BIND_INFO {
    NT_ULONG        ShareType;
    NT_SOCKADDR_IN  Address;
} AFD_BIND_INFO;

/* EA (Extended Attributes) buffer for AFD socket creation */
typedef struct _NT_FILE_FULL_EA_INFORMATION {
    NT_ULONG    NextEntryOffset;
    NT_UCHAR    Flags;
    NT_UCHAR    EaNameLength;
    NT_USHORT   EaValueLength;
    NT_CHAR     EaName[1]; /* Variable length, followed by value */
} NT_FILE_FULL_EA_INFORMATION;

/* AFD open packet — passed as EA value when creating socket handle */
typedef struct _AFD_OPEN_PACKET {
    NT_ULONG    afdFlags;
    NT_ULONG    groupID;
    NT_ULONG    addressFamily;
    NT_ULONG    socketType;
    NT_ULONG    protocol;
    NT_ULONG    sizeOfTransportName;
    NT_WCHAR    transportName[1]; /* Variable: L"\\Device\\Tcp" etc. */
} AFD_OPEN_PACKET;

/* For NtCreateUserProcess */
typedef struct _NT_RTL_USER_PROCESS_PARAMETERS {
    NT_ULONG            MaximumLength;
    NT_ULONG            Length;
    NT_ULONG            Flags;
    NT_ULONG            DebugFlags;
    NT_HANDLE           ConsoleHandle;
    NT_ULONG            ConsoleFlags;
    NT_HANDLE           StandardInput;
    NT_HANDLE           StandardOutput;
    NT_HANDLE           StandardError;
    NT_UNICODE_STRING   CurrentDirectory_DosPath;
    NT_HANDLE           CurrentDirectory_Handle;
    NT_UNICODE_STRING   DllPath;
    NT_UNICODE_STRING   ImagePathName;
    NT_UNICODE_STRING   CommandLine;
    /* ... more fields follow but we don't need them */
} NT_RTL_USER_PROCESS_PARAMETERS;

/* Computer name from registry key */
typedef struct _NT_KEY_VALUE_PARTIAL_INFORMATION {
    NT_ULONG TitleIndex;
    NT_ULONG Type;
    NT_ULONG DataLength;
    NT_UCHAR Data[1]; /* Variable length */
} NT_KEY_VALUE_PARTIAL_INFORMATION;

/* System time info */
typedef struct _NT_SYSTEM_TIMEOFDAY_INFORMATION {
    NT_LARGE_INTEGER BootTime;
    NT_LARGE_INTEGER CurrentTime;
    NT_LARGE_INTEGER TimeZoneBias;
    NT_ULONG         TimeZoneId;
    NT_ULONG         Reserved;
    uint64_t         BootTimeBias;
    uint64_t         SleepTimeBias;
} NT_SYSTEM_TIMEOFDAY_INFORMATION;

/* Security attributes for handle inheritance */
typedef struct _NT_SECURITY_ATTRIBUTES {
    NT_ULONG    nLength;
    NT_PVOID    lpSecurityDescriptor;
    NT_BOOLEAN  bInheritHandle;
} NT_SECURITY_ATTRIBUTES;

/* PEB / LDR structures for module enumeration (no GetModuleHandle) */
typedef struct _NT_LDR_DATA_TABLE_ENTRY {
    /* LIST_ENTRY InLoadOrderLinks */
    struct _NT_LDR_DATA_TABLE_ENTRY *Flink_Load;
    struct _NT_LDR_DATA_TABLE_ENTRY *Blink_Load;
    /* LIST_ENTRY InMemoryOrderLinks */
    struct _NT_LDR_DATA_TABLE_ENTRY *Flink_Mem;
    struct _NT_LDR_DATA_TABLE_ENTRY *Blink_Mem;
    /* LIST_ENTRY InInitializationOrderLinks */
    struct _NT_LDR_DATA_TABLE_ENTRY *Flink_Init;
    struct _NT_LDR_DATA_TABLE_ENTRY *Blink_Init;
    NT_PVOID            DllBase;
    NT_PVOID            EntryPoint;
    NT_ULONG            SizeOfImage;
    NT_UNICODE_STRING   FullDllName;
    NT_UNICODE_STRING   BaseDllName;
    /* ... more fields follow */
} NT_LDR_DATA_TABLE_ENTRY;

typedef struct _NT_PEB_LDR_DATA {
    NT_ULONG    Length;
    NT_BOOLEAN  Initialized;
    NT_PVOID    SsHandle;
    /* InLoadOrderModuleList */
    NT_LDR_DATA_TABLE_ENTRY *InLoadOrderModuleList_Flink;
    NT_LDR_DATA_TABLE_ENTRY *InLoadOrderModuleList_Blink;
    /* InMemoryOrderModuleList */
    NT_LDR_DATA_TABLE_ENTRY *InMemoryOrderModuleList_Flink;
    NT_LDR_DATA_TABLE_ENTRY *InMemoryOrderModuleList_Blink;
} NT_PEB_LDR_DATA;

typedef struct _NT_PEB {
    NT_UCHAR            Reserved1[2];
    NT_UCHAR            BeingDebugged;
    NT_UCHAR            Reserved2[1];
    NT_PVOID            Reserved3[2];
    NT_PEB_LDR_DATA    *Ldr;
    NT_RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
    /* ... many more fields follow */
} NT_PEB;

/* PE export directory for manual symbol resolution */
typedef struct _NT_IMAGE_DOS_HEADER {
    NT_USHORT   e_magic;
    NT_USHORT   e_cblp;
    NT_USHORT   e_cp;
    NT_USHORT   e_crlc;
    NT_USHORT   e_cparhdr;
    NT_USHORT   e_minalloc;
    NT_USHORT   e_maxalloc;
    NT_USHORT   e_ss;
    NT_USHORT   e_sp;
    NT_USHORT   e_csum;
    NT_USHORT   e_ip;
    NT_USHORT   e_cs;
    NT_USHORT   e_lfarlc;
    NT_USHORT   e_ovno;
    NT_USHORT   e_res[4];
    NT_USHORT   e_oemid;
    NT_USHORT   e_oeminfo;
    NT_USHORT   e_res2[10];
    NT_LONG     e_lfanew;
} NT_IMAGE_DOS_HEADER;

typedef struct _NT_IMAGE_FILE_HEADER {
    NT_USHORT   Machine;
    NT_USHORT   NumberOfSections;
    NT_ULONG    TimeDateStamp;
    NT_ULONG    PointerToSymbolTable;
    NT_ULONG    NumberOfSymbols;
    NT_USHORT   SizeOfOptionalHeader;
    NT_USHORT   Characteristics;
} NT_IMAGE_FILE_HEADER;

typedef struct _NT_IMAGE_DATA_DIRECTORY {
    NT_ULONG    VirtualAddress;
    NT_ULONG    Size;
} NT_IMAGE_DATA_DIRECTORY;

typedef struct _NT_IMAGE_OPTIONAL_HEADER64 {
    NT_USHORT   Magic;
    NT_UCHAR    MajorLinkerVersion;
    NT_UCHAR    MinorLinkerVersion;
    NT_ULONG    SizeOfCode;
    NT_ULONG    SizeOfInitializedData;
    NT_ULONG    SizeOfUninitializedData;
    NT_ULONG    AddressOfEntryPoint;
    NT_ULONG    BaseOfCode;
    uint64_t    ImageBase;
    NT_ULONG    SectionAlignment;
    NT_ULONG    FileAlignment;
    NT_USHORT   MajorOperatingSystemVersion;
    NT_USHORT   MinorOperatingSystemVersion;
    NT_USHORT   MajorImageVersion;
    NT_USHORT   MinorImageVersion;
    NT_USHORT   MajorSubsystemVersion;
    NT_USHORT   MinorSubsystemVersion;
    NT_ULONG    Win32VersionValue;
    NT_ULONG    SizeOfImage;
    NT_ULONG    SizeOfHeaders;
    NT_ULONG    CheckSum;
    NT_USHORT   Subsystem;
    NT_USHORT   DllCharacteristics;
    uint64_t    SizeOfStackReserve;
    uint64_t    SizeOfStackCommit;
    uint64_t    SizeOfHeapReserve;
    uint64_t    SizeOfHeapCommit;
    NT_ULONG    LoaderFlags;
    NT_ULONG    NumberOfRvaAndSizes;
    NT_IMAGE_DATA_DIRECTORY DataDirectory[16];
} NT_IMAGE_OPTIONAL_HEADER64;

typedef struct _NT_IMAGE_NT_HEADERS64 {
    NT_ULONG                    Signature;
    NT_IMAGE_FILE_HEADER        FileHeader;
    NT_IMAGE_OPTIONAL_HEADER64  OptionalHeader;
} NT_IMAGE_NT_HEADERS64;

typedef struct _NT_IMAGE_EXPORT_DIRECTORY {
    NT_ULONG    Characteristics;
    NT_ULONG    TimeDateStamp;
    NT_USHORT   MajorVersion;
    NT_USHORT   MinorVersion;
    NT_ULONG    Name;
    NT_ULONG    Base;
    NT_ULONG    NumberOfFunctions;
    NT_ULONG    NumberOfNames;
    NT_ULONG    AddressOfFunctions;
    NT_ULONG    AddressOfNames;
    NT_ULONG    AddressOfNameOrdinals;
} NT_IMAGE_EXPORT_DIRECTORY;

/* ========================================================================
 * Section 3: NT Function Pointer Typedefs
 * ======================================================================== */

/* Calling convention */
#define NTAPI __stdcall

/* File operations */
typedef NT_NTSTATUS (NTAPI *fn_NtCreateFile)(
    NT_HANDLE *FileHandle, NT_ACCESS_MASK DesiredAccess,
    NT_OBJECT_ATTRIBUTES *ObjectAttributes, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_LARGE_INTEGER *AllocationSize, NT_ULONG FileAttributes,
    NT_ULONG ShareAccess, NT_ULONG CreateDisposition, NT_ULONG CreateOptions,
    NT_PVOID EaBuffer, NT_ULONG EaLength);

typedef NT_NTSTATUS (NTAPI *fn_NtReadFile)(
    NT_HANDLE FileHandle, NT_HANDLE Event, NT_PVOID ApcRoutine,
    NT_PVOID ApcContext, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_PVOID Buffer, NT_ULONG Length, NT_LARGE_INTEGER *ByteOffset,
    NT_PVOID Key);

typedef NT_NTSTATUS (NTAPI *fn_NtWriteFile)(
    NT_HANDLE FileHandle, NT_HANDLE Event, NT_PVOID ApcRoutine,
    NT_PVOID ApcContext, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_PVOID Buffer, NT_ULONG Length, NT_LARGE_INTEGER *ByteOffset,
    NT_PVOID Key);

typedef NT_NTSTATUS (NTAPI *fn_NtClose)(NT_HANDLE Handle);

typedef NT_NTSTATUS (NTAPI *fn_NtQueryInformationFile)(
    NT_HANDLE FileHandle, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_PVOID FileInformation, NT_ULONG Length,
    NT_ULONG FileInformationClass);

typedef NT_NTSTATUS (NTAPI *fn_NtSetInformationFile)(
    NT_HANDLE FileHandle, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_PVOID FileInformation, NT_ULONG Length,
    NT_ULONG FileInformationClass);

/* Socket/device IOCTL */
typedef NT_NTSTATUS (NTAPI *fn_NtDeviceIoControlFile)(
    NT_HANDLE FileHandle, NT_HANDLE Event, NT_PVOID ApcRoutine,
    NT_PVOID ApcContext, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_ULONG IoControlCode, NT_PVOID InputBuffer, NT_ULONG InputBufferLength,
    NT_PVOID OutputBuffer, NT_ULONG OutputBufferLength);

/* Memory */
typedef NT_NTSTATUS (NTAPI *fn_NtAllocateVirtualMemory)(
    NT_HANDLE ProcessHandle, NT_PVOID *BaseAddress, NT_ULONG_PTR ZeroBits,
    NT_SIZE_T *RegionSize, NT_ULONG AllocationType, NT_ULONG Protect);

typedef NT_NTSTATUS (NTAPI *fn_NtFreeVirtualMemory)(
    NT_HANDLE ProcessHandle, NT_PVOID *BaseAddress,
    NT_SIZE_T *RegionSize, NT_ULONG FreeType);

/* Process */
typedef NT_NTSTATUS (NTAPI *fn_NtSetInformationProcess)(
    NT_HANDLE ProcessHandle, NT_ULONG ProcessInformationClass,
    NT_PVOID ProcessInformation, NT_ULONG ProcessInformationLength);

typedef NT_NTSTATUS (NTAPI *fn_NtQueryInformationProcess)(
    NT_HANDLE ProcessHandle, NT_ULONG ProcessInformationClass,
    NT_PVOID ProcessInformation, NT_ULONG ProcessInformationLength,
    NT_ULONG *ReturnLength);

typedef NT_NTSTATUS (NTAPI *fn_NtTerminateProcess)(
    NT_HANDLE ProcessHandle, NT_NTSTATUS ExitStatus);

typedef NT_NTSTATUS (NTAPI *fn_NtWaitForSingleObject)(
    NT_HANDLE Handle, NT_BOOLEAN Alertable, NT_LARGE_INTEGER *Timeout);

/* Process spawning — we use RtlCreateProcessParametersEx + NtCreateUserProcess
 * but NtCreateUserProcess is complex, so we fall back to a simpler pipe+spawn
 * approach using NtCreateNamedPipeFile + raw process creation. */

/* For process creation, we use RtlCreateProcessParametersEx */
typedef NT_NTSTATUS (NTAPI *fn_RtlCreateProcessParametersEx)(
    NT_RTL_USER_PROCESS_PARAMETERS **pProcessParameters,
    NT_UNICODE_STRING *ImagePathName, NT_UNICODE_STRING *DllPath,
    NT_UNICODE_STRING *CurrentDirectory, NT_UNICODE_STRING *CommandLine,
    NT_PVOID Environment, NT_UNICODE_STRING *WindowTitle,
    NT_UNICODE_STRING *DesktopInfo, NT_UNICODE_STRING *ShellInfo,
    NT_UNICODE_STRING *RuntimeData, NT_ULONG Flags);

typedef NT_NTSTATUS (NTAPI *fn_RtlDestroyProcessParameters)(
    NT_RTL_USER_PROCESS_PARAMETERS *ProcessParameters);

/* Pipe */
typedef NT_NTSTATUS (NTAPI *fn_NtCreateNamedPipeFile)(
    NT_HANDLE *FileHandle, NT_ULONG DesiredAccess,
    NT_OBJECT_ATTRIBUTES *ObjectAttributes, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_ULONG ShareAccess, NT_ULONG CreateDisposition, NT_ULONG CreateOptions,
    NT_ULONG NamedPipeType, NT_ULONG ReadMode, NT_ULONG CompletionMode,
    NT_ULONG MaximumInstances, NT_ULONG InboundQuota,
    NT_ULONG OutboundQuota, NT_LARGE_INTEGER *DefaultTimeout);

/* Registry (for hostname / OS info) */
typedef NT_NTSTATUS (NTAPI *fn_NtOpenKey)(
    NT_HANDLE *KeyHandle, NT_ACCESS_MASK DesiredAccess,
    NT_OBJECT_ATTRIBUTES *ObjectAttributes);

typedef NT_NTSTATUS (NTAPI *fn_NtQueryValueKey)(
    NT_HANDLE KeyHandle, NT_UNICODE_STRING *ValueName,
    NT_ULONG KeyValueInformationClass, NT_PVOID KeyValueInformation,
    NT_ULONG Length, NT_ULONG *ResultLength);

#define NT_KeyValuePartialInformation  2
#define NT_KEY_READ                    0x00020019UL

/* System information */
typedef NT_NTSTATUS (NTAPI *fn_NtQuerySystemInformation)(
    NT_ULONG SystemInformationClass, NT_PVOID SystemInformation,
    NT_ULONG SystemInformationLength, NT_ULONG *ReturnLength);

/* Time */
typedef NT_NTSTATUS (NTAPI *fn_NtQuerySystemTime)(
    NT_LARGE_INTEGER *SystemTime);

/* Delay execution (Sleep equivalent) */
typedef NT_NTSTATUS (NTAPI *fn_NtDelayExecution)(
    NT_BOOLEAN Alertable, NT_LARGE_INTEGER *DelayInterval);

/* String utilities from ntdll */
typedef void (NTAPI *fn_RtlInitUnicodeString)(
    NT_UNICODE_STRING *DestinationString, const NT_WCHAR *SourceString);

typedef NT_NTSTATUS (NTAPI *fn_RtlAdjustPrivilege)(
    NT_ULONG Privilege, NT_BOOLEAN Enable,
    NT_BOOLEAN CurrentThread, NT_BOOLEAN *OldValue);

typedef NT_ULONG (NTAPI *fn_RtlNtStatusToDosError)(NT_NTSTATUS Status);

typedef NT_NTSTATUS (NTAPI *fn_NtCreateSection)(
    NT_HANDLE *SectionHandle, NT_ACCESS_MASK DesiredAccess,
    NT_OBJECT_ATTRIBUTES *ObjectAttributes, NT_LARGE_INTEGER *MaximumSize,
    NT_ULONG SectionPageProtection, NT_ULONG AllocationAttributes,
    NT_HANDLE FileHandle);

/* NtCreateUserProcess (Vista+) */
typedef NT_NTSTATUS (NTAPI *fn_NtCreateUserProcess)(
    NT_HANDLE *ProcessHandle, NT_HANDLE *ThreadHandle,
    NT_ACCESS_MASK ProcessDesiredAccess, NT_ACCESS_MASK ThreadDesiredAccess,
    NT_OBJECT_ATTRIBUTES *ProcessObjectAttributes,
    NT_OBJECT_ATTRIBUTES *ThreadObjectAttributes,
    NT_ULONG ProcessFlags, NT_ULONG ThreadFlags,
    NT_PVOID ProcessParameters,
    NT_PVOID CreateInfo,
    NT_PVOID AttributeList);

/* NtResumeThread */
typedef NT_NTSTATUS (NTAPI *fn_NtResumeThread)(
    NT_HANDLE ThreadHandle, NT_ULONG *PreviousSuspendCount);

/* NtOpenFile (simpler than NtCreateFile for read-only) */
typedef NT_NTSTATUS (NTAPI *fn_NtOpenFile)(
    NT_HANDLE *FileHandle, NT_ACCESS_MASK DesiredAccess,
    NT_OBJECT_ATTRIBUTES *ObjectAttributes, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_ULONG ShareAccess, NT_ULONG OpenOptions);

/* Flock equivalent — NtLockFile */
typedef NT_NTSTATUS (NTAPI *fn_NtLockFile)(
    NT_HANDLE FileHandle, NT_HANDLE Event, NT_PVOID ApcRoutine,
    NT_PVOID ApcContext, NT_IO_STATUS_BLOCK *IoStatusBlock,
    NT_LARGE_INTEGER *ByteOffset, NT_LARGE_INTEGER *Length,
    NT_ULONG Key, NT_BOOLEAN FailImmediately, NT_BOOLEAN ExclusiveLock);

/* RtlDosPathNameToNtPathName */
typedef NT_BOOLEAN (NTAPI *fn_RtlDosPathNameToNtPathName_U)(
    const NT_WCHAR *DosFileName, NT_UNICODE_STRING *NtFileName,
    NT_WCHAR **FilePart, NT_PVOID Reserved);

typedef void (NTAPI *fn_RtlFreeUnicodeString)(NT_UNICODE_STRING *UnicodeString);

/* ========================================================================
 * Section 4: Global Function Pointer Table
 * ======================================================================== */

/* All resolved ntdll pointers live in this struct. */
typedef struct _NT_SYSCALL_TABLE {
    /* File I/O */
    fn_NtCreateFile                     NtCreateFile;
    fn_NtOpenFile                       NtOpenFile;
    fn_NtReadFile                       NtReadFile;
    fn_NtWriteFile                      NtWriteFile;
    fn_NtClose                          NtClose;
    fn_NtQueryInformationFile           NtQueryInformationFile;
    fn_NtSetInformationFile             NtSetInformationFile;

    /* Device IOCTL (sockets) */
    fn_NtDeviceIoControlFile            NtDeviceIoControlFile;

    /* Memory */
    fn_NtAllocateVirtualMemory          NtAllocateVirtualMemory;
    fn_NtFreeVirtualMemory              NtFreeVirtualMemory;

    /* Process */
    fn_NtSetInformationProcess          NtSetInformationProcess;
    fn_NtQueryInformationProcess        NtQueryInformationProcess;
    fn_NtTerminateProcess               NtTerminateProcess;
    fn_NtWaitForSingleObject            NtWaitForSingleObject;
    fn_NtCreateUserProcess              NtCreateUserProcess;
    fn_NtResumeThread                   NtResumeThread;

    /* Pipe */
    fn_NtCreateNamedPipeFile            NtCreateNamedPipeFile;

    /* Registry */
    fn_NtOpenKey                        NtOpenKey;
    fn_NtQueryValueKey                  NtQueryValueKey;

    /* System */
    fn_NtQuerySystemInformation         NtQuerySystemInformation;
    fn_NtQuerySystemTime                NtQuerySystemTime;
    fn_NtDelayExecution                 NtDelayExecution;

    /* Lock */
    fn_NtLockFile                       NtLockFile;

    /* Rtl helpers */
    fn_RtlInitUnicodeString             RtlInitUnicodeString;
    fn_RtlAdjustPrivilege               RtlAdjustPrivilege;
    fn_RtlNtStatusToDosError            RtlNtStatusToDosError;
    fn_RtlCreateProcessParametersEx     RtlCreateProcessParametersEx;
    fn_RtlDestroyProcessParameters      RtlDestroyProcessParameters;
    fn_RtlDosPathNameToNtPathName_U     RtlDosPathNameToNtPathName_U;
    fn_RtlFreeUnicodeString             RtlFreeUnicodeString;

    /* Section */
    fn_NtCreateSection                  NtCreateSection;

    /* Initialised flag */
    int                                 initialized;
} NT_SYSCALL_TABLE;

static NT_SYSCALL_TABLE g_nt = { 0 };

/* ========================================================================
 * Section 5: PEB Walk — Find ntdll.dll Base (no GetModuleHandle)
 * ======================================================================== */

static inline NT_PEB *_nt_get_peb(void)
{
    /* On x64 Windows, the PEB is at gs:[0x60] */
    NT_PEB *peb;
#ifdef _MSC_VER
    peb = (NT_PEB *)__readgsqword(0x60);
#else
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));
#endif
    return peb;
}

/* Simple case-insensitive wide-char comparison (ASCII range only) */
static inline int _nt_wstricmp(const NT_WCHAR *a, const NT_WCHAR *b)
{
    while (*a && *b) {
        NT_WCHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    NT_WCHAR ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z') ca += 32;
    if (cb >= 'A' && cb <= 'Z') cb += 32;
    return (int)ca - (int)cb;
}

/* Find a loaded module by name via PEB → LDR walk */
static inline NT_PVOID _nt_get_module_base(const NT_WCHAR *name)
{
    NT_PEB *peb = _nt_get_peb();
    if (!peb || !peb->Ldr) return (NT_PVOID)0;

    /* Walk InLoadOrderModuleList */
    NT_LDR_DATA_TABLE_ENTRY *head =
        peb->Ldr->InLoadOrderModuleList_Flink;
    NT_LDR_DATA_TABLE_ENTRY *entry = head;

    do {
        if (entry->BaseDllName.Buffer && entry->DllBase) {
            if (_nt_wstricmp(entry->BaseDllName.Buffer, name) == 0) {
                return entry->DllBase;
            }
        }
        entry = entry->Flink_Load;
    } while (entry && entry != head);

    return (NT_PVOID)0;
}

/* ========================================================================
 * Section 6: PE Export Resolution (no GetProcAddress)
 * ======================================================================== */

/* Simple ASCII strcmp */
static inline int _nt_astrcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* Resolve an export by name from a PE module base */
static inline NT_PVOID _nt_get_proc_address(NT_PVOID module_base,
                                             const char *func_name)
{
    uint8_t *base = (uint8_t *)module_base;

    NT_IMAGE_DOS_HEADER *dos = (NT_IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != 0x5A4D) return (NT_PVOID)0; /* "MZ" */

    NT_IMAGE_NT_HEADERS64 *nt =
        (NT_IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return (NT_PVOID)0; /* "PE\0\0" */

    NT_IMAGE_DATA_DIRECTORY *export_dir =
        &nt->OptionalHeader.DataDirectory[0]; /* IMAGE_DIRECTORY_ENTRY_EXPORT */
    if (export_dir->Size == 0) return (NT_PVOID)0;

    NT_IMAGE_EXPORT_DIRECTORY *exports =
        (NT_IMAGE_EXPORT_DIRECTORY *)(base + export_dir->VirtualAddress);

    NT_ULONG *names     = (NT_ULONG *)(base + exports->AddressOfNames);
    NT_USHORT *ordinals = (NT_USHORT *)(base + exports->AddressOfNameOrdinals);
    NT_ULONG *functions = (NT_ULONG *)(base + exports->AddressOfFunctions);

    for (NT_ULONG i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (_nt_astrcmp(name, func_name) == 0) {
            NT_ULONG rva = functions[ordinals[i]];
            /* Check for forwarder (RVA points within export directory) */
            if (rva >= export_dir->VirtualAddress &&
                rva < export_dir->VirtualAddress + export_dir->Size) {
                /* Forwarder — not handled, return NULL */
                return (NT_PVOID)0;
            }
            return (NT_PVOID)(base + rva);
        }
    }
    return (NT_PVOID)0;
}

/* ========================================================================
 * Section 7: Syscall Table Initialisation
 * ======================================================================== */

#define _NT_RESOLVE(table, mod, name) \
    (table)->name = (fn_##name)_nt_get_proc_address(mod, #name)

static inline int nt_syscall_init(void)
{
    if (g_nt.initialized) return 0;

    NT_PVOID ntdll = _nt_get_module_base(L"ntdll.dll");
    if (!ntdll) return -1;

    /* File I/O */
    _NT_RESOLVE(&g_nt, ntdll, NtCreateFile);
    _NT_RESOLVE(&g_nt, ntdll, NtOpenFile);
    _NT_RESOLVE(&g_nt, ntdll, NtReadFile);
    _NT_RESOLVE(&g_nt, ntdll, NtWriteFile);
    _NT_RESOLVE(&g_nt, ntdll, NtClose);
    _NT_RESOLVE(&g_nt, ntdll, NtQueryInformationFile);
    _NT_RESOLVE(&g_nt, ntdll, NtSetInformationFile);

    /* Device IOCTL */
    _NT_RESOLVE(&g_nt, ntdll, NtDeviceIoControlFile);

    /* Memory */
    _NT_RESOLVE(&g_nt, ntdll, NtAllocateVirtualMemory);
    _NT_RESOLVE(&g_nt, ntdll, NtFreeVirtualMemory);

    /* Process */
    _NT_RESOLVE(&g_nt, ntdll, NtSetInformationProcess);
    _NT_RESOLVE(&g_nt, ntdll, NtQueryInformationProcess);
    _NT_RESOLVE(&g_nt, ntdll, NtTerminateProcess);
    _NT_RESOLVE(&g_nt, ntdll, NtWaitForSingleObject);
    _NT_RESOLVE(&g_nt, ntdll, NtCreateUserProcess);
    _NT_RESOLVE(&g_nt, ntdll, NtResumeThread);

    /* Pipe */
    _NT_RESOLVE(&g_nt, ntdll, NtCreateNamedPipeFile);

    /* Registry */
    _NT_RESOLVE(&g_nt, ntdll, NtOpenKey);
    _NT_RESOLVE(&g_nt, ntdll, NtQueryValueKey);

    /* System */
    _NT_RESOLVE(&g_nt, ntdll, NtQuerySystemInformation);
    _NT_RESOLVE(&g_nt, ntdll, NtQuerySystemTime);
    _NT_RESOLVE(&g_nt, ntdll, NtDelayExecution);

    /* Lock */
    _NT_RESOLVE(&g_nt, ntdll, NtLockFile);

    /* Section */
    _NT_RESOLVE(&g_nt, ntdll, NtCreateSection);

    /* Rtl helpers */
    _NT_RESOLVE(&g_nt, ntdll, RtlInitUnicodeString);
    _NT_RESOLVE(&g_nt, ntdll, RtlAdjustPrivilege);
    _NT_RESOLVE(&g_nt, ntdll, RtlNtStatusToDosError);
    _NT_RESOLVE(&g_nt, ntdll, RtlCreateProcessParametersEx);
    _NT_RESOLVE(&g_nt, ntdll, RtlDestroyProcessParameters);
    _NT_RESOLVE(&g_nt, ntdll, RtlDosPathNameToNtPathName_U);
    _NT_RESOLVE(&g_nt, ntdll, RtlFreeUnicodeString);

    /* Validate critical functions are resolved */
    if (!g_nt.NtCreateFile || !g_nt.NtReadFile || !g_nt.NtWriteFile ||
        !g_nt.NtClose || !g_nt.NtAllocateVirtualMemory ||
        !g_nt.NtDeviceIoControlFile) {
        return -1;
    }

    g_nt.initialized = 1;
    return 0;
}

#undef _NT_RESOLVE

/* ========================================================================
 * Section 8: NT Allocator (replaces malloc/free)
 * ======================================================================== */

static inline void *nt_malloc(size_t size)
{
    if (size == 0) size = 1;
    /* Add header for storing the region size */
    size_t total = size + sizeof(size_t);
    NT_PVOID base = (NT_PVOID)0;
    NT_SIZE_T region_size = (NT_SIZE_T)total;

    NT_NTSTATUS status = g_nt.NtAllocateVirtualMemory(
        NT_CURRENT_PROCESS, &base, 0, &region_size,
        NT_MEM_COMMIT | NT_MEM_RESERVE, NT_PAGE_READWRITE);

    if (!NT_SUCCESS(status)) return (void *)0;

    /* Store the allocated region size at the start */
    *(size_t *)base = region_size;
    return (void *)((size_t *)base + 1);
}

static inline void nt_free(void *ptr)
{
    if (!ptr) return;
    size_t *header = (size_t *)ptr - 1;
    NT_PVOID base = (NT_PVOID)header;
    NT_SIZE_T region_size = 0; /* Must be 0 for MEM_RELEASE */

    g_nt.NtFreeVirtualMemory(NT_CURRENT_PROCESS, &base,
                             &region_size, NT_MEM_RELEASE);
}

static inline void *nt_realloc(void *ptr, size_t new_size)
{
    if (!ptr) return nt_malloc(new_size);
    if (new_size == 0) { nt_free(ptr); return (void *)0; }

    size_t *header = (size_t *)ptr - 1;
    size_t old_region = *header;
    size_t old_payload = old_region - sizeof(size_t);

    void *new_ptr = nt_malloc(new_size);
    if (!new_ptr) return (void *)0;

    size_t copy_size = old_payload < new_size ? old_payload : new_size;
    uint8_t *d = (uint8_t *)new_ptr;
    const uint8_t *s = (const uint8_t *)ptr;
    for (size_t i = 0; i < copy_size; i++) d[i] = s[i];

    nt_free(ptr);
    return new_ptr;
}

/* ========================================================================
 * Section 9: Helper Utilities
 * ======================================================================== */

/* Initialize OBJECT_ATTRIBUTES */
static inline void _nt_init_object_attributes(
    NT_OBJECT_ATTRIBUTES *oa, NT_UNICODE_STRING *name,
    NT_ULONG attributes, NT_HANDLE root)
{
    oa->Length = sizeof(NT_OBJECT_ATTRIBUTES);
    oa->RootDirectory = root;
    oa->ObjectName = name;
    oa->Attributes = attributes;
    oa->SecurityDescriptor = (NT_PVOID)0;
    oa->SecurityQualityOfService = (NT_PVOID)0;
}

/* Wide string length (wcslen equivalent) */
static inline size_t _nt_wcslen(const NT_WCHAR *s)
{
    const NT_WCHAR *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

/* Wide string copy */
static inline NT_WCHAR *_nt_wcscpy(NT_WCHAR *dst, const NT_WCHAR *src)
{
    NT_WCHAR *d = dst;
    while ((*d++ = *src++) != 0) ;
    return dst;
}

/* Narrow to wide conversion (ASCII only) */
static inline void _nt_ascii_to_wide(NT_WCHAR *dst, const char *src, size_t max)
{
    size_t i;
    for (i = 0; i < max - 1 && src[i]; i++) {
        dst[i] = (NT_WCHAR)(unsigned char)src[i];
    }
    dst[i] = 0;
}

/* Wide to narrow conversion (ASCII only) */
static inline void _nt_wide_to_ascii(char *dst, const NT_WCHAR *src, size_t max)
{
    size_t i;
    for (i = 0; i < max - 1 && src[i]; i++) {
        dst[i] = (char)src[i];
    }
    dst[i] = 0;
}

/* Build NT path from DOS path: "C:\foo" → "\??\C:\foo" */
static inline void _nt_dos_to_nt_path(NT_WCHAR *nt_path, const NT_WCHAR *dos_path,
                                       size_t max_chars)
{
    /* Prefix with \??\ */
    if (max_chars < 5) return;
    nt_path[0] = L'\\';
    nt_path[1] = L'?';
    nt_path[2] = L'?';
    nt_path[3] = L'\\';

    size_t len = _nt_wcslen(dos_path);
    if (len > max_chars - 5) len = max_chars - 5;
    for (size_t i = 0; i <= len; i++) {
        nt_path[4 + i] = dos_path[i];
    }
}

/* Host-to-network short (big-endian) */
static inline uint16_t _nt_htons(uint16_t val)
{
    return (uint16_t)((val >> 8) | (val << 8));
}

/* Parse dotted-quad IPv4 address into network byte order uint32 */
static inline int _nt_inet_pton4(const char *src, uint32_t *dst)
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

    /* Network byte order */
    *dst = ((result >> 24) & 0xFF)       |
           (((result >> 16) & 0xFF) << 8)  |
           (((result >> 8)  & 0xFF) << 16) |
           ((result & 0xFF) << 24);
    return 0;
}

#endif /* _WIN32 */
#endif /* SYSCALL_WIN32_H */
