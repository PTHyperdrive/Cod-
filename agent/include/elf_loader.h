/* ==========================================================================
 * elf_loader.h — Userspace ELF Loader Interface
 * ==========================================================================
 * Provides the ability to load and execute ELF binaries received from the
 * server directly in memory, without touching disk.  The loader:
 *
 *   1. Validates the ELF header (magic, class, endianness, type)
 *   2. Maps PT_LOAD segments via mmap with correct permissions
 *   3. Applies ELF relocations (R_X86_64_RELATIVE for PIE)
 *   4. Jumps to the entry point
 *
 * Supports:
 *   - ET_DYN  (PIE / shared object) — mapped at arbitrary base
 *   - ET_EXEC (static executable)   — mapped at fixed addresses
 *
 * All operations use raw syscalls via syscall_linux.h.
 * x86_64 only.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */
#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#ifdef __linux__

#include <stdint.h>
#include <stddef.h>

/* ---- ELF format constants --------------------------------------------- */
/* We define these ourselves to avoid depending on <elf.h>.                */

/* ELF magic */
#define ELF_MAGIC       "\x7fELF"
#define ELF_MAGIC_SIZE  4

/* ELF class */
#define ELFCLASS64      2

/* ELF data encoding */
#define ELFDATA2LSB     1   /* Little-endian */

/* ELF object type */
#define ET_EXEC         2   /* Executable */
#define ET_DYN          3   /* Shared object / PIE */

/* ELF machine */
#define EM_X86_64       62

/* Program header types */
#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_PHDR         6
#define PT_GNU_RELRO    0x6474e552

/* Program header flags */
#define PF_X            0x1
#define PF_W            0x2
#define PF_R            0x4

/* Dynamic section tags */
#define DT_NULL         0
#define DT_RELA         7
#define DT_RELASZ       8
#define DT_RELAENT      9
#define DT_JMPREL       23
#define DT_PLTRELSZ     2
#define DT_PLTREL       20

/* Relocation types (x86_64) */
#define R_X86_64_NONE       0
#define R_X86_64_64         1
#define R_X86_64_RELATIVE   8
#define R_X86_64_JUMP_SLOT  7
#define R_X86_64_GLOB_DAT   6

/* Section header types */
#define SHT_RELA        4

/* ---- ELF64 structures ------------------------------------------------- */

typedef struct {
    uint8_t  e_ident[16];   /* ELF identification */
    uint16_t e_type;        /* Object type */
    uint16_t e_machine;     /* Machine architecture */
    uint32_t e_version;     /* Object file version */
    uint64_t e_entry;       /* Entry point virtual address */
    uint64_t e_phoff;       /* Program header table offset */
    uint64_t e_shoff;       /* Section header table offset */
    uint32_t e_flags;       /* Processor-specific flags */
    uint16_t e_ehsize;      /* ELF header size */
    uint16_t e_phentsize;   /* Program header entry size */
    uint16_t e_phnum;       /* Number of program headers */
    uint16_t e_shentsize;   /* Section header entry size */
    uint16_t e_shnum;       /* Number of section headers */
    uint16_t e_shstrndx;    /* Section name string table index */
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;        /* Segment type */
    uint32_t p_flags;       /* Segment flags */
    uint64_t p_offset;      /* File offset */
    uint64_t p_vaddr;       /* Virtual address */
    uint64_t p_paddr;       /* Physical address */
    uint64_t p_filesz;      /* File size */
    uint64_t p_memsz;       /* Memory size */
    uint64_t p_align;       /* Alignment */
} Elf64_Phdr;

typedef struct {
    uint64_t r_offset;      /* Relocation offset */
    uint64_t r_info;        /* Relocation type + symbol index */
    int64_t  r_addend;      /* Addend */
} Elf64_Rela;

typedef struct {
    int64_t  d_tag;         /* Dynamic entry tag */
    union {
        uint64_t d_val;     /* Integer value */
        uint64_t d_ptr;     /* Virtual address */
    } d_un;
} Elf64_Dyn;

/* Macros for r_info */
#define ELF64_R_SYM(i)     ((i) >> 32)
#define ELF64_R_TYPE(i)    ((i) & 0xffffffffL)

/* ---- Loaded ELF context ----------------------------------------------- */

/**
 * Represents a loaded ELF binary in memory.
 * Holds the mapping information needed to execute or unload it.
 */
typedef struct {
    void     *base;         /* Base address of first mapping         */
    size_t    total_size;   /* Total mapped size (base to end)       */
    uint64_t  entry;        /* Absolute entry point address          */
    uint16_t  type;         /* ET_EXEC or ET_DYN                    */
    int       loaded;       /* Non-zero if successfully loaded       */
} elf_ctx_t;

/* ---- API -------------------------------------------------------------- */

/**
 * Validate an ELF binary in a memory buffer.
 * Checks magic, class (64-bit), endianness (little), and machine (x86_64).
 *
 * Returns 0 if the buffer contains a valid ELF64 x86_64 binary,
 * -1 otherwise.
 */
int elf_validate(const uint8_t *data, size_t size);

/**
 * Load an ELF binary from a memory buffer into the process address space.
 *
 * Maps all PT_LOAD segments, applies relocations for ET_DYN binaries,
 * and computes the absolute entry point address.
 *
 * On success, fills `ctx` with mapping information and returns 0.
 * On failure, returns -1 and any partially-mapped memory is cleaned up.
 */
int elf_load(const uint8_t *data, size_t size, elf_ctx_t *ctx);

/**
 * Execute a loaded ELF binary by jumping to its entry point.
 *
 * For ET_DYN (PIE) binaries, the entry point is called as a function
 * pointer.  This function does NOT return if the loaded ELF calls exit().
 *
 * `argc`, `argv`, `envp` are passed to the entry point if it follows
 * the standard C ABI (i.e., main(argc, argv, envp)).
 *
 * Returns the entry point's return value, or -1 on error.
 */
int elf_execute(const elf_ctx_t *ctx, int argc, char **argv, char **envp);

/**
 * Unload a previously loaded ELF binary by unmapping its memory.
 * Returns 0 on success, -1 on failure.
 */
int elf_unload(elf_ctx_t *ctx);

#endif /* __linux__ */
#endif /* ELF_LOADER_H */
