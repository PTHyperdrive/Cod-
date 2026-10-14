/* ==========================================================================
 * elf_loader.c — Userspace ELF Loader Implementation
 * ==========================================================================
 * Loads ELF64 binaries received from the server directly into the process
 * address space using raw syscalls.  No libc, no dynamic linker.
 *
 * Flow:
 *   1. Validate ELF header (magic, class, endianness, machine)
 *   2. Scan PT_LOAD segments to determine total memory span
 *   3. Reserve a contiguous virtual memory region via mmap(MAP_ANONYMOUS)
 *   4. Map each PT_LOAD segment into the reserved region with correct
 *      permissions (PROT_READ, PROT_WRITE, PROT_EXEC)
 *   5. Process relocations (RELA) for position-independent code
 *   6. Compute absolute entry point and jump
 *
 * Supports:
 *   - ET_DYN  (PIE / shared object) — mapped at arbitrary base
 *   - ET_EXEC (statically-linked)   — mapped at fixed virtual addresses
 *
 * x86_64 only.  All operations via raw syscall wrappers.
 *
 * ACADEMIC/EDUCATIONAL USE ONLY.
 * ========================================================================== */

#ifdef __linux__

#include "elf_loader.h"
#include "syscall_linux.h"
#include "nolibc.h"
#include "pal.h"

/* Page size constant (x86_64) */
#define PAGE_SIZE   4096UL
#define PAGE_MASK   (~(PAGE_SIZE - 1))

/* Align down to page boundary */
#define PAGE_ALIGN_DOWN(x) ((x) & PAGE_MASK)

/* Align up to page boundary */
#define PAGE_ALIGN_UP(x)   (((x) + PAGE_SIZE - 1) & PAGE_MASK)

/* ---- Validation ------------------------------------------------------- */

int elf_validate(const uint8_t *data, size_t size)
{
    if (data == NULL || size < sizeof(Elf64_Ehdr)) {
        return -1;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;

    /* Check magic bytes: 0x7f 'E' 'L' 'F' */
    if (_nc_memcmp(ehdr->e_ident, ELF_MAGIC, ELF_MAGIC_SIZE) != 0) {
        pal_log("elf_loader: bad magic");
        return -1;
    }

    /* Must be 64-bit */
    if (ehdr->e_ident[4] != ELFCLASS64) {
        pal_log("elf_loader: not ELFCLASS64");
        return -1;
    }

    /* Must be little-endian */
    if (ehdr->e_ident[5] != ELFDATA2LSB) {
        pal_log("elf_loader: not little-endian");
        return -1;
    }

    /* Must be executable or shared object */
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        pal_log("elf_loader: unsupported ELF type %d", ehdr->e_type);
        return -1;
    }

    /* Must be x86_64 */
    if (ehdr->e_machine != EM_X86_64) {
        pal_log("elf_loader: not x86_64 (machine=%d)", ehdr->e_machine);
        return -1;
    }

    /* Validate program header table fits within the data */
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
        pal_log("elf_loader: no program headers");
        return -1;
    }

    uint64_t ph_end = ehdr->e_phoff +
                      (uint64_t)ehdr->e_phnum * ehdr->e_phentsize;
    if (ph_end > size) {
        pal_log("elf_loader: program headers exceed data bounds");
        return -1;
    }

    return 0;
}

/* ---- Convert ELF segment flags to mmap protection flags --------------- */

static int elf_flags_to_prot(uint32_t p_flags)
{
    int prot = SC_PROT_NONE;
    if (p_flags & PF_R) prot |= SC_PROT_READ;
    if (p_flags & PF_W) prot |= SC_PROT_WRITE;
    if (p_flags & PF_X) prot |= SC_PROT_EXEC;
    return prot;
}

/* ---- Loading ---------------------------------------------------------- */

int elf_load(const uint8_t *data, size_t size, elf_ctx_t *ctx)
{
    if (data == NULL || ctx == NULL) {
        return -1;
    }

    _nc_memset(ctx, 0, sizeof(elf_ctx_t));

    /* Validate first */
    if (elf_validate(data, size) != 0) {
        return -1;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
    ctx->type = ehdr->e_type;

    /* ------------------------------------------------------------------ *
     * Pass 1: Determine the virtual address range covered by all          *
     * PT_LOAD segments.  For ET_DYN, vaddr starts at 0 (relative).       *
     * ------------------------------------------------------------------ */
    uint64_t vaddr_min = UINT64_MAX;
    uint64_t vaddr_max = 0;
    int load_count = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = (const Elf64_Phdr *)
            (data + ehdr->e_phoff + (uint64_t)i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        uint64_t seg_start = PAGE_ALIGN_DOWN(phdr->p_vaddr);
        uint64_t seg_end   = PAGE_ALIGN_UP(phdr->p_vaddr + phdr->p_memsz);

        if (seg_start < vaddr_min) vaddr_min = seg_start;
        if (seg_end   > vaddr_max) vaddr_max = seg_end;
        load_count++;
    }

    if (load_count == 0) {
        pal_log("elf_loader: no PT_LOAD segments");
        return -1;
    }

    size_t total_size = (size_t)(vaddr_max - vaddr_min);

    /* ------------------------------------------------------------------ *
     * Reserve a contiguous virtual memory region.                         *
     * For ET_DYN, let the kernel choose the base address.                 *
     * For ET_EXEC, map at the fixed vaddr_min.                            *
     * ------------------------------------------------------------------ */
    void *base;
    if (ehdr->e_type == ET_DYN) {
        /* Reserve the full range with PROT_NONE first, then map
         * individual segments with MAP_FIXED on top. */
        base = sc_mmap(NULL, total_size,
                       SC_PROT_NONE,
                       SC_MAP_PRIVATE | SC_MAP_ANONYMOUS,
                       -1, 0);
    } else {
        /* ET_EXEC: fixed address */
        base = sc_mmap((void *)vaddr_min, total_size,
                       SC_PROT_NONE,
                       SC_MAP_PRIVATE | SC_MAP_ANONYMOUS | SC_MAP_FIXED,
                       -1, 0);
    }

    if (base == SC_MAP_FAILED) {
        pal_log("elf_loader: mmap reserve failed");
        return -1;
    }

    /* Calculate the load bias (difference between where we mapped and
     * where the ELF expects to be loaded) */
    uintptr_t load_bias = (uintptr_t)base - (uintptr_t)vaddr_min;

    /* ------------------------------------------------------------------ *
     * Pass 2: Map each PT_LOAD segment into the reserved region.          *
     * ------------------------------------------------------------------ */
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = (const Elf64_Phdr *)
            (data + ehdr->e_phoff + (uint64_t)i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        uint64_t seg_start = PAGE_ALIGN_DOWN(phdr->p_vaddr);
        uint64_t seg_end   = PAGE_ALIGN_UP(phdr->p_vaddr + phdr->p_memsz);
        size_t   seg_size  = (size_t)(seg_end - seg_start);

        /* Map writable first so we can copy data in */
        void *seg_addr = sc_mmap(
            (void *)(load_bias + seg_start),
            seg_size,
            SC_PROT_READ | SC_PROT_WRITE,
            SC_MAP_PRIVATE | SC_MAP_ANONYMOUS | SC_MAP_FIXED,
            -1, 0
        );

        if (seg_addr == SC_MAP_FAILED) {
            pal_log("elf_loader: mmap segment %d failed", i);
            sc_munmap(base, total_size);
            return -1;
        }

        /* Copy file-backed portion of the segment */
        if (phdr->p_filesz > 0) {
            if (phdr->p_offset + phdr->p_filesz > size) {
                pal_log("elf_loader: segment %d exceeds file bounds", i);
                sc_munmap(base, total_size);
                return -1;
            }
            _nc_memcpy(
                (void *)(load_bias + phdr->p_vaddr),
                data + phdr->p_offset,
                (size_t)phdr->p_filesz
            );
        }

        /* BSS portion (memsz > filesz) is already zero from MAP_ANONYMOUS */
    }

    /* ------------------------------------------------------------------ *
     * Pass 3: Process relocations for ET_DYN (PIE) binaries.              *
     * We look for PT_DYNAMIC to find the RELA table.                      *
     * ------------------------------------------------------------------ */
    if (ehdr->e_type == ET_DYN) {
        /* Find PT_DYNAMIC segment */
        const Elf64_Phdr *dyn_phdr = NULL;
        for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
            const Elf64_Phdr *phdr = (const Elf64_Phdr *)
                (data + ehdr->e_phoff + (uint64_t)i * ehdr->e_phentsize);
            if (phdr->p_type == PT_DYNAMIC) {
                dyn_phdr = phdr;
                break;
            }
        }

        if (dyn_phdr != NULL) {
            /* Walk the dynamic section (already mapped in memory) */
            const Elf64_Dyn *dyn = (const Elf64_Dyn *)
                (load_bias + dyn_phdr->p_vaddr);

            uint64_t rela_addr = 0;
            uint64_t rela_size = 0;
            uint64_t rela_ent  = 0;
            uint64_t jmprel_addr = 0;
            uint64_t jmprel_size = 0;

            for (int j = 0; dyn[j].d_tag != DT_NULL; j++) {
                switch (dyn[j].d_tag) {
                case DT_RELA:
                    rela_addr = dyn[j].d_un.d_ptr;
                    break;
                case DT_RELASZ:
                    rela_size = dyn[j].d_un.d_val;
                    break;
                case DT_RELAENT:
                    rela_ent = dyn[j].d_un.d_val;
                    break;
                case DT_JMPREL:
                    jmprel_addr = dyn[j].d_un.d_ptr;
                    break;
                case DT_PLTRELSZ:
                    jmprel_size = dyn[j].d_un.d_val;
                    break;
                default:
                    break;
                }
            }

            /* Apply RELA relocations */
            if (rela_addr != 0 && rela_size != 0 && rela_ent != 0) {
                size_t num_rela = (size_t)(rela_size / rela_ent);
                const Elf64_Rela *rela = (const Elf64_Rela *)
                    (load_bias + rela_addr);

                for (size_t r = 0; r < num_rela; r++) {
                    uint32_t rtype = (uint32_t)ELF64_R_TYPE(rela[r].r_info);

                    if (rtype == R_X86_64_RELATIVE) {
                        /* R_X86_64_RELATIVE: *target = base + addend */
                        uint64_t *target = (uint64_t *)
                            (load_bias + rela[r].r_offset);
                        *target = (uint64_t)load_bias + (uint64_t)rela[r].r_addend;
                    }
                    /* Other relocation types (GLOB_DAT, JUMP_SLOT) would
                     * require a symbol table lookup — not supported for
                     * standalone executables without dynamic linking. */
                }
            }

            /* Apply PLT relocations (JMPREL) if present */
            if (jmprel_addr != 0 && jmprel_size != 0) {
                size_t ent_size = rela_ent > 0 ? (size_t)rela_ent
                                                : sizeof(Elf64_Rela);
                size_t num_jmprel = (size_t)(jmprel_size / ent_size);
                const Elf64_Rela *jmprel = (const Elf64_Rela *)
                    (load_bias + jmprel_addr);

                for (size_t r = 0; r < num_jmprel; r++) {
                    uint32_t rtype = (uint32_t)ELF64_R_TYPE(jmprel[r].r_info);
                    if (rtype == R_X86_64_RELATIVE) {
                        uint64_t *target = (uint64_t *)
                            (load_bias + jmprel[r].r_offset);
                        *target = (uint64_t)load_bias +
                                  (uint64_t)jmprel[r].r_addend;
                    }
                }
            }
        }
    }

    /* ------------------------------------------------------------------ *
     * Pass 4: Set final memory protections on each segment.               *
     * We mapped everything RW for the copy/reloc phase; now restrict.     *
     * ------------------------------------------------------------------ */
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = (const Elf64_Phdr *)
            (data + ehdr->e_phoff + (uint64_t)i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        uint64_t seg_start = PAGE_ALIGN_DOWN(phdr->p_vaddr);
        uint64_t seg_end   = PAGE_ALIGN_UP(phdr->p_vaddr + phdr->p_memsz);

        int prot = elf_flags_to_prot(phdr->p_flags);
        sc_mprotect((void *)(load_bias + seg_start),
                    (size_t)(seg_end - seg_start), prot);
    }

    /* ------------------------------------------------------------------ *
     * Fill in the context.                                                *
     * ------------------------------------------------------------------ */
    ctx->base       = base;
    ctx->total_size = total_size;
    ctx->entry      = load_bias + ehdr->e_entry;
    ctx->loaded     = 1;

    pal_log("elf_loader: loaded %s at base=%p, entry=%p, size=%lu",
            ehdr->e_type == ET_DYN ? "ET_DYN" : "ET_EXEC",
            base, (void *)ctx->entry, (unsigned long)total_size);

    return 0;
}

/* ---- Execution -------------------------------------------------------- */

int elf_execute(const elf_ctx_t *ctx, int argc, char **argv, char **envp)
{
    if (ctx == NULL || !ctx->loaded || ctx->entry == 0) {
        pal_log("elf_loader: invalid context for execution");
        return -1;
    }

    pal_log("elf_loader: jumping to entry point %p", (void *)ctx->entry);

    /* Cast the entry point to a function pointer.
     * For a PIE compiled with -nostartfiles, the entry point is typically
     * a function with signature: int entry(int argc, char **argv, char **envp)
     * or void _start(void) with registers set up. */

    /* Try the standard main()-like ABI first */
    typedef int (*elf_entry_fn)(int, char **, char **);
    elf_entry_fn entry = (elf_entry_fn)ctx->entry;

    int result = entry(argc, argv, envp);
    return result;
}

/* ---- Unloading -------------------------------------------------------- */

int elf_unload(elf_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->loaded) {
        return -1;
    }

    if (ctx->base != NULL && ctx->total_size > 0) {
        int rc = sc_munmap(ctx->base, ctx->total_size);
        if (rc < 0) {
            pal_log("elf_loader: munmap failed");
            return -1;
        }
    }

    ctx->base       = NULL;
    ctx->total_size = 0;
    ctx->entry      = 0;
    ctx->loaded     = 0;

    pal_log("elf_loader: unloaded");
    return 0;
}

#endif /* __linux__ */
