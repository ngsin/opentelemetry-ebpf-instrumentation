/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - PLT/GOT Hooking Framework
 *
 * Uses dl_iterate_phdr() to enumerate loaded shared objects, parses their
 * ELF dynamic sections to find GOT entries, and patches them atomically.
 * Handles Full RELRO (read-only GOT) via mprotect().
 */

#define _GNU_SOURCE
#include "got_hook.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/* Hook registry entry */
struct hook_entry {
    const char *symbol_name;
    void       *replacement;
    void       *original;
    void      **got_entries[64];  /* Pointers to patched GOT slots */
    int         got_count;
    int         active;
};

/* Global hook registry */
static struct hook_entry g_hooks[OBI_MAX_HOOKS];
static int g_hook_count = 0;

/* Callback context for dl_iterate_phdr */
struct patch_ctx {
    const char *symbol_name;
    void       *replacement;
    void       *original;
    void     ***got_entries;
    int         got_capacity;
    int         got_count;
    int         patched;
};

/*
 * try_mprotect_rw - Make a memory page writable.
 * Returns the previous protection flags, or -1 on failure.
 */
static int try_mprotect_rw(void *addr) {
    long page_size = sysconf(_SC_PAGESIZE);
    void *page = (void *)((uintptr_t)addr & ~(page_size - 1));
    /* Try to make writable; if it fails, the page is already writable */
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE) == 0) {
        return PROT_READ; /* Was read-only, now writable */
    }
    return 0; /* Already writable or failed */
}

/*
 * restore_mprotect - Restore memory protection after patching.
 */
static void restore_mprotect(void *addr, int old_prot) {
    if (old_prot == PROT_READ) {
        long page_size = sysconf(_SC_PAGESIZE);
        void *page = (void *)((uintptr_t)addr & ~(page_size - 1));
        mprotect(page, page_size, PROT_READ);
    }
}

/*
 * patch_callback - dl_iterate_phdr callback that patches GOT entries in one shared object.
 */
static int patch_callback(struct dl_phdr_info *info, size_t size, void *data) {
    struct patch_ctx *ctx = (struct patch_ctx *)data;
    (void)size;

    /* Skip objects without a name (vDSO, linux-gate, etc.) - they don't
     * have GOT entries for user-space symbols and their dynamic sections
     * may have unusual layouts that cause crashes when parsed. */
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
        /* Main executable - process it, but note that for PIE binaries
         * dlpi_addr is nonzero and DT_* entries may need base adjustment. */
    } else {
        /* Skip kernel objects like [vdso] and the agent itself */
        const char *name = info->dlpi_name;
        if (name[0] == '[' || strstr(name, "obi-cpp-agent") != NULL) {
            return 0;
        }
    }

    /* Find PT_DYNAMIC segment */
    const ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    /* Extract dynamic section entries */
    const ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    const ElfW(Rela) *jmprel = NULL;
    size_t pltrelsz = 0;

    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:
            symtab = (const ElfW(Sym) *)d->d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = (const char *)d->d_un.d_ptr;
            break;
        case DT_JMPREL:
            jmprel = (const ElfW(Rela) *)d->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            pltrelsz = d->d_un.d_val;
            break;
        }
    }

    if (!symtab || !strtab || !jmprel || pltrelsz == 0) {
        return 0; /* Not enough info to patch */
    }

    /*
     * For PIE executables (and sometimes shared libraries loaded at a
     * non-zero base), the dynamic section entries (DT_SYMTAB, DT_STRTAB,
     * DT_JMPREL) may contain file offsets rather than relocated virtual
     * addresses.  Detect this by checking whether the pointers fall below
     * the load base, and if so, add the base to make them absolute.
     */
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    if (base != 0) {
        if ((uintptr_t)symtab < base)
            symtab = (const ElfW(Sym) *)((uintptr_t)symtab + base);
        if ((uintptr_t)strtab < base)
            strtab = (const char *)((uintptr_t)strtab + base);
        if ((uintptr_t)jmprel < base)
            jmprel = (const ElfW(Rela) *)((uintptr_t)jmprel + base);
    }

    /* Iterate PLT relocation entries */
    size_t nrel = pltrelsz / sizeof(ElfW(Rela));
    for (size_t i = 0; i < nrel; i++) {
        unsigned int sym_idx = ELF64_R_SYM(jmprel[i].r_info);
        const char *name = strtab + symtab[sym_idx].st_name;

        if (strcmp(name, ctx->symbol_name) != 0) {
            continue;
        }

        /* Found the GOT entry */
        void **got_slot = (void **)(info->dlpi_addr + jmprel[i].r_offset);

        /* Save original if this is the first match */
        if (!ctx->original && *got_slot) {
            ctx->original = *got_slot;
        }

        /* Temporarily make GOT writable (handles Full RELRO) */
        int old_prot = try_mprotect_rw(got_slot);

        /* Atomic pointer replacement (aligned pointer write is atomic on x86_64) */
        *got_slot = ctx->replacement;

        /* Restore protection */
        restore_mprotect(got_slot, old_prot);

        /* Record the GOT slot for later removal */
        if (ctx->got_count < ctx->got_capacity) {
            ctx->got_entries[ctx->got_count++] = got_slot;
        }

        ctx->patched++;
    }

    return 0; /* Continue iterating */
}

__attribute__((visibility("hidden")))
int obi_hook_install(const char *symbol_name, void *replacement, void **original) {
    if (g_hook_count >= OBI_MAX_HOOKS) {
        return -1;
    }

    struct hook_entry *entry = &g_hooks[g_hook_count];
    struct patch_ctx ctx = {
        .symbol_name = symbol_name,
        .replacement = replacement,
        .original    = NULL,
        .got_entries = entry->got_entries,
        .got_capacity = 64,
        .got_count   = 0,
        .patched     = 0,
    };

    dl_iterate_phdr(patch_callback, &ctx);

    if (ctx.patched == 0) {
        return -1; /* Symbol not found in any GOT */
    }

    entry->symbol_name = symbol_name;
    entry->replacement = replacement;
    entry->original = ctx.original;
    entry->got_count = ctx.got_count;
    entry->active = 1;
    g_hook_count++;

    if (original) {
        *original = ctx.original;
    }

    return 0;
}

__attribute__((visibility("hidden")))
int obi_hook_remove(const char *symbol_name) {
    for (int i = 0; i < g_hook_count; i++) {
        if (!g_hooks[i].active) continue;
        if (strcmp(g_hooks[i].symbol_name, symbol_name) != 0) continue;

        /* Restore all patched GOT entries */
        for (int j = 0; j < g_hooks[i].got_count; j++) {
            void **slot = g_hooks[i].got_entries[j];
            int old_prot = try_mprotect_rw(slot);
            *slot = g_hooks[i].original;
            restore_mprotect(slot, old_prot);
        }

        g_hooks[i].active = 0;
        return 0;
    }
    return -1;
}

__attribute__((visibility("hidden")))
void obi_hook_remove_all(void) {
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].active) {
            obi_hook_remove(g_hooks[i].symbol_name);
        }
    }
    g_hook_count = 0;
}
