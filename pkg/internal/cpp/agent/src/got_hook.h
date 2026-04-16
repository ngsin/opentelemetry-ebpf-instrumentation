/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - PLT/GOT Hooking Framework
 */

#ifndef OBI_GOT_HOOK_H
#define OBI_GOT_HOOK_H

#include <stddef.h>

/*
 * Maximum number of hooks that can be installed simultaneously.
 */
#define OBI_MAX_HOOKS 32

/*
 * obi_hook_install - Install a GOT hook for the named symbol.
 *
 * Scans all loaded shared objects via dl_iterate_phdr(), finds GOT entries
 * for the target symbol, and replaces them atomically with the replacement
 * function pointer.
 *
 * @symbol_name: Name of the function to hook (e.g., "curl_easy_perform")
 * @replacement: Pointer to the replacement function
 * @original:    Output pointer to the original function (can be NULL)
 *
 * Returns 0 on success (at least one GOT entry patched), -1 on failure.
 */
__attribute__((visibility("hidden")))
int obi_hook_install(const char *symbol_name, void *replacement, void **original);

/*
 * obi_hook_remove - Remove a previously installed GOT hook.
 *
 * Restores the original function pointer in all patched GOT entries.
 *
 * @symbol_name: Name of the hooked function
 *
 * Returns 0 on success, -1 if hook was not found.
 */
__attribute__((visibility("hidden")))
int obi_hook_remove(const char *symbol_name);

/*
 * obi_hook_remove_all - Remove all installed hooks.
 */
__attribute__((visibility("hidden")))
void obi_hook_remove_all(void);

#endif /* OBI_GOT_HOOK_H */
