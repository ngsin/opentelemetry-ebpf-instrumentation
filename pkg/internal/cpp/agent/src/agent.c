/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Main entry point
 *
 * This shared library is injected into C++ processes via ptrace+dlopen.
 * The constructor runs automatically on load, setting up hooks and
 * the span export channel. The destructor cleans up on unload.
 *
 * Design principles:
 *   - Pure C, no libstdc++ dependency
 *   - Only links against libc (target process always has it)
 *   - All internal symbols have hidden visibility
 *   - Memory allocated via mmap, not target process's malloc
 *   - Thread-local storage for span context (no global locks)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <errno.h>

#include "config.h"

/* Forward declarations for sub-modules (stubs for now) */
extern int obi_export_init(const char *socket_path);
extern void obi_export_shutdown(void);
extern int obi_hooks_install(uint32_t flags);
extern void obi_hooks_remove(void);

/* Global config (hidden visibility) */
__attribute__((visibility("hidden")))
struct obi_config g_obi_config;

/* File descriptor for the traces_ctx_v1 pinned BPF map (-1 = unavailable) */
__attribute__((visibility("hidden")))
int g_traces_ctx_fd = -1;

/* File descriptor for the incoming_trace_map pinned BPF map (-1 = unavailable) */
__attribute__((visibility("hidden")))
int g_incoming_trace_map_fd = -1;

/* Memory pool base and size */
__attribute__((visibility("hidden")))
void *g_obi_mempool = NULL;

__attribute__((visibility("hidden")))
size_t g_obi_mempool_size = 0;

#define OBI_MEMPOOL_SIZE (1024 * 1024) /* 1 MB private memory pool */

/* Debug logging macro */
#define OBI_DBG(fmt, ...) \
    do { \
        if (obi_config_has_flag(&g_obi_config, OBI_CFG_DEBUG)) { \
            fprintf(stderr, "[obi-cpp-agent] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/*
 * Agent constructor - runs when the .so is loaded via dlopen.
 */
__attribute__((constructor))
static void obi_agent_init(void) {
    OBI_DBG("agent loading, pid=%d", getpid());

    /* Step 1: Read configuration */
    if (obi_config_read(&g_obi_config) != 0) {
        fprintf(stderr, "[obi-cpp-agent] failed to read config for pid %d\n", getpid());
        return;
    }

    OBI_DBG("config loaded: socket=%s flags=%u bpf_map=%s host_pid=%u",
            g_obi_config.socket_path, g_obi_config.flags,
            g_obi_config.bpf_map_path, g_obi_config.host_pid);

    /* Step 2: Open pinned BPF map (traces_ctx_v1) for HTTPS traceparent injection */
    if (g_obi_config.bpf_map_path[0] != '\0') {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.pathname = (uint64_t)(unsigned long)g_obi_config.bpf_map_path;

        g_traces_ctx_fd = (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
        if (g_traces_ctx_fd < 0) {
            OBI_DBG("failed to open BPF map %s: errno=%d (%s). "
                    "HTTPS traceparent injection disabled; TCP option propagation unaffected.",
                    g_obi_config.bpf_map_path, errno, strerror(errno));
        } else {
            OBI_DBG("opened BPF map fd=%d for traces_ctx_v1", g_traces_ctx_fd);
        }
    } else {
        OBI_DBG("no bpf_map_path configured, HTTPS traceparent injection disabled");
    }

    /* Step 2b: Open pinned BPF map (incoming_trace_map) for HTTPS server trace propagation */
    if (g_obi_config.incoming_trace_map_path[0] != '\0') {
        union bpf_attr attr2;
        memset(&attr2, 0, sizeof(attr2));
        attr2.pathname = (uint64_t)(unsigned long)g_obi_config.incoming_trace_map_path;

        g_incoming_trace_map_fd = (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr2, sizeof(attr2));
        if (g_incoming_trace_map_fd < 0) {
            OBI_DBG("failed to open incoming_trace_map %s: errno=%d (%s)",
                    g_obi_config.incoming_trace_map_path, errno, strerror(errno));
        } else {
            OBI_DBG("opened BPF map fd=%d for incoming_trace_map", g_incoming_trace_map_fd);
        }
    } else {
        OBI_DBG("no incoming_trace_map_path configured");
    }

    /*
     * Safety check: if both BPF maps failed to open, skip hook installation
     * entirely.  Without the maps the hooks serve no useful purpose and risk
     * crashing the target application (SEGV from GOT patching).
     * Principle: never affect the normal operation of the host process.
     */
    if (g_traces_ctx_fd < 0 || g_incoming_trace_map_fd < 0) {
        fprintf(stderr, "[obi-cpp-agent] BPF map unavailable (traces_ctx=%d, incoming_trace=%d), "
                "skipping hook installation to protect application (pid=%d)\n",
                g_traces_ctx_fd, g_incoming_trace_map_fd, getpid());
        /* Close whichever map did open, if any */
        if (g_traces_ctx_fd >= 0) {
            close(g_traces_ctx_fd);
            g_traces_ctx_fd = -1;
        }
        if (g_incoming_trace_map_fd >= 0) {
            close(g_incoming_trace_map_fd);
            g_incoming_trace_map_fd = -1;
        }
        return;
    }

    /* Step 3: Allocate private memory pool via mmap (not malloc) */
    g_obi_mempool = mmap(NULL, OBI_MEMPOOL_SIZE,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
    if (g_obi_mempool == MAP_FAILED) {
        g_obi_mempool = NULL;
        fprintf(stderr, "[obi-cpp-agent] mmap failed for memory pool\n");
        return;
    }
    g_obi_mempool_size = OBI_MEMPOOL_SIZE;
    OBI_DBG("memory pool allocated: %zu bytes at %p", g_obi_mempool_size, g_obi_mempool);

    /* Step 4: Connect to span export socket */
    if (obi_export_init(g_obi_config.socket_path) != 0) {
        OBI_DBG("failed to connect export socket, spans will be dropped");
        /* Non-fatal: we still install hooks, spans are just dropped */
    }

    /* Step 5: Install function hooks based on detected libraries */
    if (obi_hooks_install(g_obi_config.flags) != 0) {
        OBI_DBG("failed to install some hooks");
    }

    OBI_DBG("agent initialized successfully");
}

/*
 * Agent destructor - runs when the .so is unloaded.
 */
__attribute__((destructor))
static void obi_agent_fini(void) {
    OBI_DBG("agent unloading");

    /* Remove hooks first */
    obi_hooks_remove();

    /* Shutdown export channel */
    obi_export_shutdown();

    /* Close BPF map fds */
    if (g_traces_ctx_fd >= 0) {
        close(g_traces_ctx_fd);
        g_traces_ctx_fd = -1;
    }
    if (g_incoming_trace_map_fd >= 0) {
        close(g_incoming_trace_map_fd);
        g_incoming_trace_map_fd = -1;
    }

    /* Free memory pool */
    if (g_obi_mempool && g_obi_mempool != MAP_FAILED) {
        munmap(g_obi_mempool, g_obi_mempool_size);
        g_obi_mempool = NULL;
        g_obi_mempool_size = 0;
    }

    OBI_DBG("agent unloaded");
}
