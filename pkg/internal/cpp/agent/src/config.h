/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Configuration reader
 *
 * Reads configuration from /tmp/.obi-cpp-config-<pid> written by the Go-side
 * CppInjector before injection.
 */

#ifndef OBI_CONFIG_H
#define OBI_CONFIG_H

#include <stdint.h>

/* Maximum path length for socket path */
#define OBI_MAX_PATH 256

/* Configuration flags (bitmask) */
#define OBI_CFG_DEBUG        (1 << 0)
#define OBI_CFG_CURL_HOOK    (1 << 1)
#define OBI_CFG_GRPC_HOOK    (1 << 2)
#define OBI_CFG_HTTP_SERVER_HOOK      (1 << 3)  /* Plain HTTP server hook */
#define OBI_CFG_HTTP_SERVER_TLS_HOOK  (1 << 4)  /* HTTPS/TLS server hook */

/* Agent configuration, populated from config file */
struct obi_config {
    uint32_t flags;                        /* OBI_CFG_* bitmask */
    char     socket_path[OBI_MAX_PATH];    /* Unix socket path for span export */
    char     bpf_map_path[OBI_MAX_PATH];   /* Pinned BPF map path (traces_ctx_v1) */
    char     incoming_trace_map_path[OBI_MAX_PATH]; /* Pinned BPF map path (incoming_trace_map) */
    uint32_t pid;                          /* Target process PID (namespace PID) */
    uint32_t host_pid;                     /* Host-namespace PID (for BPF map key) */
};

/*
 * obi_config_read - Read configuration from file.
 *
 * Reads /tmp/.obi-cpp-config-<pid> and populates the config struct.
 * Returns 0 on success, -1 on failure.
 */
__attribute__((visibility("hidden")))
int obi_config_read(struct obi_config *cfg);

/*
 * obi_config_has_flag - Check if a configuration flag is set.
 */
static inline int obi_config_has_flag(const struct obi_config *cfg, uint32_t flag) {
    return (cfg->flags & flag) != 0;
}

#endif /* OBI_CONFIG_H */
