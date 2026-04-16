/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Hook dispatcher
 *
 * Routes hook installation to the appropriate per-library hook modules
 * based on the detection flags passed from the Go side.
 */

#include <stdint.h>
#include "config.h"
#include "got_hook.h"

/* Forward declarations for per-library hook modules */
extern int obi_curl_hooks_install(void);
extern void obi_curl_hooks_remove(void);

/* HTTP server hook modules */
extern int obi_http_server_hooks_install(void);
extern void obi_http_server_hooks_remove(void);
extern int obi_http_server_tls_hooks_install(void);
extern void obi_http_server_tls_hooks_remove(void);

__attribute__((visibility("hidden")))
int obi_hooks_install(uint32_t flags) {
    int rc = 0;

    if (flags & OBI_CFG_CURL_HOOK) {
        if (obi_curl_hooks_install() != 0) {
            rc = -1; /* Non-fatal: log and continue */
        }
    }

    if (flags & OBI_CFG_HTTP_SERVER_HOOK) {
        if (obi_http_server_hooks_install() != 0) {
            rc = -1;
        }
    }

    if (flags & OBI_CFG_HTTP_SERVER_TLS_HOOK) {
        if (obi_http_server_tls_hooks_install() != 0) {
            rc = -1;
        }
    }

    /* Future: gRPC hooks would go here */
    /* if (flags & OBI_CFG_GRPC_HOOK) { ... } */

    return rc;
}

__attribute__((visibility("hidden")))
void obi_hooks_remove(void) {
    obi_curl_hooks_remove();
    obi_http_server_hooks_remove();
    obi_http_server_tls_hooks_remove();
    obi_hook_remove_all();
}
