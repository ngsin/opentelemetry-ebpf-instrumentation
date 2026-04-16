/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - HTTP server hooks
 *
 * GOT hooks for accept4/recv/send/close (plain HTTP) and
 * SSL_read/SSL_write (HTTPS/TLS) to generate HTTP server spans.
 */

#ifndef OBI_HTTP_SERVER_HOOKS_H
#define OBI_HTTP_SERVER_HOOKS_H

/*
 * obi_http_server_hooks_install - Install plain HTTP server hooks.
 *
 * Hooks accept4, recv, send, and close to track HTTP connections
 * and generate server spans.
 *
 * Returns 0 on success, -1 on failure.
 */
__attribute__((visibility("hidden")))
int obi_http_server_hooks_install(void);

/*
 * obi_http_server_hooks_remove - Remove plain HTTP server hooks.
 */
__attribute__((visibility("hidden")))
void obi_http_server_hooks_remove(void);

/*
 * obi_http_server_tls_hooks_install - Install HTTPS/TLS server hooks.
 *
 * Hooks SSL_read and SSL_write to intercept decrypted HTTP data.
 * Requires OpenSSL to be loaded in the target process.
 * Falls back gracefully if SSL_get_fd cannot be resolved.
 *
 * Returns 0 on success, -1 on failure.
 */
__attribute__((visibility("hidden")))
int obi_http_server_tls_hooks_install(void);

/*
 * obi_http_server_tls_hooks_remove - Remove HTTPS/TLS server hooks.
 */
__attribute__((visibility("hidden")))
void obi_http_server_tls_hooks_remove(void);

#endif /* OBI_HTTP_SERVER_HOOKS_H */
