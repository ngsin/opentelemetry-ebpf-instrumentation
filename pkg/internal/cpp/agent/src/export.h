/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Export channel header
 */

#ifndef OBI_EXPORT_H
#define OBI_EXPORT_H

#include <stdint.h>
#include "span.h"

/*
 * obi_export_init - Connect to the OBI Unix domain socket.
 *
 * @socket_path: Path to the Unix domain socket (e.g., /tmp/.obi-<pid>.sock)
 *
 * Returns 0 on success, -1 on failure.
 */
__attribute__((visibility("hidden")))
int obi_export_init(const char *socket_path);

/*
 * obi_export_send - Send a span event over the Unix socket.
 *
 * Serializes the fixed header and variable-length fields into a single
 * message. Non-blocking; drops the span if the socket is not writable.
 *
 * Returns 0 on success, -1 on failure (span dropped).
 */
__attribute__((visibility("hidden")))
int obi_export_send(const struct obi_span_event *event,
                    const char *method, uint32_t method_len,
                    const char *url, uint32_t url_len);

/*
 * obi_export_shutdown - Close the export socket.
 */
__attribute__((visibility("hidden")))
void obi_export_shutdown(void);

#endif /* OBI_EXPORT_H */
