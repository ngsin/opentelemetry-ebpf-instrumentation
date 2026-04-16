/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Span creation and memory management
 *
 * Uses __thread TLS for per-thread span context (no locks needed).
 * Generates trace/span IDs from /dev/urandom.
 * Memory is stack-allocated per span (no heap allocation needed).
 */

#define _GNU_SOURCE
#include "span.h"

#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* Forward declaration of export function */
extern int obi_export_send(const struct obi_span_event *event,
                           const char *method, uint32_t method_len,
                           const char *url, uint32_t url_len);

/* Thread-local span storage */
static __thread struct obi_span tls_span;

/*
 * generate_random_bytes - Fill buffer with random bytes from /dev/urandom.
 * Returns 0 on success, -1 on failure.
 */
static int generate_random_bytes(void *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? 0 : -1;
}

/*
 * get_monotonic_ns - Get current CLOCK_MONOTONIC time in nanoseconds.
 */
static uint64_t get_monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

__attribute__((visibility("hidden")))
struct obi_span *obi_span_begin(uint8_t event_type) {
    struct obi_span *span = &tls_span;

    memset(span, 0, sizeof(*span));
    span->event.event_type = event_type;
    span->event.start_time_ns = get_monotonic_ns();

    /* Generate trace ID (16 bytes) and span ID (8 bytes) */
    generate_random_bytes(span->event.trace_id, sizeof(span->event.trace_id));
    generate_random_bytes(span->event.span_id, sizeof(span->event.span_id));
    /* parent_span_id remains zero (no parent in Phase 1) */

    return span;
}

__attribute__((visibility("hidden")))
void obi_span_end(struct obi_span *span) {
    if (!span) return;

    span->event.end_time_ns = get_monotonic_ns();
    span->event.method_len = (uint32_t)strlen(span->method);
    span->event.url_len = (uint32_t)strlen(span->url);

    /* Send to export channel (best-effort, don't block) */
    obi_export_send(&span->event,
                    span->method, span->event.method_len,
                    span->url, span->event.url_len);
}

__attribute__((visibility("hidden")))
void obi_span_set_method(struct obi_span *span, const char *method) {
    if (!span || !method) return;
    strncpy(span->method, method, OBI_MAX_METHOD_LEN - 1);
    span->method[OBI_MAX_METHOD_LEN - 1] = '\0';
}

__attribute__((visibility("hidden")))
void obi_span_set_url(struct obi_span *span, const char *url) {
    if (!span || !url) return;
    strncpy(span->url, url, OBI_MAX_URL_LEN - 1);
    span->url[OBI_MAX_URL_LEN - 1] = '\0';
}

__attribute__((visibility("hidden")))
void obi_span_set_status(struct obi_span *span, uint16_t status) {
    if (!span) return;
    span->event.status = status;
}
