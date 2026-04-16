/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Span creation and memory management
 */

#ifndef OBI_SPAN_H
#define OBI_SPAN_H

#include <stdint.h>
#include <stddef.h>

/* Event types matching Go-side request.EventType */
#define OBI_EVENT_HTTP_SERVER  1   /* EventTypeHTTP (server) */
#define OBI_EVENT_HTTP_CLIENT  3   /* EventTypeHTTPClient */
#define OBI_EVENT_GRPC_CLIENT  4   /* EventTypeGRPCClient */

/* Maximum lengths for variable-length fields */
#define OBI_MAX_METHOD_LEN   32
#define OBI_MAX_URL_LEN      2048

/*
 * Wire protocol struct sent over Unix socket.
 * Must match the Go-side SpanReader's parsing.
 */
struct __attribute__((packed)) obi_span_event {
    uint8_t  event_type;        /* OBI_EVENT_HTTP_CLIENT, etc. */
    uint8_t  flags;
    uint16_t status;            /* HTTP status code */
    uint32_t method_len;
    uint32_t url_len;
    uint64_t start_time_ns;     /* CLOCK_MONOTONIC nanoseconds */
    uint64_t end_time_ns;
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    /* Variable-length fields follow: method[method_len] + url[url_len] */
};

/* Size of the fixed portion of obi_span_event */
#define OBI_SPAN_EVENT_FIXED_SIZE \
    (1 + 1 + 2 + 4 + 4 + 8 + 8 + 16 + 8 + 8) /* = 60 bytes */

/* Compile-time check: the packed struct must match the wire size exactly.
 * If this fails, the Go-side SpanReader will misparse the binary protocol. */
_Static_assert(sizeof(struct obi_span_event) == OBI_SPAN_EVENT_FIXED_SIZE,
               "obi_span_event struct size does not match wire protocol size");

/*
 * Active span context, stored in TLS for the current thread.
 */
struct obi_span {
    struct obi_span_event event;
    char   method[OBI_MAX_METHOD_LEN];
    char   url[OBI_MAX_URL_LEN];
};

/*
 * obi_span_begin - Start a new span.
 *
 * Records the start time using CLOCK_MONOTONIC and generates IDs.
 * The span is stored in thread-local storage.
 *
 * Returns a pointer to the active span, or NULL on failure.
 */
__attribute__((visibility("hidden")))
struct obi_span *obi_span_begin(uint8_t event_type);

/*
 * obi_span_end - Complete the current span.
 *
 * Records the end time, finalizes the span event, and sends it
 * to the export channel.
 */
__attribute__((visibility("hidden")))
void obi_span_end(struct obi_span *span);

/*
 * obi_span_set_method - Set the HTTP method for a span.
 */
__attribute__((visibility("hidden")))
void obi_span_set_method(struct obi_span *span, const char *method);

/*
 * obi_span_set_url - Set the URL for a span.
 */
__attribute__((visibility("hidden")))
void obi_span_set_url(struct obi_span *span, const char *url);

/*
 * obi_span_set_status - Set the HTTP status code for a span.
 */
__attribute__((visibility("hidden")))
void obi_span_set_status(struct obi_span *span, uint16_t status);

#endif /* OBI_SPAN_H */
