/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - HTTP protocol parser
 *
 * Lightweight HTTP/1.x request line and response line parser for
 * detecting and extracting HTTP protocol information from raw socket data.
 */

#ifndef OBI_HTTP_PARSE_H
#define OBI_HTTP_PARSE_H

#include <stddef.h>
#include <stdint.h>

/*
 * is_http_request - Check if the buffer starts with an HTTP request method.
 *
 * Uses a 4-byte prefix match to identify HTTP methods:
 * GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS.
 *
 * Returns 1 if the buffer appears to be an HTTP request, 0 otherwise.
 */
__attribute__((visibility("hidden")))
int is_http_request(const char *buf, size_t len);

/*
 * parse_request_line - Extract HTTP method and path from a request line.
 *
 * Parses "METHOD /path HTTP/1.x\r\n" and copies method and path into
 * the provided buffers. Strings are always NUL-terminated.
 *
 * @buf:         Raw request data
 * @len:         Length of buf
 * @method:      Output buffer for HTTP method (e.g., "GET")
 * @method_size: Size of method buffer
 * @path:        Output buffer for URL path (e.g., "/api/users")
 * @path_size:   Size of path buffer
 */
__attribute__((visibility("hidden")))
void parse_request_line(const char *buf, size_t len,
                        char *method, int method_size,
                        char *path, int path_size);

/*
 * parse_http_response_status - Extract status code from an HTTP response line.
 *
 * Matches "HTTP/1.x NNN" and returns the 3-digit status code.
 *
 * Returns the status code (e.g., 200, 404), or 0 if not a valid response.
 */
__attribute__((visibility("hidden")))
int parse_http_response_status(const char *buf, size_t len);

/*
 * parse_content_length - Extract Content-Length value from HTTP headers.
 *
 * Performs a case-insensitive search for "Content-Length:" header.
 *
 * Returns the Content-Length value, or 0 if not found.
 */
__attribute__((visibility("hidden")))
uint32_t parse_content_length(const char *buf, size_t len);

/*
 * find_header_end - Find the end of HTTP headers (\r\n\r\n).
 *
 * Returns a pointer to the first byte after the header terminator,
 * or NULL if the terminator was not found.
 */
__attribute__((visibility("hidden")))
const char *find_header_end(const char *buf, size_t len);

/*
 * count_body_bytes - Count bytes after the header terminator.
 *
 * Given a buffer that contains headers + possibly some body data,
 * returns the number of body bytes present after \r\n\r\n.
 * Returns 0 if the header end is not found.
 */
__attribute__((visibility("hidden")))
uint32_t count_body_bytes(const char *buf, size_t len);

/*
 * parse_traceparent - Extract W3C traceparent header from HTTP headers.
 *
 * Searches for "traceparent:" header (case-insensitive) and parses the
 * W3C trace context format: "00-{32hex trace_id}-{16hex span_id}-{2hex flags}"
 *
 * @buf:            Raw HTTP request data (including request line + headers)
 * @len:            Length of buf
 * @trace_id:       Output: 16-byte trace ID (only written on success)
 * @parent_span_id: Output: 8-byte parent span ID (only written on success)
 *
 * Returns 1 on success, 0 if traceparent header not found or invalid.
 */
__attribute__((visibility("hidden")))
int parse_traceparent(const char *buf, size_t len,
                      uint8_t trace_id[16], uint8_t parent_span_id[8]);

#endif /* OBI_HTTP_PARSE_H */
