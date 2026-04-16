/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - HTTP protocol parser
 *
 * Lightweight HTTP/1.x request line and response line parser.
 * Designed for minimal overhead in GOT hook hot paths.
 */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "http_parse.h"

/*
 * is_http_request - Check if buffer starts with an HTTP request method.
 *
 * Uses 4-byte prefix matching for fast rejection of non-HTTP data.
 * Validated against 14 non-HTTP protocols in POC testing.
 */
__attribute__((visibility("hidden")))
int is_http_request(const char *buf, size_t len) {
    if (len < 4) return 0;
    return (memcmp(buf, "GET ", 4) == 0 ||
            memcmp(buf, "POST", 4) == 0 ||
            memcmp(buf, "PUT ", 4) == 0 ||
            memcmp(buf, "DELE", 4) == 0 ||  /* DELETE */
            memcmp(buf, "HEAD", 4) == 0 ||
            memcmp(buf, "PATC", 4) == 0 ||  /* PATCH */
            memcmp(buf, "OPTI", 4) == 0);   /* OPTIONS */
}

/*
 * parse_request_line - Extract method and path from "METHOD /path HTTP/1.x\r\n".
 */
__attribute__((visibility("hidden")))
void parse_request_line(const char *buf, size_t len,
                        char *method, int method_size,
                        char *path, int path_size) {
    /* Initialize outputs */
    if (method_size > 0) method[0] = '\0';
    if (path_size > 0) path[0] = '\0';

    /* Find first space → end of method */
    const char *sp1 = memchr(buf, ' ', len);
    if (!sp1) return;

    int mlen = (int)(sp1 - buf);
    if (mlen >= method_size) mlen = method_size - 1;
    if (mlen > 0) {
        memcpy(method, buf, mlen);
    }
    method[mlen] = '\0';

    /* Find second space → end of path */
    sp1++;
    size_t remaining = len - (size_t)(sp1 - buf);
    const char *sp2 = memchr(sp1, ' ', remaining);
    if (!sp2) {
        /* No second space; try \r\n as terminator */
        sp2 = memchr(sp1, '\r', remaining);
        if (!sp2) {
            /* Take the rest (up to path_size) */
            int plen = (int)remaining;
            if (plen >= path_size) plen = path_size - 1;
            if (plen > 0) {
                memcpy(path, sp1, plen);
            }
            path[plen] = '\0';
            return;
        }
    }

    int plen = (int)(sp2 - sp1);
    if (plen >= path_size) plen = path_size - 1;
    if (plen > 0) {
        memcpy(path, sp1, plen);
    }
    path[plen] = '\0';
}

/*
 * parse_http_response_status - Extract status code from "HTTP/1.x NNN ...".
 *
 * Returns the 3-digit status code, or 0 if the buffer doesn't match.
 */
__attribute__((visibility("hidden")))
int parse_http_response_status(const char *buf, size_t len) {
    /* Minimum: "HTTP/1.x NNN" = 12 bytes */
    if (len < 12) return 0;
    if (memcmp(buf, "HTTP/1.", 7) != 0) return 0;

    /* buf[8] should be space, buf[9..11] should be digits */
    if (buf[8] != ' ') return 0;
    if (!isdigit((unsigned char)buf[9]) ||
        !isdigit((unsigned char)buf[10]) ||
        !isdigit((unsigned char)buf[11])) {
        return 0;
    }

    return (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
}

/*
 * parse_content_length - Extract Content-Length value from HTTP headers.
 *
 * Case-insensitive search for "Content-Length:" header line.
 */
__attribute__((visibility("hidden")))
uint32_t parse_content_length(const char *buf, size_t len) {
    /* Search for "Content-Length:" (case-insensitive) */
    const char *p = buf;
    const char *end = buf + len - 15; /* minimum "Content-Length:0" */

    while (p <= end) {
        /* Find next newline to get line start */
        if ((p[0] == 'C' || p[0] == 'c') &&
            (p[1] == 'o' || p[1] == 'O') &&
            (p[2] == 'n' || p[2] == 'N') &&
            (p[3] == 't' || p[3] == 'T') &&
            (p[4] == 'e' || p[4] == 'E') &&
            (p[5] == 'n' || p[5] == 'N') &&
            (p[6] == 't' || p[6] == 'T') &&
            p[7] == '-' &&
            (p[8] == 'L' || p[8] == 'l') &&
            (p[9] == 'e' || p[9] == 'E') &&
            (p[10] == 'n' || p[10] == 'N') &&
            (p[11] == 'g' || p[11] == 'G') &&
            (p[12] == 't' || p[12] == 'T') &&
            (p[13] == 'h' || p[13] == 'H') &&
            p[14] == ':') {
            /* Skip "Content-Length:" and optional whitespace */
            const char *val = p + 15;
            while (val < buf + len && *val == ' ') val++;

            /* Parse digits */
            uint32_t result = 0;
            while (val < buf + len && isdigit((unsigned char)*val)) {
                result = result * 10 + (*val - '0');
                val++;
            }
            return result;
        }
        /* Advance to next line */
        const char *nl = memchr(p, '\n', len - (size_t)(p - buf));
        if (!nl) break;
        p = nl + 1;
    }

    return 0;
}

/*
 * find_header_end - Find the end of HTTP headers (\r\n\r\n).
 *
 * Returns pointer to first byte after \r\n\r\n, or NULL if not found.
 */
__attribute__((visibility("hidden")))
const char *find_header_end(const char *buf, size_t len) {
    if (len < 4) return NULL;

    const char *end = buf + len - 3;
    for (const char *p = buf; p < end; p++) {
        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            return p + 4;
        }
    }
    return NULL;
}

/*
 * count_body_bytes - Count bytes after the header terminator.
 */
__attribute__((visibility("hidden")))
uint32_t count_body_bytes(const char *buf, size_t len) {
    const char *body_start = find_header_end(buf, len);
    if (!body_start) return 0;

    size_t header_len = (size_t)(body_start - buf);
    if (header_len >= len) return 0;

    return (uint32_t)(len - header_len);
}

/*
 * hex_digit - Convert a hex character to its numeric value.
 * Returns -1 if not a valid hex digit.
 */
static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * parse_hex_bytes - Parse hex string into byte array.
 * Returns 1 on success, 0 if any character is not a valid hex digit.
 */
static int parse_hex_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_digit(hex[i * 2]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

/*
 * parse_traceparent - Extract W3C traceparent header from HTTP headers.
 *
 * Searches for "traceparent:" (case-insensitive) and parses:
 *   00-{32 hex trace_id}-{16 hex span_id}-{2 hex flags}
 *
 * Returns 1 on success, 0 if not found or invalid format.
 */
__attribute__((visibility("hidden")))
int parse_traceparent(const char *buf, size_t len,
                      uint8_t trace_id[16], uint8_t parent_span_id[8]) {
    /*
     * Search for "\ntraceparent:" or "\r\ntraceparent:" (case-insensitive).
     * Also check if the header starts at the very beginning after the
     * request line (unlikely but possible).
     */
    static const char hdr_lower[] = "traceparent:";
    const size_t hdr_len = 12; /* strlen("traceparent:") */

    const char *p = buf;
    const char *end = buf + len;
    const char *val = NULL;

    while (p < end) {
        /* Find next newline */
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;

        const char *line_start = nl + 1;
        if (line_start + hdr_len >= end) break;

        /* Case-insensitive match for "traceparent:" */
        int match = 1;
        for (size_t i = 0; i < hdr_len; i++) {
            char c = line_start[i];
            /* Convert to lowercase for comparison */
            if (c >= 'A' && c <= 'Z') c += 32;
            if (c != hdr_lower[i]) {
                match = 0;
                break;
            }
        }

        if (match) {
            val = line_start + hdr_len;
            break;
        }

        p = line_start;
    }

    if (!val) return 0;

    /* Skip optional whitespace after colon */
    while (val < end && (*val == ' ' || *val == '\t')) val++;

    /*
     * W3C traceparent format: "00-{32hex}-{16hex}-{2hex}"
     * Minimum length: 2 + 1 + 32 + 1 + 16 + 1 + 2 = 55 chars
     */
    if (val + 55 > end) return 0;

    /* Verify version "00" and separator */
    if (val[0] != '0' || val[1] != '0' || val[2] != '-') return 0;

    /* Parse 32-char trace-id (16 bytes) */
    if (val[35] != '-') return 0; /* separator after trace-id */
    if (!parse_hex_bytes(val + 3, trace_id, 16)) return 0;

    /* Parse 16-char parent-id (8 bytes) */
    if (val[52] != '-') return 0; /* separator after parent-id */
    if (!parse_hex_bytes(val + 36, parent_span_id, 8)) return 0;

    return 1;
}
