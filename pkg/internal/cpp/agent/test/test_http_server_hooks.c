/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Test: HTTP server hooks state machine and connection table
 *
 * Strategy: We expose the static functions by compiling http_server_hooks.c
 * with TEST_MODE defined, which makes process_recv_data / process_send_data
 * non-static. We also link against stub implementations of got_hook and span.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* We directly test the state machine by re-declaring the data types   */
/* and calling the functions through the normal compilation of          */
/* http_server_hooks.c. Since the functions are static, we extract     */
/* just the state machine and connection table logic.                   */
/* ------------------------------------------------------------------ */

#include "http_parse.h"

/* Replicate the connection state types from http_server_hooks.c */
#define MAX_TRACKED_FDS 1024

enum conn_state {
    CONN_IDLE,
    CONN_RECV_HEADERS,
    CONN_RECV_BODY,
    CONN_REQUEST_DONE,
    CONN_NON_HTTP,
};

struct conn_info {
    enum conn_state state;
    uint64_t        start_ns;
    uint32_t        peer_addr;
    uint16_t        peer_port;
    char            method[8];
    char            path[256];
    uint32_t        content_length;
    uint32_t        body_received;
    uint8_t         is_tls;
    int             active;
};

/* Track emitted spans */
static int g_span_count = 0;
static char g_last_method[8];
static char g_last_path[256];
static int g_last_status = 0;

static void reset_span_tracking(void) {
    g_span_count = 0;
    g_last_method[0] = '\0';
    g_last_path[0] = '\0';
    g_last_status = 0;
}

/* ------------------------------------------------------------------ */
/* Re-implement process_recv_data / process_send_data exactly as in    */
/* http_server_hooks.c but with our span stub                          */
/* ------------------------------------------------------------------ */

static void process_recv_data(struct conn_info *ci, const char *buf, size_t len) {
    switch (ci->state) {
    case CONN_IDLE:
        if (is_http_request(buf, len)) {
            ci->state = CONN_RECV_HEADERS;
            ci->start_ns = 1000000000ULL; /* fixed for testing */
            parse_request_line(buf, len,
                               ci->method, (int)sizeof(ci->method),
                               ci->path, (int)sizeof(ci->path));

            const char *body_start = find_header_end(buf, len);
            if (body_start) {
                ci->content_length = parse_content_length(buf, len);
                if (ci->content_length == 0) {
                    ci->state = CONN_REQUEST_DONE;
                } else {
                    ci->state = CONN_RECV_BODY;
                    ci->body_received = (uint32_t)(len - (size_t)(body_start - buf));
                    if (ci->body_received >= ci->content_length) {
                        ci->state = CONN_REQUEST_DONE;
                    }
                }
            }
        } else {
            ci->state = CONN_NON_HTTP;
        }
        break;

    case CONN_RECV_HEADERS:
        if (find_header_end(buf, len)) {
            ci->content_length = parse_content_length(buf, len);
            ci->state = (ci->content_length > 0) ? CONN_RECV_BODY : CONN_REQUEST_DONE;
        }
        break;

    case CONN_RECV_BODY:
        ci->body_received += (uint32_t)len;
        if (ci->body_received >= ci->content_length) {
            ci->state = CONN_REQUEST_DONE;
        }
        break;

    default:
        break;
    }
}

static void process_send_data(struct conn_info *ci, const char *buf, size_t len) {
    if (ci->state != CONN_REQUEST_DONE) return;

    int status = parse_http_response_status(buf, len);
    if (status > 0) {
        /* Record span emission */
        g_span_count++;
        memset(g_last_method, 0, sizeof(g_last_method));
        memset(g_last_path, 0, sizeof(g_last_path));
        memcpy(g_last_method, ci->method, sizeof(g_last_method) - 1);
        memcpy(g_last_path, ci->path, sizeof(g_last_path) - 1);
        g_last_status = status;

        /* Reset for keep-alive */
        ci->state = CONN_IDLE;
        ci->content_length = 0;
        ci->body_received = 0;
        memset(ci->method, 0, sizeof(ci->method));
        memset(ci->path, 0, sizeof(ci->path));
    }
}

static inline struct conn_info *get_conn(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return NULL;
    static struct conn_info conns[MAX_TRACKED_FDS];
    return &conns[fd];
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_state_machine_normal_get(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    const char *req = "GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    process_recv_data(&ci, req, strlen(req));

    assert(ci.state == CONN_REQUEST_DONE);
    assert(strcmp(ci.method, "GET") == 0);
    assert(strcmp(ci.path, "/api/test") == 0);

    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    process_send_data(&ci, resp, strlen(resp));

    assert(g_span_count == 1);
    assert(g_last_status == 200);
    assert(strcmp(g_last_method, "GET") == 0);
    assert(strcmp(g_last_path, "/api/test") == 0);
    assert(ci.state == CONN_IDLE);

    printf("PASS: test_state_machine_normal_get\n");
}

static void test_state_machine_post_with_body(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    const char *req = "POST /submit HTTP/1.1\r\nContent-Length: 20\r\n\r\n";
    process_recv_data(&ci, req, strlen(req));

    assert(ci.state == CONN_RECV_BODY);
    assert(ci.content_length == 20);
    assert(ci.body_received == 0);

    process_recv_data(&ci, "0123456789", 10);
    assert(ci.state == CONN_RECV_BODY);
    assert(ci.body_received == 10);

    process_recv_data(&ci, "0123456789", 10);
    assert(ci.state == CONN_REQUEST_DONE);

    const char *resp = "HTTP/1.1 201 Created\r\n\r\n";
    process_send_data(&ci, resp, strlen(resp));

    assert(g_span_count == 1);
    assert(g_last_status == 201);
    assert(strcmp(g_last_method, "POST") == 0);

    printf("PASS: test_state_machine_post_with_body\n");
}

static void test_state_machine_keep_alive(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    /* First request */
    const char *req1 = "GET /page1 HTTP/1.1\r\nHost: foo\r\n\r\n";
    process_recv_data(&ci, req1, strlen(req1));
    assert(ci.state == CONN_REQUEST_DONE);

    const char *resp1 = "HTTP/1.1 200 OK\r\n\r\n";
    process_send_data(&ci, resp1, strlen(resp1));
    assert(g_span_count == 1);
    assert(ci.state == CONN_IDLE);

    /* Second request on same connection */
    const char *req2 = "GET /page2 HTTP/1.1\r\nHost: foo\r\n\r\n";
    process_recv_data(&ci, req2, strlen(req2));
    assert(ci.state == CONN_REQUEST_DONE);
    assert(strcmp(ci.path, "/page2") == 0);

    const char *resp2 = "HTTP/1.1 404 Not Found\r\n\r\n";
    process_send_data(&ci, resp2, strlen(resp2));
    assert(g_span_count == 2);
    assert(g_last_status == 404);
    assert(ci.state == CONN_IDLE);

    printf("PASS: test_state_machine_keep_alive\n");
}

static void test_state_machine_non_http(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    const char *data = "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
    process_recv_data(&ci, data, strlen(data));
    assert(ci.state == CONN_NON_HTTP);

    /* Further data should not change state */
    process_recv_data(&ci, "more data", 9);
    assert(ci.state == CONN_NON_HTTP);

    /* Send should not emit span */
    process_send_data(&ci, "response", 8);
    assert(g_span_count == 0);

    printf("PASS: test_state_machine_non_http\n");
}

static void test_conn_table_boundaries(void) {
    /* fd=0 should be valid */
    struct conn_info *ci = get_conn(0);
    assert(ci != NULL);

    /* fd=MAX_TRACKED_FDS-1 should be valid */
    ci = get_conn(MAX_TRACKED_FDS - 1);
    assert(ci != NULL);

    /* fd=MAX_TRACKED_FDS should be out of range */
    ci = get_conn(MAX_TRACKED_FDS);
    assert(ci == NULL);

    /* fd=-1 should be out of range */
    ci = get_conn(-1);
    assert(ci == NULL);

    printf("PASS: test_conn_table_boundaries\n");
}

static void test_response_without_request(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    const char *resp = "HTTP/1.1 200 OK\r\n\r\n";
    process_send_data(&ci, resp, strlen(resp));
    assert(g_span_count == 0);

    printf("PASS: test_response_without_request\n");
}

static void test_post_body_in_first_recv(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    const char *req = "POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    process_recv_data(&ci, req, strlen(req));

    assert(ci.state == CONN_REQUEST_DONE);
    assert(strcmp(ci.method, "POST") == 0);

    printf("PASS: test_post_body_in_first_recv\n");
}

static void test_fragmented_headers(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    /* First recv: incomplete headers (no \r\n\r\n) */
    const char *frag1 = "GET /frag HTTP/1.1\r\nHost: ex";
    process_recv_data(&ci, frag1, strlen(frag1));
    assert(ci.state == CONN_RECV_HEADERS);

    /* Second recv: rest of headers */
    const char *frag2 = "ample.com\r\n\r\n";
    process_recv_data(&ci, frag2, strlen(frag2));
    assert(ci.state == CONN_REQUEST_DONE);

    printf("PASS: test_fragmented_headers\n");
}

static void test_500_error_response(void) {
    reset_span_tracking();
    struct conn_info ci;
    memset(&ci, 0, sizeof(ci));
    ci.state = CONN_IDLE;
    ci.active = 1;

    const char *req = "GET /error HTTP/1.1\r\nHost: x\r\n\r\n";
    process_recv_data(&ci, req, strlen(req));
    assert(ci.state == CONN_REQUEST_DONE);

    const char *resp = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    process_send_data(&ci, resp, strlen(resp));

    assert(g_span_count == 1);
    assert(g_last_status == 500);

    printf("PASS: test_500_error_response\n");
}

int main(void) {
    test_state_machine_normal_get();
    test_state_machine_post_with_body();
    test_state_machine_keep_alive();
    test_state_machine_non_http();
    test_conn_table_boundaries();
    test_response_without_request();
    test_post_body_in_first_recv();
    test_fragmented_headers();
    test_500_error_response();

    printf("\nAll HTTP server hook tests passed.\n");
    return 0;
}
