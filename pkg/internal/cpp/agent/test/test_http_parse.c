/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Test: HTTP protocol parser verification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "http_parse.h"

/* ------------------------------------------------------------------ */
/* is_http_request tests                                               */
/* ------------------------------------------------------------------ */

static void test_is_http_request_methods(void) {
    assert(is_http_request("GET / HTTP/1.1\r\n", 16) == 1);
    assert(is_http_request("POST /api HTTP/1.1\r\n", 20) == 1);
    assert(is_http_request("PUT /data HTTP/1.0\r\n", 20) == 1);
    assert(is_http_request("DELETE /item HTTP/1.1\r\n", 22) == 1);
    assert(is_http_request("HEAD / HTTP/1.1\r\n", 17) == 1);
    assert(is_http_request("PATC", 4) == 1);  /* PATCH prefix = "PATC" */
    assert(is_http_request("OPTI", 4) == 1);  /* OPTIONS prefix = "OPTI" */
    printf("PASS: test_is_http_request_methods\n");
}

static void test_is_http_request_negative(void) {
    /* Redis protocol */
    assert(is_http_request("*3\r\n$3\r\nSET\r\n", 13) == 0);
    /* MySQL protocol (starts with \x00) */
    assert(is_http_request("\x00\x00\x01\x0a", 4) == 0);
    /* gRPC / HTTP2 preface */
    assert(is_http_request("PRI * HTTP/2.0\r\n", 16) == 0);
    /* Random binary */
    assert(is_http_request("\x89PNG\r\n\x1a\n", 8) == 0);
    /* Too short */
    assert(is_http_request("GE", 2) == 0);
    assert(is_http_request("", 0) == 0);
    /* NULL buffer */
    assert(is_http_request(NULL, 0) == 0);
    printf("PASS: test_is_http_request_negative\n");
}

/* ------------------------------------------------------------------ */
/* parse_request_line tests                                            */
/* ------------------------------------------------------------------ */

static void test_parse_request_line_basic(void) {
    char method[8], path[256];
    const char *req = "GET /api/users HTTP/1.1\r\n";

    parse_request_line(req, strlen(req), method, sizeof(method), path, sizeof(path));
    assert(strcmp(method, "GET") == 0);
    assert(strcmp(path, "/api/users") == 0);
    printf("PASS: test_parse_request_line_basic\n");
}

static void test_parse_request_line_with_query(void) {
    char method[8], path[256];
    const char *req = "POST /search?q=hello&page=1 HTTP/1.1\r\n";

    parse_request_line(req, strlen(req), method, sizeof(method), path, sizeof(path));
    assert(strcmp(method, "POST") == 0);
    assert(strcmp(path, "/search?q=hello&page=1") == 0);
    printf("PASS: test_parse_request_line_with_query\n");
}

static void test_parse_request_line_long_path(void) {
    char method[8], path[16]; /* Small buffer to test truncation */
    const char *req = "GET /very/long/path/that/exceeds/buffer HTTP/1.1\r\n";

    parse_request_line(req, strlen(req), method, sizeof(method), path, sizeof(path));
    assert(strcmp(method, "GET") == 0);
    /* Path should be truncated and NUL-terminated */
    assert(strlen(path) < 16);
    assert(path[15] == '\0');
    printf("PASS: test_parse_request_line_long_path\n");
}

static void test_parse_request_line_root_path(void) {
    char method[8], path[256];
    const char *req = "HEAD / HTTP/1.1\r\n";

    parse_request_line(req, strlen(req), method, sizeof(method), path, sizeof(path));
    assert(strcmp(method, "HEAD") == 0);
    assert(strcmp(path, "/") == 0);
    printf("PASS: test_parse_request_line_root_path\n");
}

/* ------------------------------------------------------------------ */
/* parse_http_response_status tests                                    */
/* ------------------------------------------------------------------ */

static void test_parse_response_status_200(void) {
    const char *resp = "HTTP/1.1 200 OK\r\n";
    assert(parse_http_response_status(resp, strlen(resp)) == 200);
    printf("PASS: test_parse_response_status_200\n");
}

static void test_parse_response_status_various(void) {
    assert(parse_http_response_status("HTTP/1.1 301 Moved\r\n", 20) == 301);
    assert(parse_http_response_status("HTTP/1.1 404 Not Found\r\n", 24) == 404);
    assert(parse_http_response_status("HTTP/1.1 500 Internal\r\n", 23) == 500);
    assert(parse_http_response_status("HTTP/1.0 204 No Content\r\n", 25) == 204);
    printf("PASS: test_parse_response_status_various\n");
}

static void test_parse_response_status_invalid(void) {
    /* Not HTTP response */
    assert(parse_http_response_status("GET / HTTP/1.1\r\n", 16) == 0);
    /* Too short */
    assert(parse_http_response_status("HTTP/1", 6) == 0);
    /* No status code */
    assert(parse_http_response_status("HTTP/1.1 \r\n", 11) == 0);
    /* Empty */
    assert(parse_http_response_status("", 0) == 0);
    printf("PASS: test_parse_response_status_invalid\n");
}

/* ------------------------------------------------------------------ */
/* parse_content_length tests                                          */
/* ------------------------------------------------------------------ */

static void test_parse_content_length_present(void) {
    const char *headers = "Host: example.com\r\nContent-Length: 42\r\n\r\n";
    assert(parse_content_length(headers, strlen(headers)) == 42);
    printf("PASS: test_parse_content_length_present\n");
}

static void test_parse_content_length_case_insensitive(void) {
    const char *headers = "host: foo\r\ncontent-length: 128\r\n\r\n";
    assert(parse_content_length(headers, strlen(headers)) == 128);
    printf("PASS: test_parse_content_length_case_insensitive\n");
}

static void test_parse_content_length_missing(void) {
    const char *headers = "Host: example.com\r\nAccept: */*\r\n\r\n";
    assert(parse_content_length(headers, strlen(headers)) == 0);
    printf("PASS: test_parse_content_length_missing\n");
}

static void test_parse_content_length_zero(void) {
    const char *headers = "Content-Length: 0\r\n\r\n";
    assert(parse_content_length(headers, strlen(headers)) == 0);
    printf("PASS: test_parse_content_length_zero\n");
}

static void test_parse_content_length_large(void) {
    const char *headers = "Content-Length: 1048576\r\n\r\n";
    assert(parse_content_length(headers, strlen(headers)) == 1048576);
    printf("PASS: test_parse_content_length_large\n");
}

/* ------------------------------------------------------------------ */
/* find_header_end tests                                               */
/* ------------------------------------------------------------------ */

static void test_find_header_end_complete(void) {
    const char *msg = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    const char *end = find_header_end(msg, strlen(msg));
    assert(end != NULL);
    assert(strcmp(end, "hello") == 0);
    printf("PASS: test_find_header_end_complete\n");
}

static void test_find_header_end_incomplete(void) {
    const char *msg = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
    const char *end = find_header_end(msg, strlen(msg));
    assert(end == NULL);
    printf("PASS: test_find_header_end_incomplete\n");
}

static void test_find_header_end_empty_body(void) {
    const char *msg = "HTTP/1.1 200 OK\r\n\r\n";
    const char *end = find_header_end(msg, strlen(msg));
    assert(end != NULL);
    assert(*end == '\0'); /* points to end of string */
    printf("PASS: test_find_header_end_empty_body\n");
}

static void test_find_header_end_empty(void) {
    assert(find_header_end("", 0) == NULL);
    assert(find_header_end(NULL, 0) == NULL);
    printf("PASS: test_find_header_end_empty\n");
}

/* ------------------------------------------------------------------ */
/* parse_traceparent tests                                             */
/* ------------------------------------------------------------------ */

static void test_parse_traceparent_valid(void) {
    const char *req =
        "GET /greeting HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n"
        "\r\n";
    uint8_t trace_id[16], parent_span_id[8];
    int ok = parse_traceparent(req, strlen(req), trace_id, parent_span_id);
    assert(ok == 1);
    /* Verify trace_id = 0af7651916cd43dd8448eb211c80319c */
    assert(trace_id[0]  == 0x0a);
    assert(trace_id[1]  == 0xf7);
    assert(trace_id[2]  == 0x65);
    assert(trace_id[3]  == 0x19);
    assert(trace_id[14] == 0x31);
    assert(trace_id[15] == 0x9c);
    /* Verify parent_span_id = b7ad6b7169203331 */
    assert(parent_span_id[0] == 0xb7);
    assert(parent_span_id[1] == 0xad);
    assert(parent_span_id[6] == 0x33);
    assert(parent_span_id[7] == 0x31);
    printf("PASS: test_parse_traceparent_valid\n");
}

static void test_parse_traceparent_case_insensitive(void) {
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: x\r\n"
        "Traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n"
        "\r\n";
    uint8_t trace_id[16], parent_span_id[8];
    int ok = parse_traceparent(req, strlen(req), trace_id, parent_span_id);
    assert(ok == 1);
    assert(trace_id[0] == 0x0a);
    printf("PASS: test_parse_traceparent_case_insensitive\n");
}

static void test_parse_traceparent_missing(void) {
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: */*\r\n"
        "\r\n";
    uint8_t trace_id[16], parent_span_id[8];
    int ok = parse_traceparent(req, strlen(req), trace_id, parent_span_id);
    assert(ok == 0);
    printf("PASS: test_parse_traceparent_missing\n");
}

static void test_parse_traceparent_malformed(void) {
    /* Wrong version */
    {
        const char *req =
            "GET / HTTP/1.1\r\n"
            "traceparent: 01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n"
            "\r\n";
        uint8_t trace_id[16], parent_span_id[8];
        assert(parse_traceparent(req, strlen(req), trace_id, parent_span_id) == 0);
    }
    /* Too short value */
    {
        const char *req =
            "GET / HTTP/1.1\r\n"
            "traceparent: 00-abc\r\n"
            "\r\n";
        uint8_t trace_id[16], parent_span_id[8];
        assert(parse_traceparent(req, strlen(req), trace_id, parent_span_id) == 0);
    }
    /* Invalid hex chars in trace_id */
    {
        const char *req =
            "GET / HTTP/1.1\r\n"
            "traceparent: 00-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-b7ad6b7169203331-01\r\n"
            "\r\n";
        uint8_t trace_id[16], parent_span_id[8];
        assert(parse_traceparent(req, strlen(req), trace_id, parent_span_id) == 0);
    }
    printf("PASS: test_parse_traceparent_malformed\n");
}

static void test_parse_traceparent_with_spaces(void) {
    /* OWS (optional whitespace) after colon */
    const char *req =
        "GET / HTTP/1.1\r\n"
        "traceparent:  00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n"
        "\r\n";
    uint8_t trace_id[16], parent_span_id[8];
    int ok = parse_traceparent(req, strlen(req), trace_id, parent_span_id);
    assert(ok == 1);
    assert(trace_id[0] == 0x0a);
    printf("PASS: test_parse_traceparent_with_spaces\n");
}

/* ------------------------------------------------------------------ */
/* count_body_bytes tests                                              */
/* ------------------------------------------------------------------ */

static void test_count_body_bytes(void) {
    const char *msg = "HTTP/1.1 200 OK\r\n\r\nhello";
    assert(count_body_bytes(msg, strlen(msg)) == 5);
    printf("PASS: test_count_body_bytes\n");
}

static void test_count_body_bytes_no_body(void) {
    const char *msg = "HTTP/1.1 200 OK\r\n\r\n";
    assert(count_body_bytes(msg, strlen(msg)) == 0);
    printf("PASS: test_count_body_bytes_no_body\n");
}

static void test_count_body_bytes_no_header_end(void) {
    const char *msg = "HTTP/1.1 200 OK\r\n";
    assert(count_body_bytes(msg, strlen(msg)) == 0);
    printf("PASS: test_count_body_bytes_no_header_end\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    /* is_http_request */
    test_is_http_request_methods();
    test_is_http_request_negative();

    /* parse_request_line */
    test_parse_request_line_basic();
    test_parse_request_line_with_query();
    test_parse_request_line_long_path();
    test_parse_request_line_root_path();

    /* parse_http_response_status */
    test_parse_response_status_200();
    test_parse_response_status_various();
    test_parse_response_status_invalid();

    /* parse_content_length */
    test_parse_content_length_present();
    test_parse_content_length_case_insensitive();
    test_parse_content_length_missing();
    test_parse_content_length_zero();
    test_parse_content_length_large();

    /* find_header_end */
    test_find_header_end_complete();
    test_find_header_end_incomplete();
    test_find_header_end_empty_body();
    test_find_header_end_empty();

    /* count_body_bytes */
    test_count_body_bytes();
    test_count_body_bytes_no_body();
    test_count_body_bytes_no_header_end();

    /* parse_traceparent */
    test_parse_traceparent_valid();
    test_parse_traceparent_case_insensitive();
    test_parse_traceparent_missing();
    test_parse_traceparent_malformed();
    test_parse_traceparent_with_spaces();

    printf("\nAll HTTP parse tests passed.\n");
    return 0;
}
