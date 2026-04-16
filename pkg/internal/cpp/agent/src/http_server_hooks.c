/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - HTTP server hooks
 *
 * Intercepts libc socket functions (accept4/recv/send/close) via GOT
 * hooking to detect HTTP traffic and generate server-side spans.
 * Also hooks SSL_read/SSL_write for HTTPS/TLS support.
 *
 * The approach is protocol-aware and library-agnostic: it works with
 * any C++ HTTP server that uses libc for socket I/O (e.g., cpp-httplib).
 *
 * TLS note: Some libraries (e.g., cpp-httplib) read one byte at a time
 * via SSL_read.  We handle this with a per-fd reassembly buffer that
 * accumulates decrypted bytes until a complete HTTP request is detected.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <unistd.h>

#include "config.h"
#include "got_hook.h"
#include "host_tid.h"
#include "span.h"
#include "http_parse.h"

/* Access global config and BPF map fd from agent.c */
extern struct obi_config g_obi_config;
extern int g_incoming_trace_map_fd;
extern int g_traces_ctx_fd;

/* Debug logging macro (same as agent.c) */
#define OBI_DBG(fmt, ...) \
    do { \
        if (obi_config_has_flag(&g_obi_config, OBI_CFG_DEBUG)) { \
            fprintf(stderr, "[obi-http-hooks] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/* ------------------------------------------------------------------ */
/* Per-fd connection tracking                                          */
/* ------------------------------------------------------------------ */

#define MAX_TRACKED_FDS 1024

/*
 * Reassembly buffer size for TLS connections.
 * Must be large enough to hold a complete HTTP request line + headers.
 * 4 KB is generous for typical request headers.
 */
#define TLS_REASM_BUF_SIZE 4096

enum conn_state {
    CONN_IDLE,           /* Waiting for new request */
    CONN_RECV_HEADERS,   /* Receiving request headers */
    CONN_RECV_BODY,      /* Receiving request body (Content-Length tracking) */
    CONN_REQUEST_DONE,   /* Request complete, waiting for response */
    CONN_NON_HTTP,       /* Confirmed non-HTTP, skip forever (plain only) */
};

struct conn_info {
    enum conn_state state;
    uint64_t        start_ns;       /* Span start timestamp (CLOCK_MONOTONIC) */
    uint32_t        peer_addr;      /* IPv4 peer address (network byte order) */
    uint16_t        peer_port;      /* Peer port (host byte order) */
    uint32_t        local_addr;     /* IPv4 local address (network byte order) */
    uint16_t        local_port;     /* Local port (host byte order) */
    char            method[8];      /* HTTP method: GET, POST, etc. */
    char            path[256];      /* URL path */
    uint32_t        content_length; /* Request body length (0 = no body) */
    uint32_t        body_received;  /* Body bytes received so far */
    uint8_t         is_tls;         /* 1 = TLS connection */
    int             active;         /* Slot in use */

    /* Parsed W3C traceparent header from incoming request */
    uint8_t         trace_id[16];       /* trace-id from traceparent */
    uint8_t         parent_span_id[8];  /* parent-id from traceparent */
    uint8_t         has_traceparent;    /* 1 if valid traceparent was found */

    /* TLS reassembly buffer for byte-at-a-time reading */
    char            tls_buf[TLS_REASM_BUF_SIZE];
    uint32_t        tls_buf_len;    /* Current bytes in tls_buf */
};

static struct conn_info g_conns[MAX_TRACKED_FDS];

static inline struct conn_info *get_conn(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return NULL;
    return &g_conns[fd];
}

static uint64_t clock_gettime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* Shared processing logic for plain HTTP (large recv buffers)         */
/* ------------------------------------------------------------------ */

static void process_recv_data(struct conn_info *ci, const char *buf, size_t len) {
    switch (ci->state) {
    case CONN_IDLE:
        if (is_http_request(buf, len)) {
            ci->state = CONN_RECV_HEADERS;
            ci->start_ns = clock_gettime_ns();
            parse_request_line(buf, len,
                               ci->method, (int)sizeof(ci->method),
                               ci->path, (int)sizeof(ci->path));

            /* Check if we got complete headers in one recv */
            const char *body_start = find_header_end(buf, len);
            if (body_start) {
                /* Parse traceparent from complete headers */
                ci->has_traceparent = (uint8_t)parse_traceparent(
                    buf, (size_t)(body_start - buf),
                    ci->trace_id, ci->parent_span_id);

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
        /* Continue receiving headers (TCP fragmentation) */
        if (find_header_end(buf, len)) {
            /* Parse traceparent from complete headers */
            ci->has_traceparent = (uint8_t)parse_traceparent(
                buf, len, ci->trace_id, ci->parent_span_id);

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
    OBI_DBG("process_send_data: status=%d method=%s path=%s tls=%d len=%zu",
            status, ci->method, ci->path, ci->is_tls, len);
    if (status > 0) {
        /* Emit span */
        struct obi_span *span = obi_span_begin(OBI_EVENT_HTTP_SERVER);
        if (span) {
            obi_span_set_method(span, ci->method);
            obi_span_set_url(span, ci->path);
            obi_span_set_status(span, (uint16_t)status);
            span->event.start_time_ns = ci->start_ns;

            /* Propagate trace context from incoming traceparent header */
            if (ci->has_traceparent) {
                memcpy(span->event.trace_id, ci->trace_id, 16);
                memcpy(span->event.parent_span_id, ci->parent_span_id, 8);
                /* span_id stays randomly generated (this is a new span) */
            }

            obi_span_end(span);
            OBI_DBG("span emitted: %s %s -> %d (tls=%d traceparent=%d)",
                    ci->method, ci->path, status, ci->is_tls, ci->has_traceparent);
        }

        /* Reset for keep-alive */
        ci->state = CONN_IDLE;
        ci->content_length = 0;
        ci->body_received = 0;
        ci->tls_buf_len = 0;
        ci->has_traceparent = 0;
        memset(ci->trace_id, 0, sizeof(ci->trace_id));
        memset(ci->parent_span_id, 0, sizeof(ci->parent_span_id));
        memset(ci->method, 0, sizeof(ci->method));
        memset(ci->path, 0, sizeof(ci->path));
    }
}

/* ------------------------------------------------------------------ */
/* BPF map write: propagate parsed traceparent to eBPF via             */
/* incoming_trace_map so kprobe can late-bind the trace context.       */
/* ------------------------------------------------------------------ */

/*
 * IPv4-mapped-IPv6 prefix (::ffff:0:0/96).
 * Must match bpf/common/connection_info.h:ip4ip6_prefix.
 */
static const uint8_t ip4ip6_prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};

/* EPHEMERAL_PORT_MIN — must match bpf/common/protocol_defs.h */
#define EPHEMERAL_PORT_MIN 32768

/*
 * write_incoming_trace_map — Write parsed traceparent into the BPF
 * incoming_trace_map so eBPF kprobe can find it during server span creation.
 *
 * Key:   connection_info_t (36 bytes) — sorted 4-tuple with IPv4-in-IPv6 encoding
 * Value: tp_info_pid_t    (56 bytes) — trace_id, span_id (= parent's span_id)
 */
static void write_incoming_trace_map(struct conn_info *ci) {
    if (g_incoming_trace_map_fd < 0 || !ci->has_traceparent) return;

    /*
     * Build connection_info_t key (36 bytes).
     * IPv4 addresses are stored in IPv4-mapped-IPv6 format:
     *   bytes [0..11] = ip4ip6_prefix, bytes [12..15] = IPv4 addr (NBO).
     * After filling, sort so the ephemeral port (client) is in s_port.
     */
    struct {
        uint8_t  s_addr[16];
        uint8_t  d_addr[16];
        uint16_t s_port;
        uint16_t d_port;
    } conn_key;
    memset(&conn_key, 0, sizeof(conn_key));

    /* Peer = client side (ephemeral port) → s_addr initially */
    memcpy(conn_key.s_addr, ip4ip6_prefix, 12);
    memcpy(conn_key.s_addr + 12, &ci->peer_addr, 4);
    conn_key.s_port = ci->peer_port;

    /* Local = server side (well-known port) → d_addr initially */
    memcpy(conn_key.d_addr, ip4ip6_prefix, 12);
    memcpy(conn_key.d_addr + 12, &ci->local_addr, 4);
    conn_key.d_port = ci->local_port;

    /*
     * sort_connection_info() equivalent — matches
     * bpf/common/connection_info.h:sort_connection_info().
     */
    int s_eph = (conn_key.s_port >= EPHEMERAL_PORT_MIN);
    int d_eph = (conn_key.d_port >= EPHEMERAL_PORT_MIN);

    if (s_eph && !d_eph) {
        /* Already correct: client (ephemeral) in source position */
    } else if ((d_eph && !s_eph) || (conn_key.d_port > conn_key.s_port)) {
        /* Swap source ↔ destination */
        uint8_t  tmp_addr[16];
        uint16_t tmp_port;
        memcpy(tmp_addr, conn_key.s_addr, 16);
        memcpy(conn_key.s_addr, conn_key.d_addr, 16);
        memcpy(conn_key.d_addr, tmp_addr, 16);
        tmp_port = conn_key.s_port;
        conn_key.s_port = conn_key.d_port;
        conn_key.d_port = tmp_port;
    }

    /*
     * Build tp_info_pid_t value (56 bytes).
     * Layout must exactly match bpf/common/tp_info.h.
     */
    struct {
        /* tp_info_t (48 bytes) */
        uint8_t  trace_id[16];
        uint8_t  span_id[8];     /* parent's span ID from traceparent */
        uint8_t  parent_id[8];   /* unused by find_trace_for_server_request */
        uint64_t ts;
        uint8_t  flags;
        uint8_t  _pad1[7];
        /* tp_info_pid_t extra fields (8 bytes) */
        uint32_t pid;
        uint8_t  valid;
        uint8_t  written;
        uint8_t  req_type;
        uint8_t  _pad2[1];
    } tp_val;
    memset(&tp_val, 0, sizeof(tp_val));

    memcpy(tp_val.trace_id, ci->trace_id, 16);
    memcpy(tp_val.span_id, ci->parent_span_id, 8);
    tp_val.pid   = g_obi_config.host_pid;
    tp_val.valid = 1;

    /* BPF_MAP_UPDATE_ELEM via raw bpf() syscall */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)g_incoming_trace_map_fd;
    attr.key    = (uint64_t)(unsigned long)&conn_key;
    attr.value  = (uint64_t)(unsigned long)&tp_val;
    attr.flags  = 0; /* BPF_ANY */

    long rc = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    OBI_DBG("write_incoming_trace_map: rc=%ld peer=%08x:%u local=%08x:%u",
            rc, ci->peer_addr, ci->peer_port, ci->local_addr, ci->local_port);

    /*
     * Also update traces_ctx_v1 with the correct trace context so that
     * child spans (e.g., Redis SET/GET) created on the same thread during
     * request handling inherit the correct traceID from the traceparent
     * header, rather than the random traceID that eBPF initially assigned.
     *
     * traces_ctx_v1 key: (host_pid << 32) | host_tid
     * traces_ctx_v1 value: obi_ctx_info_t = { trace_id[16], span_id[8] }
     *
     * Use per-thread key so concurrent worker threads (e.g., cpp-httplib
     * thread pool) each have their own trace context entry and don't
     * overwrite each other.  The host_tid is obtained from /proc NSpid.
     * This matches bpf_get_current_pid_tgid() on the eBPF side.
     */
    if (g_traces_ctx_fd >= 0 && rc == 0 && g_obi_config.host_pid != 0) {
        uint64_t host_pid_tgid = make_host_pid_tgid(g_obi_config.host_pid);

        struct {
            uint8_t trace_id[16];
            uint8_t span_id[8];
        } ctx_val;
        memcpy(ctx_val.trace_id, ci->trace_id, 16);
        memcpy(ctx_val.span_id, ci->parent_span_id, 8);

        union bpf_attr ctx_attr;
        memset(&ctx_attr, 0, sizeof(ctx_attr));
        ctx_attr.map_fd = (uint32_t)g_traces_ctx_fd;
        ctx_attr.key    = (uint64_t)(unsigned long)&host_pid_tgid;
        ctx_attr.value  = (uint64_t)(unsigned long)&ctx_val;
        ctx_attr.flags  = 0; /* BPF_ANY */

        long ctx_rc = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &ctx_attr, sizeof(ctx_attr));
        OBI_DBG("update_traces_ctx_v1: rc=%ld host_pid_tgid=0x%llx (host_pid=%u)",
                ctx_rc, (unsigned long long)host_pid_tgid, g_obi_config.host_pid);
    }
}

/* ------------------------------------------------------------------ */
/* TLS reassembly: accumulate bytes and process once we have enough    */
/* ------------------------------------------------------------------ */

/*
 * tls_process_accumulated - Process the TLS reassembly buffer.
 *
 * Called after appending new bytes to tls_buf.  Tries to detect and
 * parse the HTTP request from the accumulated data.
 *
 * For CONN_IDLE: waits until we have at least 4 bytes to check the
 * HTTP method, then detects headers end (\r\n\r\n).
 *
 * For CONN_RECV_HEADERS: continues waiting for \r\n\r\n.
 */
static void tls_process_accumulated(struct conn_info *ci) {
    const char *buf = ci->tls_buf;
    size_t len = ci->tls_buf_len;

    switch (ci->state) {
    case CONN_IDLE:
        /* Need at least 4 bytes to detect HTTP method (e.g., "GET ") */
        if (len < 4) return;

        if (is_http_request(buf, len)) {
            ci->state = CONN_RECV_HEADERS;
            ci->start_ns = clock_gettime_ns();
            parse_request_line(buf, len,
                               ci->method, (int)sizeof(ci->method),
                               ci->path, (int)sizeof(ci->path));
            OBI_DBG("TLS request detected: %s %s (buf_len=%u)",
                    ci->method, ci->path, ci->tls_buf_len);

            /* Check if complete headers arrived */
            const char *body_start = find_header_end(buf, len);
            if (body_start) {
                /* Parse traceparent from complete headers */
                ci->has_traceparent = (uint8_t)parse_traceparent(
                    buf, (size_t)(body_start - buf),
                    ci->trace_id, ci->parent_span_id);

                /* Write traceparent to BPF incoming_trace_map for eBPF late-binding */
                write_incoming_trace_map(ci);

                ci->content_length = parse_content_length(buf, len);
                if (ci->content_length == 0) {
                    ci->state = CONN_REQUEST_DONE;
                    ci->tls_buf_len = 0; /* Done with buffer */
                    OBI_DBG("TLS request complete (no body): %s %s",
                            ci->method, ci->path);
                } else {
                    ci->state = CONN_RECV_BODY;
                    ci->body_received = (uint32_t)(len - (size_t)(body_start - buf));
                    ci->tls_buf_len = 0; /* Done with header buffer */
                    if (ci->body_received >= ci->content_length) {
                        ci->state = CONN_REQUEST_DONE;
                    }
                }
            }
        } else {
            /*
             * Not HTTP.  For TLS, don't mark as CONN_NON_HTTP permanently
             * because the first few bytes might be from a renegotiation or
             * alert.  Instead, just reset the buffer and stay IDLE.
             * The plain recv hook will handle CONN_NON_HTTP for non-TLS.
             */
            ci->tls_buf_len = 0;
        }
        break;

    case CONN_RECV_HEADERS:
        /* Re-parse from accumulated buffer for complete headers */
        parse_request_line(buf, len,
                           ci->method, (int)sizeof(ci->method),
                           ci->path, (int)sizeof(ci->path));

        if (find_header_end(buf, len)) {
            /* Parse traceparent from complete headers */
            ci->has_traceparent = (uint8_t)parse_traceparent(
                buf, len, ci->trace_id, ci->parent_span_id);

            /* Write traceparent to BPF incoming_trace_map for eBPF late-binding */
            write_incoming_trace_map(ci);

            ci->content_length = parse_content_length(buf, len);
            ci->tls_buf_len = 0; /* Done with header buffer */
            if (ci->content_length > 0) {
                ci->state = CONN_RECV_BODY;
                /* Approximate: body bytes already in buffer */
                const char *body_start = find_header_end(buf, len);
                if (body_start) {
                    ci->body_received = (uint32_t)(len - (size_t)(body_start - buf));
                }
                if (ci->body_received >= ci->content_length) {
                    ci->state = CONN_REQUEST_DONE;
                }
            } else {
                ci->state = CONN_REQUEST_DONE;
            }
            OBI_DBG("TLS headers complete: %s %s content_length=%u state=%d",
                    ci->method, ci->path, ci->content_length, (int)ci->state);
        }
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Plain HTTP hooks: accept4, recv, send, close                        */
/* ------------------------------------------------------------------ */

static int (*orig_accept4)(int, struct sockaddr *, socklen_t *, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static int (*orig_close)(int) = NULL;

static int hooked_accept4(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen, int flags) {
    int fd = orig_accept4(sockfd, addr, addrlen, flags);
    if (fd >= 0 && fd < MAX_TRACKED_FDS) {
        struct conn_info *ci = &g_conns[fd];
        memset(ci, 0, sizeof(*ci));
        ci->state = CONN_IDLE;
        ci->active = 1;
        if (addr && addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            ci->peer_addr = sin->sin_addr.s_addr;
            ci->peer_port = ntohs(sin->sin_port);
        }
        /* Get local address/port via getsockname for BPF map key construction */
        struct sockaddr_in local_sin;
        socklen_t local_len = sizeof(local_sin);
        if (getsockname(fd, (struct sockaddr *)&local_sin, &local_len) == 0
            && local_sin.sin_family == AF_INET) {
            ci->local_addr = local_sin.sin_addr.s_addr;
            ci->local_port = ntohs(local_sin.sin_port);
        }
    }
    return fd;
}

static ssize_t hooked_recv(int fd, void *buf, size_t len, int flags) {
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (ret <= 0) return ret;

    struct conn_info *ci = get_conn(fd);
    if (!ci) return ret;

    /* Auto-activate fd for tracking if not already active.
     * This handles pre-existing connections established before
     * agent injection (e.g., keep-alive connections). */
    if (!ci->active) {
        ci->active = 1;
        ci->state = CONN_IDLE;
    }

    /* Skip processing for TLS fds — encrypted data is meaningless */
    if (ci->is_tls) return ret;

    if (ci->state == CONN_NON_HTTP) return ret;

    process_recv_data(ci, (const char *)buf, (size_t)ret);
    return ret;
}

static ssize_t hooked_send(int fd, const void *buf, size_t len, int flags) {
    struct conn_info *ci = get_conn(fd);
    if (ci && ci->active && !ci->is_tls && ci->state == CONN_REQUEST_DONE) {
        process_send_data(ci, (const char *)buf, len);
    }
    return orig_send(fd, buf, len, flags);
}

static int hooked_close(int fd) {
    struct conn_info *ci = get_conn(fd);
    if (ci && ci->active) {
        ci->active = 0;
        ci->state = CONN_IDLE;
        ci->tls_buf_len = 0;
    }
    return orig_close(fd);
}

/* ------------------------------------------------------------------ */
/* TLS hooks: SSL_read, SSL_write                                      */
/* ------------------------------------------------------------------ */

typedef int (*ssl_read_fn)(void *, void *, int);
typedef int (*ssl_write_fn)(void *, const void *, int);
typedef int (*ssl_get_fd_fn)(const void *);

static ssl_read_fn orig_SSL_read = NULL;
static ssl_write_fn orig_SSL_write = NULL;
static ssl_get_fd_fn resolved_SSL_get_fd = NULL;

static int hooked_SSL_read(void *ssl, void *buf, int num) {
    int ret = orig_SSL_read(ssl, buf, num);
    if (ret <= 0 || !resolved_SSL_get_fd) return ret;

    int fd = resolved_SSL_get_fd(ssl);
    struct conn_info *ci = get_conn(fd);
    if (!ci) return ret;

    /* Activate the fd for TLS tracking if not already active */
    if (!ci->active) {
        ci->active = 1;
        ci->state = CONN_IDLE;
        ci->tls_buf_len = 0;
    }
    ci->is_tls = 1;

    /* Refresh peer/local addresses at the start of each new request.
     * The fd may have been reused for a different connection (no close
     * hook in the TLS path), so we re-read the addresses on every
     * CONN_IDLE → first-data transition. */
    if (ci->state == CONN_IDLE && ci->tls_buf_len == 0) {
        struct sockaddr_in sin;
        socklen_t slen = sizeof(sin);
        if (getpeername(fd, (struct sockaddr *)&sin, &slen) == 0
            && sin.sin_family == AF_INET) {
            ci->peer_addr = sin.sin_addr.s_addr;
            ci->peer_port = ntohs(sin.sin_port);
        }
        slen = sizeof(sin);
        if (getsockname(fd, (struct sockaddr *)&sin, &slen) == 0
            && sin.sin_family == AF_INET) {
            ci->local_addr = sin.sin_addr.s_addr;
            ci->local_port = ntohs(sin.sin_port);
        }
    }

    /*
     * For TLS connections where data arrives one byte at a time
     * (e.g., cpp-httplib's SSL_read(ssl, buf, 1)), we accumulate
     * into a reassembly buffer and process once we have enough.
     */
    if (ci->state == CONN_IDLE || ci->state == CONN_RECV_HEADERS) {
        /* Accumulate into reassembly buffer */
        size_t to_copy = (size_t)ret;
        if (ci->tls_buf_len + to_copy > TLS_REASM_BUF_SIZE) {
            /* Buffer overflow — reset and skip this request */
            OBI_DBG("SSL_read: fd=%d reassembly buffer overflow (%u + %zu > %d), resetting",
                    fd, ci->tls_buf_len, to_copy, TLS_REASM_BUF_SIZE);
            ci->tls_buf_len = 0;
            ci->state = CONN_IDLE;
            return ret;
        }
        memcpy(ci->tls_buf + ci->tls_buf_len, buf, to_copy);
        ci->tls_buf_len += (uint32_t)to_copy;

        tls_process_accumulated(ci);
    } else if (ci->state == CONN_RECV_BODY) {
        /* Body data: just count bytes */
        ci->body_received += (uint32_t)ret;
        if (ci->body_received >= ci->content_length) {
            ci->state = CONN_REQUEST_DONE;
            OBI_DBG("TLS body complete: %s %s (%u/%u bytes)",
                    ci->method, ci->path, ci->body_received, ci->content_length);
        }
    }
    /* CONN_REQUEST_DONE and CONN_NON_HTTP: ignore further reads */

    return ret;
}

static int hooked_SSL_write(void *ssl, const void *buf, int num) {
    if (resolved_SSL_get_fd) {
        int fd = resolved_SSL_get_fd(ssl);
        struct conn_info *ci = get_conn(fd);
        if (ci && ci->active && ci->is_tls && ci->state == CONN_REQUEST_DONE) {
            process_send_data(ci, (const char *)buf, (size_t)num);
        }
    }
    return orig_SSL_write(ssl, buf, num);
}

/* ------------------------------------------------------------------ */
/* Install / Remove                                                    */
/* ------------------------------------------------------------------ */

__attribute__((visibility("hidden")))
int obi_http_server_hooks_install(void) {
    void *orig;
    int rc = 0;

    /* Initialize connection table */
    memset(g_conns, 0, sizeof(g_conns));

    /* Hook accept4 */
    orig = NULL;
    if (obi_hook_install("accept4", (void *)hooked_accept4, &orig) == 0) {
        orig_accept4 = (int (*)(int, struct sockaddr *, socklen_t *, int))orig;
        OBI_DBG("hooked accept4 -> %p", (void *)orig_accept4);
    } else {
        OBI_DBG("FAILED to hook accept4 (not in GOT)");
        rc = -1;
    }

    /* Hook recv */
    orig = NULL;
    if (obi_hook_install("recv", (void *)hooked_recv, &orig) == 0) {
        orig_recv = (ssize_t (*)(int, void *, size_t, int))orig;
        OBI_DBG("hooked recv -> %p", (void *)orig_recv);
    } else {
        OBI_DBG("FAILED to hook recv");
        rc = -1;
    }

    /* Hook send */
    orig = NULL;
    if (obi_hook_install("send", (void *)hooked_send, &orig) == 0) {
        orig_send = (ssize_t (*)(int, const void *, size_t, int))orig;
        OBI_DBG("hooked send -> %p", (void *)orig_send);
    } else {
        OBI_DBG("FAILED to hook send");
        rc = -1;
    }

    /* Hook close */
    orig = NULL;
    if (obi_hook_install("close", (void *)hooked_close, &orig) == 0) {
        orig_close = (int (*)(int))orig;
        OBI_DBG("hooked close -> %p", (void *)orig_close);
    } else {
        OBI_DBG("FAILED to hook close");
        rc = -1;
    }

    return rc;
}

__attribute__((visibility("hidden")))
void obi_http_server_hooks_remove(void) {
    obi_hook_remove("accept4");
    obi_hook_remove("recv");
    obi_hook_remove("send");
    obi_hook_remove("close");
    orig_accept4 = NULL;
    orig_recv = NULL;
    orig_send = NULL;
    orig_close = NULL;
}

__attribute__((visibility("hidden")))
int obi_http_server_tls_hooks_install(void) {
    /* Resolve SSL_get_fd first — required for fd correlation */
    resolved_SSL_get_fd = (ssl_get_fd_fn)dlsym(RTLD_DEFAULT, "SSL_get_fd");
    if (!resolved_SSL_get_fd) {
        /* OpenSSL not loaded or SSL_get_fd not available */
        OBI_DBG("SSL_get_fd not found via dlsym — TLS hooks not installed");
        return -1;
    }
    OBI_DBG("resolved SSL_get_fd -> %p", (void *)resolved_SSL_get_fd);

    void *orig;
    int rc = 0;

    /* Hook SSL_read */
    orig = NULL;
    if (obi_hook_install("SSL_read", (void *)hooked_SSL_read, &orig) == 0) {
        orig_SSL_read = (ssl_read_fn)orig;
        OBI_DBG("hooked SSL_read -> %p", (void *)orig_SSL_read);
    } else {
        OBI_DBG("FAILED to hook SSL_read (not in GOT)");
        rc = -1;
    }

    /* Hook SSL_write */
    orig = NULL;
    if (obi_hook_install("SSL_write", (void *)hooked_SSL_write, &orig) == 0) {
        orig_SSL_write = (ssl_write_fn)orig;
        OBI_DBG("hooked SSL_write -> %p", (void *)orig_SSL_write);
    } else {
        OBI_DBG("FAILED to hook SSL_write (not in GOT)");
        rc = -1;
    }

    return rc;
}

__attribute__((visibility("hidden")))
void obi_http_server_tls_hooks_remove(void) {
    obi_hook_remove("SSL_read");
    obi_hook_remove("SSL_write");
    orig_SSL_read = NULL;
    orig_SSL_write = NULL;
    resolved_SSL_get_fd = NULL;
}
