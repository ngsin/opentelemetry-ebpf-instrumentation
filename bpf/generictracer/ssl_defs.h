// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_args.h>
#include <common/trace_key.h>
#include <common/trace_lifecycle.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/protocol_http.h>

#include <generictracer/maps/pid_tid_to_conn.h>
#include <generictracer/maps/ssl_read_accum.h>
#include <generictracer/maps/ssl_to_pid_tid.h>

#include <maps/ssl_to_conn.h>

#include <logger/bpf_dbg.h>

static __always_inline void cleanup_ssl_trace_info(http_info_t *info, void *ssl) {
    if (info->type == EVENT_HTTP_REQUEST) {
        ssl_pid_connection_info_t *ssl_info = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (ssl_info) {
            bpf_dbg_printk(
                "Looking to delete server trace for ssl = %llx, info->type = %d", ssl, info->type);
            //dbg_print_http_connection_info(&ssl_info->conn.conn); // commented out since GitHub CI doesn't like this call
            trace_key_t t_key = {0};
            t_key.extra_id = info->extra_id;
            t_key.p_key.ns = info->pid.ns;
            t_key.p_key.tid = info->task_tid;
            t_key.p_key.pid = info->pid.user_pid;

            delete_server_trace(&ssl_info->p_conn, &t_key);
        }
    }
}

static __always_inline void
cleanup_ssl_server_trace(http_info_t *info, void *ssl, void *buf, u32 len) {
    if (info && http_will_complete(info, (unsigned char *)buf, len)) {
        cleanup_ssl_trace_info(info, ssl);
    }
}

static __always_inline void cleanup_complete_ssl_server_trace(http_info_t *info, void *ssl) {
    if (info && http_info_complete(info)) {
        cleanup_ssl_trace_info(info, ssl);
    }
}

static __always_inline void
finish_possible_delayed_tls_http_request(pid_connection_info_t *pid_conn, void *ssl) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info && info->submitted) {
        // we need to check for server request, the same thread
        // could be handling both client and server requests
        if (info->type == EVENT_HTTP_REQUEST) {
            cleanup_complete_ssl_server_trace(info, ssl);
        }
        finish_http(info, pid_conn);
    }
}

static __always_inline void cleanup_trace_info_for_delayed_trace(pid_connection_info_t *pid_conn,
                                                                 void *ssl,
                                                                 void *buf,
                                                                 u32 len) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_ssl_server_trace(info, ssl, buf, len);
}

static __always_inline void
handle_ssl_buf(void *ctx, u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
    if (args) {
        void *ssl = ((void *)args->ssl);
        const u64 ssl_ptr = (u64)ssl;
        bpf_dbg_printk("SSL_buf id=%d ssl=%llx", id, ssl);
        ssl_pid_connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (!conn) {
            conn = bpf_map_lookup_elem(&pid_tid_to_conn, &id);

            if (!conn) {
                // We try even harder, we might have an SSL pointer mapped on another
                // thread, since tcp_rcv_established was handled on another thread pool.
                // First we look up a pid_tid by the ssl pointer, which might've been established
                // by a prior SSL_read on another thread, then we look up in the same map.
                // Clean-up here we are done trying if we don't succeed
                u64 *pid_tid_ptr = bpf_map_lookup_elem(&ssl_to_pid_tid, &ssl_ptr);

                if (pid_tid_ptr) {
                    const u64 pid_tid = *pid_tid_ptr;

                    conn = bpf_map_lookup_elem(&pid_tid_to_conn, &pid_tid);
                    bpf_dbg_printk(
                        "Separate pool lookup ssl=%llx, pid=%d, conn=%llx", ssl_ptr, pid_tid, conn);
                } else {
                    bpf_dbg_printk("Other thread lookup failed for ssl=%llx", ssl_ptr);
                }
            }

            // If we found a connection setup by tcp_rcv_established, which means
            // we missed a SSL_do_handshake, update our ssl to connection map to be
            // used by the rest of the SSL lifecycle. We shouldn't rely on the SSL_write
            // being on the same thread as the SSL_read.
            if (conn) {
                bpf_map_delete_elem(&pid_tid_to_conn, &id);
                ssl_pid_connection_info_t c;
                bpf_probe_read(&c, sizeof(ssl_pid_connection_info_t), conn);
                bpf_map_update_elem(&ssl_to_conn, &ssl, &c, BPF_ANY);
            }
        }

        bpf_map_delete_elem(&ssl_to_pid_tid, &ssl_ptr);

        if (!conn) {
            // At this point the threading in the language doesn't allow us to properly match the SSL* with
            // the connection info. We send partial event, at least we can find the path, timing and response.
            // even though we won't have peer information.
            ssl_pid_connection_info_t p_c = {};
            bpf_dbg_printk("setting fake connection info ssl=%llx", ssl);
            __builtin_memcpy(&p_c.p_conn.conn.s_addr, &ssl, sizeof(void *));
            p_c.p_conn.conn.d_port = p_c.p_conn.conn.s_port = p_c.orig_dport = 0;
            p_c.p_conn.pid = pid_from_pid_tgid(id);

            bpf_map_update_elem(&ssl_to_conn, &ssl, &p_c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
        }

        if (conn) {
            bpf_dbg_printk("SSL conn");
            dbg_print_http_connection_info(&conn->p_conn.conn);

            // SSL_read buffer aggregation for byte-at-a-time readers (e.g. cpp-httplib).
            // When SSL_read returns fewer than MIN_HTTP_SIZE bytes we cannot detect the
            // HTTP protocol.  Accumulate small reads into a per-SSL BPF map until we
            // have enough data for protocol detection, then dispatch the aggregated
            // buffer directly (bypassing handle_buf_with_connection's bpf_probe_read
            // which would over-read a tiny user-space buffer).
            if (direction == TCP_RECV && bytes_len > 0 && bytes_len < MIN_HTTP_SIZE) {
                ssl_read_accum_t *accum = bpf_map_lookup_elem(&ssl_read_accum, &ssl_ptr);
                if (!accum) {
                    ssl_read_accum_t new_accum = {};
                    bpf_map_update_elem(&ssl_read_accum, &ssl_ptr, &new_accum, BPF_NOEXIST);
                    accum = bpf_map_lookup_elem(&ssl_read_accum, &ssl_ptr);
                    if (!accum) {
                        // Map full — fall through to normal path as best-effort
                        goto normal_ssl_path;
                    }
                }

                u16 pos = accum->pos;
                // Bounds check for verifier: pos must be within buffer.
                // pos == FULL_BUF_SIZE is also used as a sentinel after a
                // successful accumulation dispatch — it tells us "this
                // connection already dispatched an accumulated request, don't
                // re-accumulate until the response clears the entry".
                if (pos >= FULL_BUF_SIZE) {
                    // Already dispatched or buffer full — pass through to
                    // normal path.  Do NOT delete the entry; it serves as a
                    // sentinel so subsequent small reads on the same SSL
                    // connection are routed to handle_buf_with_connection
                    // (which will hit still_reading / still_responding in the
                    // HTTP handler) instead of being re-accumulated into a
                    // garbage second request.
                    goto normal_ssl_path;
                }

                // Copy exactly 1 byte from user-space into the accumulation buffer.
                // This is the fast path for byte-at-a-time readers (e.g. cpp-httplib).
                // bytes_len is guaranteed to be [1, MIN_HTTP_SIZE) by the enclosing
                // `if`, and typically equals 1.  We only accumulate the first byte of
                // each SSL_read to avoid verifier complexity; multi-byte small reads
                // (2-11 bytes) are rare and will simply accumulate more slowly.
                bpf_probe_read(&accum->buf[pos], 1, (void *)args->buf);
                pos++;
                accum->pos = pos;

                if (pos < MIN_HTTP_SIZE) {
                    // Not enough data yet — we need at least MIN_HTTP_SIZE
                    // (12) bytes for HTTP protocol detection (e.g. "GET / HTTP/").
                    // We dispatch early rather than waiting for FULL_BUF_SIZE
                    // because cpp-httplib reads the request line byte-at-a-time
                    // then switches to larger reads for headers.  If we waited
                    // for 256 bytes, the large header read would arrive first,
                    // clear the accumulation, and pass header data (without the
                    // "GET" prefix) to protocol detection — which would fail.
                    // After dispatching, subsequent reads (both small and large)
                    // go through normal_ssl_path → handle_buf_with_connection →
                    // still_reading, which captures the rest of the request.
                    return;
                }

                // We have enough data for HTTP protocol detection.
                // Subsequent 1-byte SSL_reads will hit the sentinel
                // (pos >= FULL_BUF_SIZE) and route through normal_ssl_path
                // → handle_buf_with_connection → still_reading, which
                // appends each byte to info->buf, capturing the full URL
                // and headers (including traceparent).
                bpf_dbg_printk("SSL accum dispatch: pos=%d", pos);

                call_protocol_args_t *pargs = make_protocol_args(
                    &conn->p_conn, (void *)args->buf, bytes_len, WITH_SSL, direction, conn->orig_dport);
                if (!pargs) {
                    bpf_map_delete_elem(&ssl_read_accum, &ssl_ptr);
                    return;
                }
                __builtin_memcpy(&pargs->pid_conn, &conn->p_conn, sizeof(pid_connection_info_t));
                // Clamp pos for verifier
                if (pos > FULL_BUF_SIZE) {
                    pos = FULL_BUF_SIZE;
                }
                bpf_probe_read_kernel(pargs->small_buf, FULL_BUF_SIZE, accum->buf);
                pargs->accumulated = 1;
                pargs->bytes_len = (int)pos;

                // Mark the accumulation entry as "dispatched" so subsequent
                // small reads on this SSL connection pass through to
                // normal_ssl_path (the sentinel check at the top will match).
                // The entry is cleared when:
                //  (a) a normal-size read arrives (the cleanup below), or
                //  (b) an SSL_write (response) triggers the TCP_SEND path.
                accum->pos = FULL_BUF_SIZE;
                bpf_tail_call(ctx, &jump_table, k_tail_handle_buf_with_args);
                // tail call doesn't return; if it fails, fall through
                return;
            }

            // Normal-size read or SSL_write: manage the accumulation entry.
            {
                ssl_read_accum_t *accum = bpf_map_lookup_elem(&ssl_read_accum, &ssl_ptr);
                if (accum) {
                    if (direction == TCP_SEND) {
                        // SSL_write (response): always delete the accumulation
                        // entry — both stale partial data and the sentinel.
                        // After the response, the next request must start a
                        // fresh accumulation cycle so its "GET / HTTP/1.1"
                        // prefix is captured for protocol detection.
                        // Without this, the sentinel routes the next request's
                        // byte-at-a-time SSL_reads through normal_ssl_path
                        // where they hit still_responding and keep refreshing
                        // end_monotime_ns — preventing the Go-level timeout
                        // from ever emitting the delayed server span.
                        bpf_map_delete_elem(&ssl_read_accum, &ssl_ptr);
                    } else if (accum->pos < FULL_BUF_SIZE) {
                        // TCP_RECV with large read: clear stale partial data
                        // that was never dispatched.
                        bpf_map_delete_elem(&ssl_read_accum, &ssl_ptr);
                    }
                    // TCP_RECV with sentinel (pos == FULL_BUF_SIZE): keep it
                    // so the current request's subsequent small reads route
                    // through normal_ssl_path → still_reading.
                }
            }

normal_ssl_path:
            // For SSL_write (response direction TCP_SEND), finish any
            // previous delayed HTTP request before processing the response.
            // This is critical for byte-at-a-time SSL_read connections
            // (e.g. cpp-httplib) where the kernel-level tcp_sendmsg skips
            // SSL connections (active_send_args is never populated), so
            // finish_possible_delayed_http_request is never called through
            // the normal kernel path.  Without this, the delayed request
            // stays in ongoing_http forever, and get_or_set_http_info
            // never runs because is_http fails on 1-byte buffers.
            if (direction == TCP_SEND) {
                http_info_t *prev = bpf_map_lookup_elem(&ongoing_http, &conn->p_conn);
                if (prev && prev->delayed && !prev->submitted) {
                    finish_http(prev, &conn->p_conn);
                }
            }
            // We should attempt to clean up the server trace immediately. The cleanup information
            // is keyed of the *ssl, so when it's delayed we might have different *ssl on the same
            // connection.
            cleanup_trace_info_for_delayed_trace(&conn->p_conn, ssl, (void *)args->buf, bytes_len);
            // must be last, doesn't return
            handle_buf_with_connection(ctx,
                                       &conn->p_conn,
                                       (void *)args->buf,
                                       bytes_len,
                                       WITH_SSL,
                                       direction,
                                       conn->orig_dport);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}
