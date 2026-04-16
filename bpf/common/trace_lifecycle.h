// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/runtime.h>
#include <common/trace_key.h>
#include <common/tracing.h>

#include <maps/cp_support_connect_info.h>
#include <maps/incoming_trace_map.h>
#include <maps/outgoing_trace_map.h>
#include <maps/server_trace_conn.h>
#include <maps/server_traces.h>

#include <pid/pid_helpers.h>
#include <shared/obi_ctx.h>

static __always_inline void delete_server_trace(pid_connection_info_t *pid_conn,
                                                trace_key_t *t_key) {
    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_SERVER);
    int res = bpf_map_delete_elem(&server_traces, t_key);
    bpf_map_delete_elem(&server_trace_conn, t_key);
    bpf_dbg_printk("Deleting server span for id=%llx, pid=%d, ns=%x",
                   bpf_get_current_pid_tgid(),
                   t_key->p_key.pid,
                   t_key->p_key.ns);
    bpf_dbg_printk("Deleting server span for res=%d", res);

    // Delete traces_ctx_v1 at both eBPF-native key and Agent's per-thread
    // key to prevent stale entries from polluting subsequent requests.
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    obi_ctx__del(pid_tgid);

    const u32 tgid = (u32)(pid_tgid >> 32);
    const u32 ns_tid = get_task_tid();
    const u64 agent_key = ((u64)tgid << 32) | (u64)ns_tid;
    if (agent_key != pid_tgid) {
        obi_ctx__del(agent_key);
    }
}

static __always_inline void delete_client_trace_info(pid_connection_info_t *pid_conn) {
    bpf_dbg_printk("Deleting client trace map for connection, pid=%d", pid_conn->pid);
    dbg_print_http_connection_info(&pid_conn->conn);

    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_CLIENT);

    egress_key_t e_key = {
        .d_port = pid_conn->conn.d_port,
        .s_port = pid_conn->conn.s_port,
    };
    bpf_map_delete_elem(&outgoing_trace_map, &e_key);
    bpf_map_delete_elem(&cp_support_connect_info, pid_conn);
}

static __always_inline u8 find_trace_for_server_request(connection_info_t *conn,
                                                        tp_info_t *tp,
                                                        const u8 type) {
    u8 found_tp = 0;
    tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, conn);
    if (existing_tp) {
        found_tp = 1;
        bpf_dbg_printk("Found incoming (TCP/IP) tp for server request");
        __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
        bpf_map_delete_elem(&incoming_trace_map, conn);
    } else {
        bpf_dbg_printk("Looking up tracemap for");
        dbg_print_http_connection_info(conn);

        existing_tp = trace_info_for_connection(conn, TRACE_TYPE_CLIENT);

        bpf_dbg_printk("existing_tp=%llx", existing_tp);

        if (!disable_black_box_cp && correlated_requests(tp, existing_tp)) {
            if (existing_tp->valid) {
                bpf_dbg_printk("Found existing correlated tp for server request");
                // Mark the client info as invalid (used), in case the client
                // request information is not cleaned up.
                if ((type == EVENT_HTTP_REQUEST && existing_tp->req_type == EVENT_HTTP_CLIENT) ||
                    (type == EVENT_TCP_REQUEST && existing_tp->req_type == EVENT_TCP_REQUEST)) {
                    found_tp = 1;
                    __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
                    __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
                    // We ensure that server requests match the client type, otherwise SSL
                    // can often be confused with TCP.
                    existing_tp->valid = 0;
                    set_trace_info_for_connection(conn, TRACE_TYPE_CLIENT, existing_tp);
                    bpf_dbg_printk("setting the client info as used");
                } else {
                    bpf_dbg_printk("incompatible trace info, not using the correlated tp, type=%d, "
                                   "other type=%d",
                                   type,
                                   existing_tp->req_type);
                }
            } else {
                bpf_dbg_printk("the existing client tp was already used, ignoring");
            }
        }
    }

    return found_tp;
}

static __always_inline void server_or_client_trace(
    const u8 type, connection_info_t *conn, tp_info_pid_t *tp_p, u8 ssl, const u16 orig_dport) {

    const u64 id = bpf_get_current_pid_tgid();
    const u32 host_pid = pid_from_pid_tgid(id);

    if (type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        t_key.extra_id = extra_runtime_id();

        connection_info_part_t conn_part = {};
        populate_ephemeral_info(&conn_part, conn, orig_dport, host_pid, FD_SERVER);

        bpf_dbg_printk("Saving connection server span for pid=%d, tid=%d, ephemeral_port=%d",
                       t_key.p_key.pid,
                       t_key.p_key.tid,
                       conn_part.port);

        bpf_map_update_elem(&server_traces_aux, &conn_part, tp_p, BPF_ANY);

        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
        if (existing && (existing->req_type == tp_p->req_type) &&
            (tp_p->req_type == EVENT_HTTP_REQUEST)) {
            existing->valid = 0;
            bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
            return;
        }

        bpf_dbg_printk(
            "Saving thread server span for ns=%x, extra_id=%llx", t_key.p_key.ns, t_key.extra_id);
        bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);
        obi_ctx__set(id, &tp_p->tp);

        // For SSL server spans, store the sorted connection so that
        // find_trace_for_client_request_with_t_key can check incoming_trace_map
        // for late-arriving traceparent data when creating child spans.
        if (ssl) {
            connection_info_t sorted_conn;
            __builtin_memcpy(&sorted_conn, conn, sizeof(connection_info_t));
            sort_connection_info(&sorted_conn);
            bpf_map_update_elem(&server_trace_conn, &t_key, &sorted_conn, BPF_ANY);
        }
    } else {
        // Setup a pid, so that we can find it in TC.
        // We need the PID id to be able to query ongoing_http and update
        // the span id with the SEQ/ACK pair.
        tp_p->pid = host_pid;
        const egress_key_t e_key = {
            .d_port = conn->d_port,
            .s_port = conn->s_port,
        };

        if (ssl) {
            // Clone and mark it invalid for the purpose of storing it in the
            // outgoing_trace_map, if it's an SSL connection
            tp_info_pid_t tp_p_invalid = {0};
            __builtin_memcpy(&tp_p_invalid, tp_p, sizeof(tp_p_invalid));
            tp_p_invalid.valid = 0;
            bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p_invalid, BPF_ANY);
            // NOTE: Do NOT call obi_ctx__set() here for SSL client spans.
            // The eBPF SSL client span is created DURING curl_easy_perform()
            // (on TCP connect), but curl_hooks.c reads traces_ctx_v1 BEFORE
            // that.  Writing the client traceID here would pollute
            // traces_ctx_v1 with a stale traceID that the next request's
            // curl hook would read, causing all requests on a keep-alive
            // connection to share the same traceID.
        } else {
            bpf_map_update_elem(&outgoing_trace_map, &e_key, tp_p, BPF_ANY);
            obi_ctx__set(id, &tp_p->tp);
        }
    }
}
