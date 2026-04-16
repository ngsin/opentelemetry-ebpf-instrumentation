// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/runtime.h>
#include <common/trace_helpers.h>

#include <pid/pid_helpers.h>

#include <maps/clone_map.h>
#include <maps/cp_support_connect_info.h>
#include <maps/fd_map.h>
#include <maps/fd_to_connection.h>
#include <maps/incoming_trace_map.h>
#include <maps/java_tasks.h>
#include <maps/nginx_upstream.h>
#include <maps/nodejs_fd_map.h>
#include <maps/puma_tasks.h>
#include <maps/server_trace_conn.h>
#include <maps/server_traces.h>

#include <shared/obi_ctx.h>

static __always_inline void trace_key_from_pid_tid(trace_key_t *t_key) {
    task_tid(&t_key->p_key);

    t_key->extra_id = extra_runtime_id();
}

static __always_inline void
trace_key_from_pid_tid_with_p_key(trace_key_t *t_key, const pid_key_t *p_key, u64 id) {
    t_key->p_key = *p_key;

    const u64 extra_id = extra_runtime_id_with_task_id(id);
    t_key->extra_id = extra_id;
}

static __always_inline tp_info_pid_t *find_nginx_parent_trace(const pid_connection_info_t *p_conn,
                                                              u16 orig_dport) {
    connection_info_part_t client_part = {};
    populate_ephemeral_info(&client_part, &p_conn->conn, orig_dport, p_conn->pid, FD_CLIENT);
    fd_info_t *fd_info = fd_info_for_conn(&client_part);

    bpf_dbg_printk("fd_info lookup=%llx, type=%d", fd_info, client_part.type);
    if (fd_info) {
        connection_info_part_t *parent = bpf_map_lookup_elem(&nginx_upstream, fd_info);
        bpf_dbg_printk("parent=%llx, fd=%d, type=%d", parent, fd_info->fd, fd_info->type);
        if (parent) {
            return bpf_map_lookup_elem(&server_traces_aux, parent);
        }
    }

    return NULL;
}

static __always_inline tp_info_pid_t *find_puma_parent_trace(u64 id) {
    puma_task_id_t *task_id = bpf_map_lookup_elem(&puma_worker_tasks, &id);
    bpf_dbg_printk("puma lookup: task_id=%llx", task_id);
    if (!task_id) {
        return NULL;
    }

    bpf_dbg_printk("found item:%llx", task_id->item);

    connection_info_part_t *conn_part = bpf_map_lookup_elem(&puma_task_connections, task_id);
    bpf_dbg_printk("puma parent lookup: conn=%llx", conn_part);
    if (conn_part) {
        return bpf_map_lookup_elem(&server_traces_aux, conn_part);
    }

    return NULL;
}

static __always_inline tp_info_pid_t *
find_nodejs_parent_trace(const pid_connection_info_t *p_conn, u16 orig_dport, u64 pid_tgid) {
    connection_info_part_t client_part = {};
    populate_ephemeral_info(&client_part, &p_conn->conn, orig_dport, p_conn->pid, FD_CLIENT);
    fd_info_t *fd_info = fd_info_for_conn(&client_part);

    if (!fd_info) {
        return NULL;
    }

    const u64 client_key = (pid_tgid << 32) | fd_info->fd;

    const s32 *node_parent_request_fd = bpf_map_lookup_elem(&nodejs_fd_map, &client_key);

    if (!node_parent_request_fd) {
        return NULL;
    }

    bpf_dbg_printk("client_fd=%d, server_fd=%d", fd_info->fd, *node_parent_request_fd);

    const fd_key key = {.pid_tgid = pid_tgid, .fd = *node_parent_request_fd};

    const connection_info_t *conn = bpf_map_lookup_elem(&fd_to_connection, &key);

    if (!conn) {
        return NULL;
    }

    return trace_info_for_connection(conn, TRACE_TYPE_SERVER);
}

static __always_inline tp_info_pid_t *find_parent_process_trace(trace_key_t *t_key) {
    // Up to 5 levels of thread nesting allowed
    enum { k_max_depth = 5 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (server_tp && server_tp->valid) {
            bpf_dbg_printk("Found parent trace for pid=%d, ns=%lx, extra_id=%llx",
                           t_key->p_key.pid,
                           t_key->p_key.ns,
                           t_key->extra_id);
            return server_tp;
        }

        // not this goroutine running the server request processing
        // Let's find the parent scope
        const pid_key_t *p_tid = (const pid_key_t *)bpf_map_lookup_elem(&clone_map, &t_key->p_key);

        if (!p_tid) {
            break;
        }

        // Lookup now to see if the parent was a request
        t_key->p_key = *p_tid;
    }

    return NULL;
}

static __always_inline tp_info_pid_t *find_parent_java_trace(trace_key_t *t_key) {
    // Up to 3 levels of thread nesting allowed
    enum { k_max_depth = 3 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (server_tp && server_tp->valid) {
            bpf_dbg_printk("Found parent trace for pid=%d, ns=%lx, extra_id=%llx",
                           t_key->p_key.pid,
                           t_key->p_key.ns,
                           t_key->extra_id);
            return server_tp;
        }

        // not this java thread running the server request processing
        // Let's find the parent scope
        const pid_key_t *p_tid = (const pid_key_t *)bpf_map_lookup_elem(&java_tasks, &t_key->p_key);

        if (!p_tid) {
            break;
        }

        // Lookup now to see if the parent was a request
        t_key->p_key = *p_tid;
    }

    return NULL;
}

static __always_inline tp_info_pid_t *find_parent_trace(const pid_connection_info_t *p_conn,
                                                        u64 pid_tgid,
                                                        trace_key_t *t_key,
                                                        u16 orig_dport) {
    tp_info_pid_t *node_tp = find_nodejs_parent_trace(p_conn, orig_dport, pid_tgid);

    if (node_tp) {
        return node_tp;
    }

    bpf_dbg_printk("Looking up parent trace for pid=%d, ns=%lx, extra_id=%llx",
                   t_key->p_key.pid,
                   t_key->p_key.ns,
                   t_key->extra_id);

    tp_info_pid_t *nginx_parent = find_nginx_parent_trace(p_conn, orig_dport);

    if (nginx_parent) {
        return nginx_parent;
    }

    tp_info_pid_t *puma_parent = find_puma_parent_trace(pid_tgid);
    if (puma_parent) {
        return puma_parent;
    }

    tp_info_pid_t *java_parent = find_parent_java_trace(t_key);
    if (java_parent) {
        return java_parent;
    }

    tp_info_pid_t *proc_parent = find_parent_process_trace(t_key);

    if (proc_parent) {
        return proc_parent;
    }

    const cp_support_data_t *conn_t_key = bpf_map_lookup_elem(&cp_support_connect_info, p_conn);

    if (conn_t_key) {
        bpf_dbg_printk("Found parent trace for connection through connection lookup");
        return bpf_map_lookup_elem(&server_traces, &conn_t_key->t_key);
    }

    return 0;
}

static __always_inline u8
find_trace_for_client_request_with_t_key(const pid_connection_info_t *p_conn,
                                         u16 orig_dport,
                                         trace_key_t *t_key,
                                         u64 pid_tgid,
                                         tp_info_t *tp) {
    tp_info_pid_t *server_tp = find_parent_trace(p_conn, pid_tgid, t_key, orig_dport);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");

        if (!should_be_in_same_transaction(&server_tp->tp, tp)) {
            bpf_dbg_printk("Parent and child are too far apart, marking server trace as invalid");
            bpf_dbg_printk(
                "%lld >>> %lld (max: %lld)", tp->ts, server_tp->tp.ts, max_transaction_time);
            server_tp->valid = 0;
            return 0;
        }

        // Early late-binding for SSL server spans:
        // If the C++ agent wrote the traceparent into incoming_trace_map
        // AFTER find_trace_for_server_request() ran (i.e. server_tp still
        // has a random traceID), check incoming_trace_map now and correct
        // server_tp before the child span inherits the random traceID.
        //
        // We use server_trace_conn (keyed by trace_key_t) to find the
        // sorted server connection, then look up incoming_trace_map.
        // This avoids the racey traces_ctx_v1[agent_key] approach:
        // the eBPF uretprobe fires before the Agent's GOT hook, so
        // traces_ctx_v1 may contain stale data from a previous request.
        {
            connection_info_t *srv_conn =
                bpf_map_lookup_elem(&server_trace_conn, t_key);
            if (srv_conn) {
                tp_info_pid_t *late_tp =
                    bpf_map_lookup_elem(&incoming_trace_map, srv_conn);
                if (late_tp && valid_trace(late_tp->tp.trace_id) &&
                    __builtin_memcmp(late_tp->tp.trace_id,
                                     server_tp->tp.trace_id,
                                     TRACE_ID_SIZE_BYTES) != 0) {
                    bpf_dbg_printk(
                        "Early late-binding: updating server_tp traceID "
                        "from incoming_trace_map");
                    __builtin_memcpy(server_tp->tp.trace_id,
                                     late_tp->tp.trace_id,
                                     sizeof(server_tp->tp.trace_id));
                    __builtin_memcpy(server_tp->tp.parent_id,
                                     late_tp->tp.span_id,
                                     sizeof(server_tp->tp.parent_id));
                    // Do NOT delete incoming_trace_map here — finish_http()
                    // also needs it to correct the server span's traceID
                    // and send it to the collector.
                }
            }
        }

        __builtin_memcpy(tp->trace_id, server_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, server_tp->tp.span_id, sizeof(tp->parent_id));

        // Fallback: if early late-binding above did not fire (e.g. connection
        // key mismatch between agent and eBPF), check traces_ctx_v1 directly.
        // The C++ agent writes the correct traceID (parsed from the HTTPS
        // traceparent header) into traces_ctx_v1 via update_traces_ctx_v1()
        // during its SSL_read GOT hook — this happens BEFORE the business
        // code makes outgoing HTTP requests.
        //
        // Key priority: try the agent key FIRST.  The agent key
        // (host_pid << 32 | ns_tid) has the correct traceID from the
        // parsed traceparent header.  The eBPF native key (pid_tgid)
        // contains the random traceID from server_or_client_trace() —
        // which is the same value already in tp->trace_id and server_tp,
        // so checking it would always find a "match" and never correct.
        {
            const u32 tgid = (u32)(pid_tgid >> 32);
            const u32 ns_tid = get_task_tid();
            const u64 agent_key = ((u64)tgid << 32) | (u64)ns_tid;

            obi_ctx_info_t *obi_ctx = NULL;

            // In containers (PID namespace), agent_key != pid_tgid.
            // The agent writes correct traceID under agent_key.
            if (agent_key != pid_tgid) {
                obi_ctx = obi_ctx__get(agent_key);
            }

            // Fallback to eBPF native key (non-containerized processes,
            // or when finish_http late-binding has already corrected the
            // eBPF-side entry via obi_ctx__set with pid_tgid key).
            if (!obi_ctx || !valid_trace(obi_ctx->trace_id)) {
                obi_ctx = obi_ctx__get(pid_tgid);
            }

            if (obi_ctx && valid_trace(obi_ctx->trace_id) &&
                __builtin_memcmp(obi_ctx->trace_id, tp->trace_id,
                                 TRACE_ID_SIZE_BYTES) != 0) {
                bpf_dbg_printk("obi_ctx fallback: correcting client span "
                               "traceID from traces_ctx_v1");
                __builtin_memcpy(tp->trace_id, obi_ctx->trace_id,
                                 TRACE_ID_SIZE_BYTES);
            }
        }

        return 1;
    }

    return 0;
}

static __always_inline u8 find_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                        u16 orig_dport,
                                                        tp_info_t *tp) {

    trace_key_t t_key = {0};
    trace_key_from_pid_tid(&t_key);
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    return find_trace_for_client_request_with_t_key(p_conn, orig_dport, &t_key, pid_tgid, tp);
}

static __always_inline u8
find_parent_trace_for_client_request_with_t_key(const pid_connection_info_t *p_conn,
                                                u16 orig_dport,
                                                trace_key_t *t_key,
                                                u64 pid_tgid,
                                                tp_info_t *tp) {
    tp_info_pid_t *server_tp = find_parent_trace(p_conn, pid_tgid, t_key, orig_dport);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");

        if (!should_be_in_same_transaction(&server_tp->tp, tp)) {
            bpf_dbg_printk("Parent and child are too far apart, marking server trace as invalid");
            bpf_dbg_printk(
                "%lld >>> %lld (max: %lld)", tp->ts, server_tp->tp.ts, max_transaction_time);
            server_tp->valid = 0;
            return 0;
        }

        *tp = server_tp->tp;

        // obi_ctx fallback: same as find_trace_for_client_request_with_t_key.
        // tpinjector calls this function via find_parent_trace_for_client_request
        // and writes the result to outgoing_trace_map.  When
        // http_get_or_create_trace_info sees the outgoing_trace_map entry,
        // it uses it directly — bypassing find_trace_for_client_request.
        // So we must also correct the traceID here.
        {
            const u32 tgid = (u32)(pid_tgid >> 32);
            const u32 ns_tid = get_task_tid();
            const u64 agent_key = ((u64)tgid << 32) | (u64)ns_tid;

            obi_ctx_info_t *obi_ctx = NULL;
            if (agent_key != pid_tgid) {
                obi_ctx = obi_ctx__get(agent_key);
            }
            if (!obi_ctx || !valid_trace(obi_ctx->trace_id)) {
                obi_ctx = obi_ctx__get(pid_tgid);
            }
            if (obi_ctx && valid_trace(obi_ctx->trace_id) &&
                __builtin_memcmp(obi_ctx->trace_id, tp->trace_id,
                                 TRACE_ID_SIZE_BYTES) != 0) {
                bpf_dbg_printk("obi_ctx fallback (parent): correcting "
                               "traceID from traces_ctx_v1");
                __builtin_memcpy(tp->trace_id, obi_ctx->trace_id,
                                 TRACE_ID_SIZE_BYTES);
            }
        }

        return 1;
    }

    return 0;
}

static __always_inline u8 find_parent_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                               u16 orig_dport,
                                                               tp_info_t *tp) {

    trace_key_t t_key = {0};
    trace_key_from_pid_tid(&t_key);
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    return find_parent_trace_for_client_request_with_t_key(
        p_conn, orig_dport, &t_key, pid_tgid, tp);
}
