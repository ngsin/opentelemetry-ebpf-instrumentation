/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - traces_ctx_v1 key builder
 *
 * Provides make_host_pid_tgid() to build a per-thread BPF map key
 * using (host_pid << 32) | ns_tid.  The host_pid comes from config
 * (unique per process system-wide), and ns_tid comes from gettid()
 * (unique per thread within the PID namespace).
 *
 * On the eBPF side, the same key is reconstructed as:
 *   (tgid << 32) | get_task_tid()
 * where tgid = host PID and get_task_tid() = namespace TID.
 */

#ifndef OBI_HOST_TID_H
#define OBI_HOST_TID_H

#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * make_host_pid_tgid - Build the traces_ctx_v1 BPF map key for the
 * current thread: (host_pid << 32) | ns_tid.
 *
 * This creates a per-thread key that avoids concurrent overwrites in
 * multi-threaded servers.  The eBPF side reconstructs the same key
 * using (tgid << 32) | get_task_tid().
 *
 * Falls back to (host_pid << 32) | host_pid if gettid() fails.
 */
static inline uint64_t make_host_pid_tgid(uint32_t host_pid) {
    long ns_tid = syscall(SYS_gettid);
    if (ns_tid <= 0)
        return ((uint64_t)host_pid << 32) | (uint64_t)host_pid;
    return ((uint64_t)host_pid << 32) | (uint64_t)(uint32_t)ns_tid;
}

#endif /* OBI_HOST_TID_H */
