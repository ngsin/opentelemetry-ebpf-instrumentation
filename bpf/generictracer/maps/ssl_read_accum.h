// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/map_sizing.h>

// ssl_read_accum_t accumulates small SSL_read returns (e.g. 1-byte-at-a-time
// reads from cpp-httplib) until we have enough bytes for HTTP request parsing.
// Once pos >= FULL_BUF_SIZE the accumulated buffer is dispatched
// to the protocol handler in place of the (too-small) user-space buffer.
typedef struct ssl_read_accum {
    u8  buf[FULL_BUF_SIZE]; // accumulation buffer (matches http_info_t.buf size)
    u16 pos;                // next write offset (0..FULL_BUF_SIZE)
    u8  _pad[2];
} ssl_read_accum_t;

// Keyed by SSL pointer (u64).  LRU ensures automatic eviction when
// connections close or entries grow stale.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);                   // SSL *
    __type(value, ssl_read_accum_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ssl_read_accum SEC(".maps");
