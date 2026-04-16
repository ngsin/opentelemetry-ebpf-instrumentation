// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/trace_key.h>

// Maps a server trace key (pid/tid/ns/extra_id) to the sorted connection info
// of the corresponding server request.  Used by child-span lookup to check
// incoming_trace_map for late-arriving traceparent data from the C++ agent.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, trace_key_t);
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} server_trace_conn SEC(".maps");
