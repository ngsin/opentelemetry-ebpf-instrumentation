/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - libcurl hooks
 *
 * Intercepts curl_easy_perform() via GOT hooking.
 *
 * For HTTPS requests only, injects a Traceparent HTTP header with the
 * traceID read from the eBPF pinned map traces_ctx_v1 (when available),
 * or a freshly generated traceID for pure client processes.  This ensures
 * L4 (TCP option) and L7 (HTTP header) traceIDs are consistent, and
 * enables interop with non-OBI downstream services that only read HTTP
 * headers.
 *
 * For plain HTTP requests, no injection is performed — tpinjector already
 * handles both L4 (TCP option) and L7 (HTTP header) injection.
 *
 * No spans are created — kprobe/uprobe generic tracers produce complete
 * HTTP client spans with full metadata.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#include "got_hook.h"
#include "config.h"
#include "host_tid.h"

/*
 * libcurl type definitions (minimal, to avoid requiring curl headers).
 * These must match the libcurl ABI.
 */
typedef void CURL;
typedef int CURLcode;
typedef int CURLINFO;
typedef int CURLoption;

#define CURLE_OK                0
#define CURLINFO_EFFECTIVE_URL  0x100001  /* CURLINFO_STRING + 1 */
#define CURLOPT_HTTPHEADER      10023     /* CURLOPTTYPE_SLISTPOINT + 23 */

/* curl_slist — linked list used by CURLOPT_HTTPHEADER */
struct curl_slist {
    char *data;
    struct curl_slist *next;
};

/* Function pointer types */
typedef CURLcode (*curl_easy_perform_fn)(CURL *handle);
typedef CURLcode (*curl_easy_getinfo_fn)(CURL *handle, CURLINFO info, ...);
typedef CURLcode (*curl_easy_setopt_fn)(CURL *handle, CURLoption option, ...);
typedef struct curl_slist *(*curl_slist_append_fn)(struct curl_slist *list, const char *string);
typedef void (*curl_slist_free_all_fn)(struct curl_slist *list);

/* Original function pointer */
static curl_easy_perform_fn orig_curl_easy_perform = NULL;

/* Original curl_easy_setopt obtained via GOT hook (not dlsym).
 * Used to bypass our hook when setting headers during perform. */
static curl_easy_setopt_fn orig_curl_easy_setopt = NULL;

/* Thread-local: user's CURLOPT_HTTPHEADER slist pointer, captured by
 * hooked_curl_easy_setopt.  Safe because curl_easy_perform() blocks —
 * only one perform per thread at a time. */
static __thread struct curl_slist *tls_user_headers = NULL;

/* Dynamically resolved curl helpers (lazy init) */
static curl_easy_getinfo_fn resolved_curl_easy_getinfo = NULL;
static curl_slist_append_fn resolved_curl_slist_append = NULL;
static curl_slist_free_all_fn resolved_curl_slist_free_all = NULL;

/* obi_ctx_info_t — mirrors the BPF-side struct in obi_ctx.h */
struct obi_ctx_info {
    uint8_t trace_id[16];
    uint8_t span_id[8];
};

/* From agent.c */
extern int g_traces_ctx_fd;
extern struct obi_config g_obi_config;

/* Debug logging macro */
#define CURL_DBG(fmt, ...) \
    do { \
        if (obi_config_has_flag(&g_obi_config, OBI_CFG_DEBUG)) { \
            fprintf(stderr, "[obi-curl-hooks] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/*
 * resolve_curl_helpers - Lazily resolve libcurl helper functions via dlsym.
 */
static void resolve_curl_helpers(void) {
    if (!resolved_curl_easy_getinfo)
        resolved_curl_easy_getinfo = (curl_easy_getinfo_fn)dlsym(RTLD_DEFAULT, "curl_easy_getinfo");
    if (!resolved_curl_slist_append)
        resolved_curl_slist_append = (curl_slist_append_fn)dlsym(RTLD_DEFAULT, "curl_slist_append");
    if (!resolved_curl_slist_free_all)
        resolved_curl_slist_free_all = (curl_slist_free_all_fn)dlsym(RTLD_DEFAULT, "curl_slist_free_all");
}

/*
 * hooked_curl_easy_setopt - Replacement for curl_easy_setopt.
 *
 * Intercepts CURLOPT_HTTPHEADER to save the user's slist pointer in
 * thread-local storage.  All other options are forwarded transparently.
 *
 * Variadic forwarding: on x86_64 LP64, long/pointer/curl_off_t are all
 * 8 bytes, so extracting via va_arg(ap, void*) is safe for every
 * CURLoption type.
 */
static CURLcode hooked_curl_easy_setopt(CURL *handle, CURLoption option, ...) {
    va_list ap;
    va_start(ap, option);

    if (option == CURLOPT_HTTPHEADER) {
        struct curl_slist *headers = va_arg(ap, struct curl_slist *);
        tls_user_headers = headers;
        va_end(ap);
        if (orig_curl_easy_setopt)
            return orig_curl_easy_setopt(handle, option, headers);
        return -1;
    }

    /* All other options: extract as void* and forward. */
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (orig_curl_easy_setopt)
        return orig_curl_easy_setopt(handle, option, arg);
    return -1;
}

/*
 * bytes_to_hex - Convert binary bytes to lowercase hex string.
 * dst must have room for len*2+1 bytes.
 */
static void bytes_to_hex(const uint8_t *src, size_t len, char *dst) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = hex[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex[src[i] & 0xF];
    }
    dst[len * 2] = '\0';
}

/*
 * generate_random_bytes - Read random bytes from /dev/urandom.
 * Returns 0 on success, -1 on failure.
 */
static int generate_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/*
 * lookup_traces_ctx - Look up the current thread's trace context from the
 * pinned traces_ctx_v1 BPF map.
 *
 * The key is pid_tgid = (host_pid << 32) | ns_tid, built via
 * make_host_pid_tgid().  This matches what the eBPF side stores
 * using (tgid << 32) | get_task_tid(), and what
 * hooked_curl_easy_perform() / write_incoming_trace_map() use
 * when writing to the same map.
 *
 * Returns 0 on success (ctx populated), -1 on failure.
 */
static int lookup_traces_ctx(struct obi_ctx_info *ctx) {
    if (g_traces_ctx_fd < 0 || g_obi_config.host_pid == 0)
        return -1;

    /* Build pid_tgid key: upper 32 bits = TGID (host PID),
     * lower 32 bits = TID (namespace thread ID via gettid()).
     * This must match the key format used by:
     *   - the write path in hooked_curl_easy_perform() (make_host_pid_tgid)
     *   - the eBPF side (bpf_get_current_pid_tgid())
     *   - http_server_hooks.c write_incoming_trace_map (make_host_pid_tgid)
     * Using per-thread key ensures correct lookup on worker threads
     * where gettid() != pid. */
    uint64_t pid_tgid = make_host_pid_tgid(g_obi_config.host_pid);

    /* Use the raw bpf() syscall — no libbpf dependency needed. */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)g_traces_ctx_fd;
    attr.key = (uint64_t)(unsigned long)&pid_tgid;
    attr.value = (uint64_t)(unsigned long)ctx;

    return (int)syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/*
 * hooked_curl_easy_perform - Replacement for curl_easy_perform.
 *
 * For HTTPS URLs: reads trace context from traces_ctx_v1 BPF map and
 * injects a Traceparent HTTP header before calling the real function.
 * If no BPF context exists (pure client process), generates a fresh
 * traceID to ensure downstream services can still correlate the request.
 * The traceID matches the eBPF TCP option, ensuring L4/L7 consistency.
 *
 * For HTTP URLs: pure pass-through (tpinjector handles both L4 + L7).
 *
 * No spans are created — kprobe/uprobe produces complete spans.
 */
static CURLcode hooked_curl_easy_perform(CURL *handle) {
    if (!orig_curl_easy_perform) {
        return -1; /* Should not happen */
    }

    resolve_curl_helpers();

    /* Check if this is an HTTPS request */
    int is_https = 0;
    if (resolved_curl_easy_getinfo) {
        char *url = NULL;
        CURLcode rc = resolved_curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &url);
        if (rc == CURLE_OK && url && strncmp(url, "https://", 8) == 0) {
            is_https = 1;
        }
    }

    if (!is_https) {
        /* HTTP: tpinjector handles L4 + L7 injection, no action needed */
        return orig_curl_easy_perform(handle);
    }

    /* Safety guard: without the setopt hook we cannot safely preserve the
     * user's custom headers — skip injection to avoid breaking the app. */
    if (!orig_curl_easy_setopt || !resolved_curl_slist_append) {
        CURL_DBG("skip injection: setopt hook or slist_append not available");
        return orig_curl_easy_perform(handle);
    }

    /* HTTPS: Look up eBPF trace context and inject Traceparent header */
    struct curl_slist *injected_headers = NULL;
    struct obi_ctx_info ctx;
    int has_ctx = (lookup_traces_ctx(&ctx) == 0);
    CURL_DBG("HTTPS request: has_ctx=%d, host_pid=%u", has_ctx, g_obi_config.host_pid);

    /* Determine trace_id and span_id for the Traceparent header.
     *
     * When the BPF map has a context (has_ctx), we reuse the trace_id from
     * the eBPF-generated server span on this thread.  This ensures the
     * Traceparent header's traceID matches the eBPF TCP option traceID
     * (L4/L7 consistency).
     *
     * The span_id (parent-id in traceparent) is ALWAYS freshly generated
     * because the eBPF client span is created DURING curl_easy_perform
     * (on TCP connect/send), which hasn't happened yet at this point.
     * Using a random parent-id means the downstream server span will have
     * a parent-id that doesn't match any reported client span — but the
     * traceID is correct, so the entire request chain appears in one trace.
     *
     * When no BPF context exists (pure client process), we generate fresh
     * random IDs so downstream services can still correlate via the header. */
    uint8_t trace_id_bytes[16];
    uint8_t span_id_bytes[8];

    if (has_ctx) {
        memcpy(trace_id_bytes, ctx.trace_id, 16);
    } else {
        /* Pure client — no server request context on this thread. */
        if (generate_random_bytes(trace_id_bytes, 16) != 0) {
            goto do_perform;
        }
    }
    /* Always generate a fresh span_id for the traceparent parent-id. */
    if (generate_random_bytes(span_id_bytes, 8) != 0) {
        goto do_perform;
    }

    /* Write {trace_id, span_id} into traces_ctx_v1 so eBPF reuses this
     * span_id when creating the SSL client span (instead of urand_bytes).
     * Key: (host_pid << 32) | host_tid — matches what
     * bpf_get_current_pid_tgid() returns on the eBPF side.
     * Using per-thread key ensures correctness when curl_easy_perform is
     * called from a worker thread (host_tid != host_pid). */
    if (g_traces_ctx_fd >= 0 && g_obi_config.host_pid != 0) {
        uint64_t host_pid_tgid = make_host_pid_tgid(g_obi_config.host_pid);
        struct obi_ctx_info ctx_val;
        memcpy(ctx_val.trace_id, trace_id_bytes, 16);
        memcpy(ctx_val.span_id, span_id_bytes, 8);

        union bpf_attr wattr;
        memset(&wattr, 0, sizeof(wattr));
        wattr.map_fd = (uint32_t)g_traces_ctx_fd;
        wattr.key    = (uint64_t)(unsigned long)&host_pid_tgid;
        wattr.value  = (uint64_t)(unsigned long)&ctx_val;
        wattr.flags  = 0; /* BPF_ANY */
        syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &wattr, sizeof(wattr));

        {
            char dbg_span[17];
            bytes_to_hex(span_id_bytes, 8, dbg_span);
            CURL_DBG("wrote traces_ctx_v1: key=0x%llx span_id=%s",
                     (unsigned long long)host_pid_tgid, dbg_span);
        }
    }

    {
        char trace_hex[33]; /* 16 bytes → 32 hex + NUL */
        char span_hex[17];  /* 8 bytes → 16 hex + NUL */
        bytes_to_hex(trace_id_bytes, 16, trace_hex);
        bytes_to_hex(span_id_bytes, 8, span_hex);

        /* "traceparent: 00-<32>-<16>-01\0" */
        char tp_buf[80];
        memcpy(tp_buf, "traceparent: 00-", 16);
        memcpy(tp_buf + 16, trace_hex, 32);
        tp_buf[48] = '-';
        memcpy(tp_buf + 49, span_hex, 16);
        tp_buf[65] = '-';
        tp_buf[66] = '0';
        tp_buf[67] = '1';
        tp_buf[68] = '\0';

        /* Build combined slist: traceparent + copies of user headers.
         * We don't mutate user's list — build an independent copy. */
        injected_headers = resolved_curl_slist_append(NULL, tp_buf);
        if (injected_headers) {
            struct curl_slist *node = tls_user_headers;
            while (node) {
                injected_headers = resolved_curl_slist_append(
                    injected_headers, node->data);
                node = node->next;
            }
            orig_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, injected_headers);
        }
        CURL_DBG("injected header: %s", tp_buf);
    }

do_perform:;
    CURLcode result = orig_curl_easy_perform(handle);

    /* Clean up self-generated traceID to prevent reuse across independent
     * requests.  Only when has_ctx==0 (pure client, no server span context).
     * When has_ctx==1 (server forwarding), keep the entry so subsequent
     * curl calls within the same request handler share the same traceID. */
    if (!has_ctx && g_traces_ctx_fd >= 0 && g_obi_config.host_pid != 0) {
        uint64_t del_key = make_host_pid_tgid(g_obi_config.host_pid);
        union bpf_attr dattr;
        memset(&dattr, 0, sizeof(dattr));
        dattr.map_fd = (uint32_t)g_traces_ctx_fd;
        dattr.key    = (uint64_t)(unsigned long)&del_key;
        syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &dattr, sizeof(dattr));
        CURL_DBG("deleted traces_ctx_v1 entry (pure client cleanup)");
    }

    /* Clean up: restore user's original header list and free our combined
     * slist.  orig_curl_easy_setopt is guaranteed non-NULL here because the
     * safety guard above would have returned early otherwise. */
    if (injected_headers) {
        orig_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, tls_user_headers);
        if (resolved_curl_slist_free_all) {
            resolved_curl_slist_free_all(injected_headers);
        }
    }

    return result;
}

/*
 * obi_curl_hooks_install - Install libcurl GOT hooks.
 *
 * Returns 0 if curl_easy_perform was successfully hooked, -1 otherwise.
 */
__attribute__((visibility("hidden")))
int obi_curl_hooks_install(void) {
    int rc = 0;
    void *orig = NULL;

    /* Hook curl_easy_setopt first — captures user headers before perform.
     * If this fails, hooked_curl_easy_perform will skip header injection
     * to avoid breaking the application's custom headers. */
    if (obi_hook_install("curl_easy_setopt", (void *)hooked_curl_easy_setopt, &orig) == 0) {
        orig_curl_easy_setopt = (curl_easy_setopt_fn)orig;
    } else {
        CURL_DBG("WARNING: curl_easy_setopt hook failed, "
                 "header injection will be disabled");
    }

    orig = NULL;
    if (obi_hook_install("curl_easy_perform", (void *)hooked_curl_easy_perform, &orig) == 0) {
        orig_curl_easy_perform = (curl_easy_perform_fn)orig;
    } else {
        rc = -1;
    }

    return rc;
}

/*
 * obi_curl_hooks_remove - Remove libcurl GOT hooks.
 */
__attribute__((visibility("hidden")))
void obi_curl_hooks_remove(void) {
    obi_hook_remove("curl_easy_perform");
    obi_hook_remove("curl_easy_setopt");
    orig_curl_easy_perform = NULL;
    orig_curl_easy_setopt = NULL;
}
