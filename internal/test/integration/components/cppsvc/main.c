/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Simple C++ HTTP client using libcurl for integration testing.
 * Makes periodic HTTP GET requests to one or more target URLs in round-robin,
 * allowing OBI to detect and instrument the curl_easy_perform calls.
 *
 * Usage:
 *   cppsvc <url1> [url2 ...] <interval_sec> <max_requests>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

/* Discard response body */
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

int main(int argc, char *argv[]) {
    /* Parse arguments: [url1 url2 ...] [interval_sec] [max_requests]
     * URLs are all arguments that don't look like a plain integer.
     * The last two integer-looking arguments are interval and max_requests.
     * Backwards compatible: "url 2 200" still works as before. */

    const char *urls[32];
    int num_urls = 0;
    int interval_sec = 2;
    int max_requests = 100;

    /* Collect URLs from argv[1..] — stop when we find the trailing integers */
    int i = 1;
    while (i < argc && num_urls < 32) {
        /* Check if this arg and the next are both integers → interval + max */
        if (i + 1 < argc) {
            char *end1, *end2;
            long v1 = strtol(argv[i], &end1, 10);
            long v2 = strtol(argv[i + 1], &end2, 10);
            if (*end1 == '\0' && *end2 == '\0' && v1 > 0 && v2 > 0) {
                interval_sec = (int)v1;
                max_requests = (int)v2;
                break;
            }
        }
        /* Check if this is the last arg and is an integer → max_requests only */
        if (i + 1 == argc) {
            char *end;
            long v = strtol(argv[i], &end, 10);
            if (*end == '\0' && v > 0) {
                max_requests = (int)v;
                break;
            }
        }
        urls[num_urls++] = argv[i];
        i++;
    }

    if (num_urls == 0) {
        urls[0] = "http://testserver:8080/greeting";
        num_urls = 1;
    }

    printf("cppsvc: starting HTTP client\n");
    printf("cppsvc: %d URL(s), interval=%ds, max=%d\n", num_urls, interval_sec, max_requests);
    for (int u = 0; u < num_urls; u++) {
        printf("cppsvc:   [%d] %s\n", u, urls[u]);
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "cppsvc: curl_easy_init failed\n");
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    /* Disable keep-alive connection reuse so each request gets a fresh TCP
     * connection.  This ensures tpinjector can inject a per-request
     * traceparent via TCP options (SYN) and avoids trace_map key collisions
     * on the same {s_addr, s_port} across different request cycles. */
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

    /* Set custom HTTP headers to verify that OBI's curl hook preserves
     * application-supplied headers when injecting traceparent.
     * Critical #1 bug: hooked_curl_easy_perform() replaces the entire
     * CURLOPT_HTTPHEADER list with only traceparent, losing these. */
    struct curl_slist *custom_headers = NULL;
    custom_headers = curl_slist_append(custom_headers, "X-Custom-Auth: Bearer test-token-12345");
    custom_headers = curl_slist_append(custom_headers, "X-Request-Source: obi-integration-test");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, custom_headers);

    /* Detect if any URL is HTTPS for certificate settings */
    int has_https = 0;
    for (int u = 0; u < num_urls; u++) {
        if (strncmp(urls[u], "https://", 8) == 0) {
            has_https = 1;
            break;
        }
    }
    if (has_https) {
        printf("cppsvc: HTTPS mode detected, disabling certificate verification\n");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    int count = 0;
    int url_idx = 0;
    while (count < max_requests) {
        const char *target_url = urls[url_idx];
        curl_easy_setopt(curl, CURLOPT_URL, target_url);
        /* Re-set custom headers each iteration so that the hooked
         * curl_easy_setopt (installed after constructor) can capture
         * the user's header list in thread-local storage. */
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, custom_headers);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("cppsvc: request %d [%s] -> %ld\n", count + 1, target_url, http_code);
        } else {
            fprintf(stderr, "cppsvc: request %d [%s] failed: %s\n",
                    count + 1, target_url, curl_easy_strerror(res));
        }

        count++;
        url_idx = (url_idx + 1) % num_urls;

        if (count < max_requests) {
            sleep(interval_sec);
        }
    }

    curl_slist_free_all(custom_headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("cppsvc: done, sent %d requests\n", count);
    return 0;
}
