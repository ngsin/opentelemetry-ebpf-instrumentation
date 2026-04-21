/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OBI C++ Agent - Configuration reader
 */

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((visibility("hidden")))
int obi_config_read(struct obi_config *cfg) {
    char path[OBI_MAX_PATH];
    FILE *fp;
    char line[512];

    if (!cfg) {
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->pid = (uint32_t)getpid();

    /* 优先尝试每进程路径（ptrace 注入模式） */
    snprintf(path, sizeof(path), "/tmp/.obi-cpp-config-%u", cfg->pid);
    fp = fopen(path, "r");

    /* 回退：LD_PRELOAD 注入模式的固定路径 */
    if (!fp) {
        strncpy(path, "/var/lib/obi/obi-cpp-config", sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
        fp = fopen(path, "r");
    }

    if (!fp) {
        return -1;
    }

    /*
     * Config file format (simple key=value, one per line):
     *   socket_path=/tmp/.obi-<pid>.sock
     *   flags=3
     *   debug=1
     */
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if (strcmp(key, "socket_path") == 0) {
            strncpy(cfg->socket_path, val, OBI_MAX_PATH - 1);
            cfg->socket_path[OBI_MAX_PATH - 1] = '\0';
        } else if (strcmp(key, "bpf_map_path") == 0) {
            strncpy(cfg->bpf_map_path, val, OBI_MAX_PATH - 1);
            cfg->bpf_map_path[OBI_MAX_PATH - 1] = '\0';
        } else if (strcmp(key, "incoming_trace_map_path") == 0) {
            strncpy(cfg->incoming_trace_map_path, val, OBI_MAX_PATH - 1);
            cfg->incoming_trace_map_path[OBI_MAX_PATH - 1] = '\0';
        } else if (strcmp(key, "host_pid") == 0) {
            cfg->host_pid = (uint32_t)strtoul(val, NULL, 10);
        } else if (strcmp(key, "flags") == 0) {
            cfg->flags = (uint32_t)strtoul(val, NULL, 10);
        } else if (strcmp(key, "debug") == 0) {
            if (atoi(val)) {
                cfg->flags |= OBI_CFG_DEBUG;
            }
        }
    }

    fclose(fp);

    /*
     * LD_PRELOAD 模式下 host_pid=0（config 中不写具体值，由进程自己获取）。
     * agent.so 在目标进程内运行，所以 getpid() 直接返回宿主命名空间 PID。
     * 用它来构造正确的 traces_ctx_v1 BPF map 键：(host_pid << 32) | ns_tid。
     */
    if (cfg->host_pid == 0) {
        cfg->host_pid = cfg->pid;
    }

    return 0;
}
