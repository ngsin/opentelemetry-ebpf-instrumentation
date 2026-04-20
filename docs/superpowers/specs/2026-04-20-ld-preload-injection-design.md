# LD_PRELOAD Injection Design

Date: 2026-04-20

## Background

OBI currently injects `obi-cpp-agent.so` into C++ target processes via ptrace+dlopen. This approach has a critical reliability issue: the eBPF `sched_process_exec` tracepoint used by ProcessWatcher only captures processes created *after* OBI's eBPF programs are loaded. When cpp pods start before or concurrently with the OBI DaemonSet pod (e.g., during rollouts), the exec event is missed and injection never happens.

The fix is to switch to LD_PRELOAD injection, where the dynamic linker loads agent.so automatically at process startup — eliminating the dependency on OBI observing the exec event.

## Goals

- agent.so is loaded reliably on every cpp process start, regardless of OBI startup timing
- Simplify agent.so responsibility: only inject `traceparent` headers into outgoing HTTPS requests (libcurl hook) and parse incoming traceparent headers for eBPF late-binding (TLS server hook)
- Eliminate the Unix socket span-export pipeline from agent.so; all spans are produced by eBPF
- Disable ptrace injection (`cpp.enabled: false`)

## Non-Goals

- Changing how eBPF captures spans (HTTP/Redis/MySQL/PG all remain eBPF-only)
- Supporting non-cpp services via LD_PRELOAD
- Automatic agent.so reload when OBI updates the binary

## Architecture

```
OBI DaemonSet (hostPID=true, privileged)
  └─ On startup: extract embedded agent.so → /var/lib/obi/obi-cpp-agent.so

Node hostPath: /var/lib/obi/
  └─ obi-cpp-agent.so  (written by OBI, read by cpp pods)

cppsvctls / cppsvc Pod
  └─ volume: hostPath /var/lib/obi → /var/lib/obi (readOnly)
  └─ env: LD_PRELOAD=/var/lib/obi/obi-cpp-agent.so
  └─ At process start: dynamic linker loads agent.so automatically
  └─ agent.so constructor: installs curl GOT hook + TLS server hook
  └─ curl hook: injects traceparent header into outgoing HTTPS requests
  └─ TLS hook: writes incoming traceparent to BPF incoming_trace_map

eBPF (OBI): produces all spans unchanged
```

## Component Changes

### 1. OBI DaemonSet

**Volume:**
```yaml
volumes:
  - name: obi-agent-dir
    hostPath:
      path: /var/lib/obi
      type: DirectoryOrCreate
volumeMounts:
  - name: obi-agent-dir
    mountPath: /var/lib/obi
```

**Startup logic** (`ensureCppAgentInCache` → `ensureCppAgentOnHost`):
- Target path changes from `~/.cache/obi/cpp/obi-cpp-agent-<hash>.so` to `/var/lib/obi/obi-cpp-agent.so`
- Write is idempotent: skip if file exists and sha256 matches
- OBI runs as root (privileged), so `/var/lib/obi/` is writable

**ptrace injection disabled:**
```yaml
# DaemonSet env
- name: OTEL_EBPF_CPP_ENABLED
  value: "false"
# ConfigMap
cpp:
  enabled: false
```

### 2. cppsvc / cppsvctls Deployments

**Volume (same hostPath, readOnly):**
```yaml
volumes:
  - name: obi-agent-dir
    hostPath:
      path: /var/lib/obi
      type: Directory
volumeMounts:
  - name: obi-agent-dir
    mountPath: /var/lib/obi
    readOnly: true
```

**Environment variable:**
```yaml
env:
  - name: LD_PRELOAD
    value: /var/lib/obi/obi-cpp-agent.so
```

### 3. agent.so Changes

**Remove:** Unix socket export (`obi_export_init`, `obi_export_send`, span production). The `SpanReader` Go-side listener becomes unused for these processes.

**Keep:**
- `curl_hooks`: intercepts `curl_easy_perform` to inject `traceparent` header into outgoing HTTPS requests
- `http_server_tls_hooks`: parses incoming `traceparent` from decrypted TLS data, writes to `incoming_trace_map` BPF map for eBPF late-binding

**Config file** (written by OBI to `/var/lib/obi/obi-cpp-config`):
- Since agent.so is loaded by LD_PRELOAD and not by OBI, a fixed config path is used instead of per-pid `/tmp/.obi-<pid>-config`
- Path: `/var/lib/obi/obi-cpp-config` (written by OBI on startup, read by agent.so constructor)
- Contents: `flags`, `bpf_map_path`, `incoming_trace_map_path` (no `socket_path`, no `host_pid`)

## Data Flow

```
cppsvctls → curl_easy_perform()
  → curl_hook intercepts
  → reads traces_ctx_v1 BPF map (traceID for this connection)
  → injects "traceparent: 00-<traceID>-<spanID>-01" header
  → HTTPS request sent to cpphttpssvc with traceparent

cpphttpssvc receives HTTPS request
  → TLS hook (SSL_read) sees decrypted headers
  → parses traceparent
  → writes to incoming_trace_map BPF map
  → eBPF kprobe reads incoming_trace_map → server span gets correct parent traceID
  → eBPF produces HTTP server span with correct trace context
  → eBPF produces Redis/MySQL/PG client spans as children
```

## Deployment Order

1. Update OBI DaemonSet (add hostPath volume, disable ptrace, OBI writes agent.so on startup)
2. Update cppsvc/cppsvctls Deployments (add hostPath volume + LD_PRELOAD env)
3. Verify: check agent.so exists at `/var/lib/obi/obi-cpp-agent.so` on each node
4. Verify: check traces in Jaeger show connected cppsvctls → cpphttpssvc spans

## Risks

- **Startup race**: if cpp pod starts before OBI has written agent.so to hostPath, LD_PRELOAD will fail silently (file not found). Mitigation: OBI DaemonSet has `system-node-critical` priority and starts before regular pods; acceptable risk for now.
- **agent.so ABI**: LD_PRELOAD loads agent.so into the process address space permanently; agent.so must not crash the target process. The existing agent.so is already tested for this.
- **BPF map path**: agent.so needs to open BPF pinned maps at `/sys/fs/bpf/otel/...`. cppsvc/cppsvctls do NOT mount `/sys/fs/bpf`, so the TLS hook's BPF map write will fail silently. Curl hook (traceparent injection via `traces_ctx_v1`) also requires this mount. Options: add `/sys/fs/bpf` mount to cpp pods (requires privilege), or accept that only the curl-side traceparent injection works (eBPF handles the rest). **Decision: give cpp pods `privileged: true`** and mount `/sys/fs/bpf` (readWrite). This allows `bpf()` syscall access for BPF map read/write. Agent.so code requires zero changes. Acceptable for this integration test environment.
