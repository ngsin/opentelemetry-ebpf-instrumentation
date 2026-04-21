// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cpp // import "go.opentelemetry.io/obi/pkg/internal/cpp"

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/cpp/detect"
	cppptrace "go.opentelemetry.io/obi/pkg/internal/cpp/ptrace"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	cppAgentEmbedPlaceholder = "PLACEHOLDER"

	HostAgentDir    = "/var/lib/obi"
	HostAgentPath   = "/var/lib/obi/obi-cpp-agent.so"
	HostAgentConfig = "/var/lib/obi/obi-cpp-config"
)

// Aliases for testing.
var (
	userCacheDir = os.UserCacheDir
	renameFile   = os.Rename
)

// CppInjector manages the lifecycle of C++ agent injection via ptrace.
// It detects C++ libraries in target processes, injects agent.so, and
// manages the span reading pipeline.
type CppInjector struct {
	log       *slog.Logger
	cfg       *obi.Config
	agentPath string // cached host path to agent.so

	mu           sync.Mutex
	injectedPIDs map[app.PID]struct{}
	spanReaders  map[app.PID]*SpanReader

	// SpanOutput is the channel where parsed spans are forwarded.
	// Connect this to the existing span pipeline (e.g., SpanSignalsShortcut).
	SpanOutput chan<- []request.Span
}

// NewCppInjector creates a new CppInjector if C++ injection is enabled.
// Returns nil if disabled.
func NewCppInjector(cfg *obi.Config) (*CppInjector, error) {
	if !cfg.CPP.Enabled {
		return nil, nil
	}

	agentPath, err := ensureCppAgentInCache()
	if err != nil {
		return nil, fmt.Errorf("unable to extract embedded OBI C++ agent: %w", err)
	}

	return &CppInjector{
		cfg:          cfg,
		log:          slog.With("component", "cppagent.Injector"),
		agentPath:    agentPath,
		injectedPIDs: make(map[app.PID]struct{}),
		spanReaders:  make(map[app.PID]*SpanReader),
	}, nil
}

// NewExecutable processes a newly discovered executable and injects the
// C++ agent if supported libraries are detected.
func (i *CppInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	pid := ie.FileInfo.Pid

	i.mu.Lock()
	if _, already := i.injectedPIDs[pid]; already {
		i.mu.Unlock()
		return nil
	}
	i.mu.Unlock()

	// Step 1: Detect C++ libraries
	libs, err := detect.DetectLibraries(pid)
	if err != nil {
		return fmt.Errorf("library detection for pid %d: %w", pid, err)
	}

	if !libs.HasAny() {
		// No supported C++ libraries found
		return nil
	}

	i.log.Info("detected C++ libraries",
		"pid", pid,
		"curl", libs.HasCurl(),
		"grpc", libs.HasGRPC(),
		"httpServer", libs.HasHttpServer(),
		"httpServerTLS", libs.HasHttpServerTLS(),
	)

	// Step 2: Write config file using the namespace PID (what the process
	// sees as its own PID via getpid()).
	rootDir := ebpfcommon.RootDirectoryForPID(pid)
	nsPID, err := namespacePID(pid)
	if err != nil {
		// Fall back to host PID if we can't read NSpid
		nsPID = pid
	}
	if err := i.writeConfigFile(nsPID, pid, rootDir, libs); err != nil {
		return fmt.Errorf("writing config for pid %d: %w", pid, err)
	}

	// Step 3: Copy agent.so to target container
	containerAgentPath, err := i.copyAgent(pid, rootDir)
	if err != nil {
		return fmt.Errorf("copying agent for pid %d: %w", pid, err)
	}

	// Step 4: Start SpanReader before injection (so socket is ready)
	// Copy service attributes so the SpanReader can decorate spans with
	// the correct service identity and PID namespace.
	ie.CopyToServiceAttributes()
	sr, err := NewSpanReader(nsPID, pid, ie.FileInfo.Ns, ie.FileInfo.Service, rootDir)
	if err != nil {
		return fmt.Errorf("creating span reader for pid %d: %w", pid, err)
	}

	if i.SpanOutput != nil {
		// Create a channel that the SpanReader writes into.
		// A goroutine forwards spans to the output pipeline.
		spanChan := make(chan []request.Span, 50)
		sr.Start(context.Background(), spanChan)
		go func() {
			for spans := range spanChan {
				i.SpanOutput <- spans
			}
		}()
	}

	// Step 5: Resolve dlopen address and inject
	dlopenAddr, err := cppptrace.FindDlopenAddr(pid)
	if err != nil {
		sr.Close()
		return fmt.Errorf("resolving dlopen for pid %d: %w", pid, err)
	}

	if err := cppptrace.Inject(int(pid), containerAgentPath, dlopenAddr); err != nil {
		sr.Close()
		return fmt.Errorf("ptrace injection for pid %d: %w", pid, err)
	}

	// Step 6: Track
	i.mu.Lock()
	i.injectedPIDs[pid] = struct{}{}
	i.spanReaders[pid] = sr
	i.mu.Unlock()

	i.log.Info("successfully injected C++ agent", "pid", pid, "agent", containerAgentPath)
	return nil
}

// ProcessDeleted cleans up resources when a process exits.
func (i *CppInjector) ProcessDeleted(ie *ebpf.Instrumentable) {
	pid := ie.FileInfo.Pid

	i.mu.Lock()
	sr, exists := i.spanReaders[pid]
	if exists {
		delete(i.spanReaders, pid)
		delete(i.injectedPIDs, pid)
	}
	i.mu.Unlock()

	if !exists {
		return
	}

	// Close span reader
	if sr != nil {
		sr.Close()
	}

	// Clean up agent.so copy in the container
	rootDir := ebpfcommon.RootDirectoryForPID(pid)
	agentPath := filepath.Join(rootDir, "tmp", ObiCppAgentFileName)
	os.Remove(agentPath)

	configPath := filepath.Join(rootDir, "tmp", fmt.Sprintf(".obi-cpp-config-%d", pid))
	os.Remove(configPath)

	i.log.Debug("cleaned up C++ agent resources", "pid", pid)
}

// writeConfigFile writes the configuration file read by agent.so's constructor.
func (i *CppInjector) writeConfigFile(pid app.PID, hostPID app.PID, rootDir string, libs detect.DetectResult) error {
	configPath := filepath.Join(rootDir, "tmp", fmt.Sprintf(".obi-cpp-config-%d", pid))

	var flags uint32
	if i.cfg.CPP.Debug {
		flags |= 1 // OBI_CFG_DEBUG
	}
	if libs.HasCurl() {
		flags |= 2 // OBI_CFG_CURL_HOOK
	}
	if libs.HasGRPC() {
		flags |= 4 // OBI_CFG_GRPC_HOOK
	}
	// Note: Plain HTTP server hooks (OBI_CFG_HTTP_SERVER_HOOK) are intentionally
	// NOT set. The kprobe/uprobe generic tracers produce strictly more complete
	// HTTP server spans (with server.port, client.address, body_size, etc.).
	// However, HTTPS/TLS server hooks ARE enabled so the agent can parse
	// incoming traceparent headers from encrypted traffic and write them to
	// incoming_trace_map for eBPF late-binding trace lookup (eBPF can't read
	// decrypted HTTP headers in the SSL_read byte-at-a-time pattern).
	if libs.HasHttpServerTLS() {
		flags |= 16 // OBI_CFG_HTTP_SERVER_TLS_HOOK
	}

	socketPath := fmt.Sprintf("/tmp/.obi-%d.sock", pid)

	// The BPF pinned map path for traces_ctx_v1.  The agent uses this to
	// read the eBPF-generated traceID and inject a consistent Traceparent
	// HTTP header for HTTPS requests (L7 layer), matching the TCP option
	// traceID (L4 layer).
	bpfMapPath := path.Join(i.cfg.EBPF.BPFFSPath, "otel", "traces_ctx_v1")

	// The BPF pinned map path for incoming_trace_map.  The agent writes
	// parsed traceparent from HTTPS request headers into this map so that
	// eBPF kprobe can find it during server span creation (late-binding).
	incomingTraceMapPath := path.Join(i.cfg.EBPF.BPFFSPath, "otel", "incoming_trace_map")

	content := fmt.Sprintf("socket_path=%s\nflags=%d\nbpf_map_path=%s\nincoming_trace_map_path=%s\nhost_pid=%d\n",
		socketPath, flags, bpfMapPath, incomingTraceMapPath, hostPID)

	return os.WriteFile(configPath, []byte(content), 0644)
}

// copyAgent copies the cached agent.so to the target container's /tmp/.
func (i *CppInjector) copyAgent(pid app.PID, rootDir string) (string, error) {
	hostPath := filepath.Join(rootDir, "tmp", ObiCppAgentFileName)

	source, err := os.Open(i.agentPath)
	if err != nil {
		return "", fmt.Errorf("opening cached agent: %w", err)
	}
	defer source.Close()

	target, err := os.OpenFile(hostPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("creating target agent: %w", err)
	}
	defer target.Close()

	if _, err = target.ReadFrom(source); err != nil {
		return "", fmt.Errorf("writing agent to target: %w", err)
	}

	// Return the container-internal path (used by dlopen)
	return filepath.Join("/tmp", ObiCppAgentFileName), nil
}

// ensureCppAgentInCache extracts the embedded agent.so to the user cache.
func ensureCppAgentInCache() (string, error) {
	if len(EmbeddedCppAgentBytes) == 0 ||
		strings.TrimSpace(string(EmbeddedCppAgentBytes)) == cppAgentEmbedPlaceholder {
		return "", errors.New("embedded OBI C++ agent artifact is missing; run `make cpp-agent-docker-build`")
	}

	cacheRoot, err := userCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving user cache directory: %w", err)
	}

	cacheDir := filepath.Join(cacheRoot, "obi", "cpp")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating C++ agent cache directory: %w", err)
	}

	checksum := sha256.Sum256(EmbeddedCppAgentBytes)
	targetPath := filepath.Join(cacheDir, fmt.Sprintf("obi-cpp-agent-%x.so", checksum))

	// Fast path: reuse if already cached
	if info, err := os.Stat(targetPath); err == nil {
		if !info.IsDir() && info.Size() == int64(len(EmbeddedCppAgentBytes)) {
			return targetPath, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat cached C++ agent: %w", err)
	}

	// Write to temp file then rename (atomic)
	tmpFile, err := os.CreateTemp(cacheDir, "obi-cpp-agent-*.tmp")
	if err != nil {
		return "", fmt.Errorf("creating temp file for C++ agent: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // cleanup on failure
	}()

	if _, err := tmpFile.Write(EmbeddedCppAgentBytes); err != nil {
		return "", fmt.Errorf("writing C++ agent to cache: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("closing temp agent file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return "", fmt.Errorf("setting agent permissions: %w", err)
	}

	if err := renameFile(tmpPath, targetPath); err != nil {
		return "", fmt.Errorf("renaming agent to cache: %w", err)
	}

	return targetPath, nil
}

// namespacePID reads /proc/<pid>/status to find the innermost NSpid value,
// which is the PID as seen by the process itself (inside its PID namespace).
func namespacePID(hostPID app.PID) (app.PID, error) {
	statusPath := filepath.Join("/proc", strconv.Itoa(int(hostPID)), "status")
	f, err := os.Open(statusPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		// NSpid:\t<host_pid>\t<ns_pid1>\t<ns_pid2>...
		// The last value is the innermost namespace PID.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		last := fields[len(fields)-1]
		nsPID, err := strconv.Atoi(last)
		if err != nil {
			return 0, fmt.Errorf("parsing NSpid from %q: %w", line, err)
		}
		return app.PID(nsPID), nil
	}

	return 0, fmt.Errorf("NSpid not found in %s", statusPath)
}

// EnsureCppAgentOnHost 将内嵌的 agent.so 解压到 /var/lib/obi/，
// 并为 LD_PRELOAD 加载的进程写入共享配置文件。
// 幂等：若 agent.so 的 sha256 与已有文件一致则跳过写入。
// 当 hostPath /var/lib/obi 已挂载时，在 OBI 启动时调用。
func EnsureCppAgentOnHost(cfg *obi.Config) error {
	if len(EmbeddedCppAgentBytes) == 0 ||
		strings.TrimSpace(string(EmbeddedCppAgentBytes)) == cppAgentEmbedPlaceholder {
		return errors.New("embedded OBI C++ agent artifact is missing")
	}

	if err := os.MkdirAll(HostAgentDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", HostAgentDir, err)
	}

	// 检查已有文件是否匹配（幂等）
	checksum := sha256.Sum256(EmbeddedCppAgentBytes)
	if info, err := os.Stat(HostAgentPath); err == nil {
		if info.Size() == int64(len(EmbeddedCppAgentBytes)) {
			existing, err := os.ReadFile(HostAgentPath)
			if err == nil {
				existingSum := sha256.Sum256(existing)
				if existingSum == checksum {
					slog.Info("obi-cpp-agent.so already up to date on host", "path", HostAgentPath)
					return writeHostConfig(cfg)
				}
			}
		}
	}

	// 通过临时文件 + 重命名原子写入 agent.so
	tmpFile, err := os.CreateTemp(HostAgentDir, "obi-cpp-agent-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp agent file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(EmbeddedCppAgentBytes); err != nil {
		return fmt.Errorf("writing agent.so: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing agent.so: %w", err)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod agent.so: %w", err)
	}
	if err := renameFile(tmpPath, HostAgentPath); err != nil {
		return fmt.Errorf("renaming agent.so: %w", err)
	}

	slog.Info("extracted obi-cpp-agent.so to host", "path", HostAgentPath)
	return writeHostConfig(cfg)
}

// writeHostConfig 为 LD_PRELOAD 进程写入 /var/lib/obi/obi-cpp-config。
// 使用固定标志位：debug + curl_hook + https_server_tls_hook。
// BPF map 路径使用配置中的 BPFFSPath。
func writeHostConfig(cfg *obi.Config) error {
	var flags uint32
	if cfg.CPP.Debug {
		flags |= 1 // OBI_CFG_DEBUG
	}
	flags |= 2  // OBI_CFG_CURL_HOOK（始终启用，用于客户端 traceparent 注入）
	flags |= 16 // OBI_CFG_HTTP_SERVER_TLS_HOOK（始终启用，用于入站 traceparent）

	bpfMapPath := path.Join(cfg.EBPF.BPFFSPath, "otel", "traces_ctx_v1")
	incomingTraceMapPath := path.Join(cfg.EBPF.BPFFSPath, "otel", "incoming_trace_map")

	// socket_path 为空（LD_PRELOAD 模式下不导出 span）
	// host_pid 为 0（不使用；BPF key 使用进程自身的宿主 TID）
	content := fmt.Sprintf(
		"socket_path=\nflags=%d\nbpf_map_path=%s\nincoming_trace_map_path=%s\nhost_pid=0\n",
		flags, bpfMapPath, incomingTraceMapPath,
	)

	if err := os.WriteFile(HostAgentConfig, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing host config: %w", err)
	}
	slog.Info("wrote obi-cpp-config to host", "path", HostAgentConfig, "flags", flags)
	return nil
}
