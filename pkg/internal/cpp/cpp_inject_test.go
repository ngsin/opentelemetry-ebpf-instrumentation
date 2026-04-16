// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cpp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/cpp/detect"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestNewCppInjector_Disabled(t *testing.T) {
	cfg := &obi.Config{}
	cfg.CPP.Enabled = false

	injector, err := NewCppInjector(cfg)
	require.NoError(t, err)
	assert.Nil(t, injector)
}

func TestNewCppInjector_MissingAgent(t *testing.T) {
	cfg := &obi.Config{}
	cfg.CPP.Enabled = true
	cfg.CPP.Timeout = 15 * time.Second

	// Save and restore original embedded bytes
	origBytes := EmbeddedCppAgentBytes
	defer func() { EmbeddedCppAgentBytes = origBytes }()

	EmbeddedCppAgentBytes = []byte("PLACEHOLDER")

	injector, err := NewCppInjector(cfg)
	assert.Error(t, err)
	assert.Nil(t, injector)
	assert.Contains(t, err.Error(), "missing")
}

func TestNewCppInjector_WithValidAgent(t *testing.T) {
	cfg := &obi.Config{}
	cfg.CPP.Enabled = true
	cfg.CPP.Timeout = 15 * time.Second

	// Save and restore
	origBytes := EmbeddedCppAgentBytes
	origCacheDir := userCacheDir
	defer func() {
		EmbeddedCppAgentBytes = origBytes
		userCacheDir = origCacheDir
	}()

	// Use a real (non-placeholder) byte slice
	EmbeddedCppAgentBytes = []byte("fake-elf-binary-content-for-testing")

	// Use temp dir for cache
	tmpDir := t.TempDir()
	userCacheDir = func() (string, error) { return tmpDir, nil }

	injector, err := NewCppInjector(cfg)
	require.NoError(t, err)
	require.NotNil(t, injector)

	// Verify agent was cached
	assert.NotEmpty(t, injector.agentPath)
	_, err = os.Stat(injector.agentPath)
	assert.NoError(t, err)
}

func TestEnsureCppAgentInCache_Idempotent(t *testing.T) {
	origBytes := EmbeddedCppAgentBytes
	origCacheDir := userCacheDir
	origRename := renameFile
	defer func() {
		EmbeddedCppAgentBytes = origBytes
		userCacheDir = origCacheDir
		renameFile = origRename
	}()

	EmbeddedCppAgentBytes = []byte("test-agent-binary")
	tmpDir := t.TempDir()
	userCacheDir = func() (string, error) { return tmpDir, nil }

	// First call should create the file
	path1, err := ensureCppAgentInCache()
	require.NoError(t, err)

	// Second call should return the same path without error
	path2, err := ensureCppAgentInCache()
	require.NoError(t, err)
	assert.Equal(t, path1, path2)
}

func TestWriteConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir := tmpDir
	tmpPath := filepath.Join(tmpDir, "tmp")
	err := os.MkdirAll(tmpPath, 0755)
	require.NoError(t, err)

	injector := &CppInjector{
		cfg: &obi.Config{},
	}
	injector.cfg.CPP.Debug = true
	injector.cfg.EBPF.BPFFSPath = "/sys/fs/bpf/"

	libs := detect.DetectResult(detect.CurlDetected | detect.GRPCDetected)
	err = injector.writeConfigFile(42, 1000, rootDir, libs)
	require.NoError(t, err)

	configPath := filepath.Join(tmpPath, ".obi-cpp-config-42")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "socket_path=/tmp/.obi-42.sock")
	assert.Contains(t, content, "flags=7") // 1(debug) | 2(curl) | 4(grpc)
	assert.Contains(t, content, "bpf_map_path=/sys/fs/bpf/otel/traces_ctx_v1")
	assert.Contains(t, content, "host_pid=1000")
}

func TestWriteConfigFile_HttpServer(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir := tmpDir
	tmpPath := filepath.Join(tmpDir, "tmp")
	err := os.MkdirAll(tmpPath, 0755)
	require.NoError(t, err)

	injector := &CppInjector{
		cfg: &obi.Config{},
	}
	injector.cfg.EBPF.BPFFSPath = "/sys/fs/bpf/"

	// HTTP server + TLS detected, but hooks are intentionally NOT enabled
	// (kprobe/uprobe handles server-side tracing)
	libs := detect.DetectResult(detect.HttpServerDetected | detect.HttpServerTLSDetected)
	err = injector.writeConfigFile(99, 2000, rootDir, libs)
	require.NoError(t, err)

	configPath := filepath.Join(tmpPath, ".obi-cpp-config-99")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "socket_path=/tmp/.obi-99.sock")
	assert.Contains(t, content, "flags=0") // HTTP server hooks intentionally not set
	assert.Contains(t, content, "host_pid=2000")
}

func TestWriteConfigFile_AllFlags(t *testing.T) {
	tmpDir := t.TempDir()
	rootDir := tmpDir
	tmpPath := filepath.Join(tmpDir, "tmp")
	err := os.MkdirAll(tmpPath, 0755)
	require.NoError(t, err)

	injector := &CppInjector{
		cfg: &obi.Config{},
	}
	injector.cfg.CPP.Debug = true
	injector.cfg.EBPF.BPFFSPath = "/sys/fs/bpf/"

	// All flags detected, but only debug+curl+grpc are set in config
	// (HTTP server hooks intentionally not set)
	libs := detect.DetectResult(detect.CurlDetected | detect.GRPCDetected |
		detect.HttpServerDetected | detect.HttpServerTLSDetected)
	err = injector.writeConfigFile(77, 3000, rootDir, libs)
	require.NoError(t, err)

	configPath := filepath.Join(tmpPath, ".obi-cpp-config-77")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "socket_path=/tmp/.obi-77.sock")
	assert.Contains(t, content, "flags=7") // 1(debug) + 2(curl) + 4(grpc) = 7; HTTP server hooks not set
	assert.Contains(t, content, "bpf_map_path=/sys/fs/bpf/otel/traces_ctx_v1")
	assert.Contains(t, content, "host_pid=3000")
}
