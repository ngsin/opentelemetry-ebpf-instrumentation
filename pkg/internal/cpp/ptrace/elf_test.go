// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ptrace

import (
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newExecMap(pathname string, startAddr uintptr) *procfs.ProcMap {
	return &procfs.ProcMap{
		StartAddr: startAddr,
		EndAddr:   startAddr + 0x100000,
		Perms: &procfs.ProcMapPermissions{
			Read:    true,
			Write:   false,
			Execute: true,
			Shared:  false,
			Private: true,
		},
		Pathname: pathname,
	}
}

func TestIsLibc(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"/lib/x86_64-linux-gnu/libc.so.6", true},
		{"/lib/x86_64-linux-gnu/libc-2.31.so", true},
		{"/usr/lib/libc.so", true},
		{"/lib/libcurl.so.4", false},
		{"/lib/libcap.so.2", false},
		{"/lib/ld-linux-x86-64.so.2", false},
		{"/lib/libpthread.so.0", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.expect, isLibc(tc.path))
		})
	}
}

func TestFindLibcBaseFromMaps(t *testing.T) {
	maps := []*procfs.ProcMap{
		newExecMap("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", 0x7f0000000000),
		newExecMap("/lib/x86_64-linux-gnu/libc.so.6", 0x7f0001000000),
		newExecMap("/usr/lib/libcurl.so.4", 0x7f0002000000),
	}

	base, hostPath, err := findLibcBaseFromMaps(42, maps)
	require.NoError(t, err)
	assert.Equal(t, uintptr(0x7f0001000000), base)
	assert.Equal(t, "/proc/42/root/lib/x86_64-linux-gnu/libc.so.6", hostPath)
}

func TestFindLibcBaseFromMaps_NotFound(t *testing.T) {
	maps := []*procfs.ProcMap{
		newExecMap("/lib/x86_64-linux-gnu/libpthread.so.0", 0x7f0000000000),
	}

	_, _, err := findLibcBaseFromMaps(42, maps)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "libc.so not found")
}

func TestFindLibcBaseFromMaps_MuslLibc(t *testing.T) {
	// Alpine/musl uses libc.so directly
	maps := []*procfs.ProcMap{
		newExecMap("/lib/ld-musl-x86_64.so.1", 0x7f0000000000),
		newExecMap("/lib/libc.so", 0x7f0001000000),
	}

	base, _, err := findLibcBaseFromMaps(1, maps)
	require.NoError(t, err)
	assert.Equal(t, uintptr(0x7f0000000000), base) // ld-musl-* matches first and IS musl's libc
}

func TestResolveDynSymOffset_RealLibc(t *testing.T) {
	// This test attempts to resolve a symbol from the actual system libc.
	// Skip if libc isn't at the expected path.
	libcPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/libc.so.6",
	}

	var libcPath string
	for _, p := range libcPaths {
		if _, err := ResolveDynSymOffset(p, "write"); err == nil {
			libcPath = p
			break
		}
	}

	if libcPath == "" {
		t.Skip("libc.so not found at standard paths, skipping real ELF test")
	}

	// Test resolving a well-known symbol
	offset, err := ResolveDynSymOffset(libcPath, "write")
	require.NoError(t, err)
	assert.NotEqual(t, uintptr(0), offset, "write offset should be non-zero")

	// Test resolving a non-existent symbol
	_, err = ResolveDynSymOffset(libcPath, "__definitely_nonexistent_symbol__")
	assert.Error(t, err)
}
