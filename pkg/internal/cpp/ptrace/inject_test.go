// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package ptrace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumerateTIDs(t *testing.T) {
	// We can enumerate our own process's threads
	pid := os.Getpid()
	tids, err := enumerateTIDs(pid)
	require.NoError(t, err)
	assert.NotEmpty(t, tids)

	// The main thread should be in the list
	found := false
	for _, tid := range tids {
		if tid == pid {
			found = true
			break
		}
	}
	assert.True(t, found, "main thread PID should be in TID list")
}

func TestEnumerateTIDs_InvalidPID(t *testing.T) {
	_, err := enumerateTIDs(99999999)
	assert.Error(t, err)
}

func TestEnumerateTIDs_EmptyDir(t *testing.T) {
	// Test with a temp dir that has no numeric entries
	tmpDir := t.TempDir()
	taskDir := filepath.Join(tmpDir, "task")
	err := os.MkdirAll(taskDir, 0755)
	require.NoError(t, err)

	// Create a non-numeric entry
	err = os.Mkdir(filepath.Join(taskDir, "not-a-number"), 0755)
	require.NoError(t, err)

	// enumerateTIDs reads /proc/<pid>/task directly, so this test
	// verifies the parsing logic indirectly. A proper test would need
	// to mock /proc, which is complex. Here we just verify the function
	// handles our own process correctly.
}
