// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package ptrace

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildShellcode_Size(t *testing.T) {
	code := BuildShellcode(0x7f0000001000, 0x7f0000002000)
	assert.Equal(t, ShellcodeSize(), len(code))
}

func TestBuildShellcode_Structure(t *testing.T) {
	pathAddr := uintptr(0xDEADBEEF12345678)
	dlopenAddr := uintptr(0xCAFEBABE87654321)

	code := BuildShellcode(pathAddr, dlopenAddr)

	// Verify movabs rdi, pathAddr (48 BF <8 bytes>)
	assert.Equal(t, byte(0x48), code[0])
	assert.Equal(t, byte(0xBF), code[1])
	assert.Equal(t, uint64(pathAddr), binary.LittleEndian.Uint64(code[2:10]))

	// Verify movabs rsi, flags (48 BE <8 bytes>)
	assert.Equal(t, byte(0x48), code[10])
	assert.Equal(t, byte(0xBE), code[11])
	flags := binary.LittleEndian.Uint64(code[12:20])
	assert.Equal(t, uint64(0x2), flags) // RTLD_NOW | RTLD_LOCAL

	// Verify movabs rax, dlopenAddr (48 B8 <8 bytes>)
	assert.Equal(t, byte(0x48), code[20])
	assert.Equal(t, byte(0xB8), code[21])
	assert.Equal(t, uint64(dlopenAddr), binary.LittleEndian.Uint64(code[22:30]))

	// Verify call rax (FF D0)
	assert.Equal(t, byte(0xFF), code[30])
	assert.Equal(t, byte(0xD0), code[31])

	// Verify int3 (CC)
	assert.Equal(t, byte(0xCC), code[32])

	// Verify nop (90)
	assert.Equal(t, byte(0x90), code[33])
}

func TestBuildShellcode_DifferentAddresses(t *testing.T) {
	// Test with zero addresses
	code := BuildShellcode(0, 0)
	require.Equal(t, ShellcodeSize(), len(code))
	assert.Equal(t, uint64(0), binary.LittleEndian.Uint64(code[2:10]))
	assert.Equal(t, uint64(0), binary.LittleEndian.Uint64(code[22:30]))

	// Test with max addresses
	code = BuildShellcode(^uintptr(0), ^uintptr(0))
	require.Equal(t, ShellcodeSize(), len(code))
	assert.Equal(t, uint64(^uintptr(0)), binary.LittleEndian.Uint64(code[2:10]))
	assert.Equal(t, uint64(^uintptr(0)), binary.LittleEndian.Uint64(code[22:30]))
}

func TestAppendUint64(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"max", ^uint64(0)},
		{"typical_addr", 0x7f1234567890},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := appendUint64(nil, tc.value)
			assert.Equal(t, 8, len(result))
			assert.Equal(t, tc.value, binary.LittleEndian.Uint64(result))
		})
	}
}

func TestShellcodeSize(t *testing.T) {
	assert.Equal(t, 34, ShellcodeSize())
}
