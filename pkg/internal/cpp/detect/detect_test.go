// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
)

func newProcMap(pathname string, exec bool) *procfs.ProcMap {
	perms := &procfs.ProcMapPermissions{
		Read:    true,
		Write:   false,
		Execute: exec,
		Shared:  false,
		Private: true,
	}
	return &procfs.ProcMap{
		StartAddr: 0x7f0000000000,
		EndAddr:   0x7f0000100000,
		Perms:     perms,
		Pathname:  pathname,
	}
}

func TestDetectFromMaps_CurlOnly(t *testing.T) {
	maps := []*procfs.ProcMap{
		newProcMap("/usr/lib/x86_64-linux-gnu/libcurl.so.4.7.0", true),
		newProcMap("/lib/x86_64-linux-gnu/libc.so.6", true),
	}
	result := detectFromMaps(maps)
	assert.True(t, result.HasCurl())
	assert.False(t, result.HasGRPC())
	assert.True(t, result.HasAny())
}

func TestDetectFromMaps_GRPCOnly(t *testing.T) {
	maps := []*procfs.ProcMap{
		newProcMap("/usr/lib/libgrpc.so.1.0", true),
		newProcMap("/lib/x86_64-linux-gnu/libc.so.6", true),
	}
	result := detectFromMaps(maps)
	assert.False(t, result.HasCurl())
	assert.True(t, result.HasGRPC())
	assert.True(t, result.HasAny())
}

func TestDetectFromMaps_GRPCPlusPlus(t *testing.T) {
	maps := []*procfs.ProcMap{
		newProcMap("/usr/lib/libgrpc++.so.1.0", true),
		newProcMap("/lib/x86_64-linux-gnu/libc.so.6", true),
	}
	result := detectFromMaps(maps)
	assert.False(t, result.HasCurl())
	assert.True(t, result.HasGRPC())
}

func TestDetectFromMaps_Both(t *testing.T) {
	maps := []*procfs.ProcMap{
		newProcMap("/usr/lib/libcurl.so.4", true),
		newProcMap("/usr/lib/libgrpc.so.1", true),
		newProcMap("/lib/x86_64-linux-gnu/libc.so.6", true),
	}
	result := detectFromMaps(maps)
	assert.True(t, result.HasCurl())
	assert.True(t, result.HasGRPC())
	assert.True(t, result.HasAny())
}

func TestDetectFromMaps_None(t *testing.T) {
	maps := []*procfs.ProcMap{
		newProcMap("/lib/x86_64-linux-gnu/libc.so.6", true),
		newProcMap("/lib/x86_64-linux-gnu/libpthread.so.0", true),
	}
	result := detectFromMaps(maps)
	assert.False(t, result.HasCurl())
	assert.False(t, result.HasGRPC())
	assert.False(t, result.HasAny())
}

func TestDetectFromMaps_NonExecutable(t *testing.T) {
	// Libraries mapped without execute permission should not be detected
	maps := []*procfs.ProcMap{
		newProcMap("/usr/lib/libcurl.so.4", false),
		newProcMap("/lib/x86_64-linux-gnu/libc.so.6", true),
	}
	result := detectFromMaps(maps)
	assert.False(t, result.HasCurl())
}

func TestDetectFromMaps_EmptyMaps(t *testing.T) {
	result := detectFromMaps(nil)
	assert.False(t, result.HasAny())
}

func TestDetectResult_Bitmask(t *testing.T) {
	var r DetectResult
	assert.Equal(t, DetectResult(0), r)

	r |= CurlDetected
	assert.True(t, r.HasCurl())
	assert.False(t, r.HasGRPC())

	r |= GRPCDetected
	assert.True(t, r.HasCurl())
	assert.True(t, r.HasGRPC())
}

func TestDetectResult_HttpServer(t *testing.T) {
	var r DetectResult
	assert.False(t, r.HasHttpServer())
	assert.False(t, r.HasHttpServerTLS())

	r |= HttpServerDetected
	assert.True(t, r.HasHttpServer())
	assert.False(t, r.HasHttpServerTLS())
	assert.True(t, r.HasAny())

	r |= HttpServerTLSDetected
	assert.True(t, r.HasHttpServer())
	assert.True(t, r.HasHttpServerTLS())
}

func TestDetectResult_AllFlags(t *testing.T) {
	r := CurlDetected | GRPCDetected | HttpServerDetected | HttpServerTLSDetected
	assert.True(t, r.HasCurl())
	assert.True(t, r.HasGRPC())
	assert.True(t, r.HasHttpServer())
	assert.True(t, r.HasHttpServerTLS())
	assert.True(t, r.HasAny())
}

// buildRela64Entry creates a 24-byte Elf64_Rela entry with the given symbol
// index and relocation type (7 = R_X86_64_JUMP_SLOT).
func buildRela64Entry(symIdx uint32, relType uint32) []byte {
	buf := make([]byte, 24)
	// offset (8 bytes) - don't care
	binary.LittleEndian.PutUint64(buf[0:8], 0)
	// info (8 bytes): high 32 bits = symIdx, low 32 bits = relType
	info := (uint64(symIdx) << 32) | uint64(relType)
	binary.LittleEndian.PutUint64(buf[8:16], info)
	// addend (8 bytes) - don't care
	binary.LittleEndian.PutUint64(buf[16:24], 0)
	return buf
}

// buildRel32Entry creates an 8-byte Elf32_Rel entry with the given symbol
// index and relocation type (7 = R_386_JMP_SLOT).
func buildRel32Entry(symIdx uint32, relType uint32) []byte {
	buf := make([]byte, 8)
	// offset (4 bytes) - don't care
	binary.LittleEndian.PutUint32(buf[0:4], 0)
	// info (4 bytes): high 24 bits = symIdx, low 8 bits = relType
	info := (symIdx << 8) | (relType & 0xff)
	binary.LittleEndian.PutUint32(buf[4:8], info)
	return buf
}

func TestParseRela64_JumpSlot(t *testing.T) {
	dynsyms := []elf.Symbol{
		{Name: "accept4"},  // index 0 → symIdx 1
		{Name: "recv"},     // index 1 → symIdx 2
		{Name: "send"},     // index 2 → symIdx 3
		{Name: "printf"},   // index 3 → symIdx 4 (non-JUMP_SLOT)
	}

	var data []byte
	data = append(data, buildRela64Entry(1, 7)...)  // accept4, JUMP_SLOT
	data = append(data, buildRela64Entry(2, 7)...)  // recv, JUMP_SLOT
	data = append(data, buildRela64Entry(3, 7)...)  // send, JUMP_SLOT
	data = append(data, buildRela64Entry(4, 6)...)  // printf, GLOB_DAT (not JUMP_SLOT)

	result := make(map[string]bool)
	parseRela64(data, dynsyms, binary.LittleEndian, result)

	assert.True(t, result["accept4"])
	assert.True(t, result["recv"])
	assert.True(t, result["send"])
	assert.False(t, result["printf"])
}

func TestParseRela64_VersionSuffix(t *testing.T) {
	dynsyms := []elf.Symbol{
		{Name: "recv@GLIBC_2.2.5"},
	}

	data := buildRela64Entry(1, 7) // recv@GLIBC_2.2.5, JUMP_SLOT

	result := make(map[string]bool)
	parseRela64(data, dynsyms, binary.LittleEndian, result)

	assert.True(t, result["recv"])
	assert.False(t, result["recv@GLIBC_2.2.5"])
}

func TestParseRela64_OutOfBounds(t *testing.T) {
	dynsyms := []elf.Symbol{
		{Name: "recv"},
	}

	// symIdx 5 is out of range (only 1 symbol)
	data := buildRela64Entry(5, 7)

	result := make(map[string]bool)
	parseRela64(data, dynsyms, binary.LittleEndian, result)

	assert.Empty(t, result)
}

func TestParseRela64_EmptyData(t *testing.T) {
	dynsyms := []elf.Symbol{{Name: "recv"}}
	result := make(map[string]bool)
	parseRela64(nil, dynsyms, binary.LittleEndian, result)
	assert.Empty(t, result)
}

func TestParseRela32_JumpSlot(t *testing.T) {
	dynsyms := []elf.Symbol{
		{Name: "accept"},   // index 0 → symIdx 1
		{Name: "recv"},     // index 1 → symIdx 2
		{Name: "send"},     // index 2 → symIdx 3
	}

	var data []byte
	data = append(data, buildRel32Entry(1, 7)...)  // accept, JMP_SLOT
	data = append(data, buildRel32Entry(2, 7)...)  // recv, JMP_SLOT
	data = append(data, buildRel32Entry(3, 5)...)  // send, NOT JMP_SLOT

	result := make(map[string]bool)
	parseRela32(data, dynsyms, binary.LittleEndian, result)

	assert.True(t, result["accept"])
	assert.True(t, result["recv"])
	assert.False(t, result["send"])
}

func TestParseRela32_VersionSuffix(t *testing.T) {
	dynsyms := []elf.Symbol{
		{Name: "send@GLIBC_2.0"},
	}

	data := buildRel32Entry(1, 7)

	result := make(map[string]bool)
	parseRela32(data, dynsyms, binary.LittleEndian, result)

	assert.True(t, result["send"])
	assert.False(t, result["send@GLIBC_2.0"])
}

func TestHttpServerDetection_Logic(t *testing.T) {
	// Test the detection logic inline: accept4 + recv + send = HttpServer
	// SSL_read + SSL_write = HttpServerTLS
	tests := []struct {
		name     string
		symbols  map[string]bool
		wantHTTP bool
		wantTLS  bool
	}{
		{
			name:     "all HTTP server symbols (accept4)",
			symbols:  map[string]bool{"accept4": true, "recv": true, "send": true},
			wantHTTP: true,
			wantTLS:  false,
		},
		{
			name:     "all HTTP server symbols (accept fallback)",
			symbols:  map[string]bool{"accept": true, "recv": true, "send": true},
			wantHTTP: true,
			wantTLS:  false,
		},
		{
			name:     "missing recv",
			symbols:  map[string]bool{"accept4": true, "send": true},
			wantHTTP: false,
			wantTLS:  false,
		},
		{
			name:     "missing send",
			symbols:  map[string]bool{"accept4": true, "recv": true},
			wantHTTP: false,
			wantTLS:  false,
		},
		{
			name:     "missing accept",
			symbols:  map[string]bool{"recv": true, "send": true},
			wantHTTP: false,
			wantTLS:  false,
		},
		{
			name:     "TLS symbols only",
			symbols:  map[string]bool{"SSL_read": true, "SSL_write": true},
			wantHTTP: false,
			wantTLS:  true,
		},
		{
			name:     "TLS missing SSL_write",
			symbols:  map[string]bool{"SSL_read": true},
			wantHTTP: false,
			wantTLS:  false,
		},
		{
			name: "full HTTP + TLS",
			symbols: map[string]bool{
				"accept4": true, "recv": true, "send": true,
				"SSL_read": true, "SSL_write": true,
			},
			wantHTTP: true,
			wantTLS:  true,
		},
		{
			name:     "empty symbols",
			symbols:  map[string]bool{},
			wantHTTP: false,
			wantTLS:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result DetectResult

			hasAccept := tt.symbols["accept4"] || tt.symbols["accept"]
			hasRecv := tt.symbols["recv"]
			hasSend := tt.symbols["send"]

			if hasAccept && hasRecv && hasSend {
				result |= HttpServerDetected
			}
			if tt.symbols["SSL_read"] && tt.symbols["SSL_write"] {
				result |= HttpServerTLSDetected
			}

			assert.Equal(t, tt.wantHTTP, result.HasHttpServer(), "HTTP server detection")
			assert.Equal(t, tt.wantTLS, result.HasHttpServerTLS(), "TLS detection")
		})
	}
}
