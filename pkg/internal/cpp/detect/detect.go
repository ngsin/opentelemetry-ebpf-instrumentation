// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package detect // import "go.opentelemetry.io/obi/pkg/internal/cpp/detect"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// DetectResult is a bitmask of detected C/C++ libraries in a process.
type DetectResult uint32

const (
	// CurlDetected indicates libcurl.so was found in the process memory maps.
	CurlDetected DetectResult = 1 << iota
	// GRPCDetected indicates libgrpc.so or libgrpc++.so was found.
	GRPCDetected
	// HttpServerDetected indicates the process has accept4+recv+send GOT entries.
	HttpServerDetected
	// HttpServerTLSDetected indicates the process has SSL_read+SSL_write GOT entries.
	HttpServerTLSDetected
)

// HasCurl returns true if libcurl was detected.
func (d DetectResult) HasCurl() bool {
	return d&CurlDetected != 0
}

// HasGRPC returns true if gRPC was detected.
func (d DetectResult) HasGRPC() bool {
	return d&GRPCDetected != 0
}

// HasHttpServer returns true if HTTP server socket symbols were detected.
func (d DetectResult) HasHttpServer() bool {
	return d&HttpServerDetected != 0
}

// HasHttpServerTLS returns true if SSL_read/SSL_write were detected.
func (d DetectResult) HasHttpServerTLS() bool {
	return d&HttpServerTLSDetected != 0
}

// HasAny returns true if any supported library was detected.
func (d DetectResult) HasAny() bool {
	return d != 0
}

// libraryChecks defines the mapping from shared library names to detection flags.
var libraryChecks = []struct {
	name string
	flag DetectResult
}{
	{"libcurl.so", CurlDetected},
	{"libgrpc.so", GRPCDetected},
	{"libgrpc++.so", GRPCDetected},
}

// DetectLibraries scans /proc/<pid>/maps to identify supported C/C++ libraries
// loaded by the target process, and checks the ELF relocations for HTTP server
// socket symbols. Returns a bitmask of detected capabilities.
func DetectLibraries(pid app.PID) (DetectResult, error) {
	maps, err := procs.FindLibMaps(pid)
	if err != nil {
		return 0, err
	}

	result := detectFromMaps(maps)

	// Additionally check for HTTP server symbols via ELF relocation table
	httpResult := detectHttpServer(pid)
	result |= httpResult

	return result, nil
}

// detectFromMaps performs library detection on an already-loaded set of proc maps.
// Exported for testing.
func detectFromMaps(maps []*procfs.ProcMap) DetectResult {
	var result DetectResult

	for _, check := range libraryChecks {
		if procs.LibPath(check.name, maps) != nil {
			result |= check.flag
		}
	}

	return result
}

// detectHttpServer checks if the target process has GOT entries for socket
// functions that indicate it's an HTTP server (accept4+recv+send) and
// optionally an HTTPS server (SSL_read+SSL_write).
func detectHttpServer(pid app.PID) DetectResult {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	f, err := elf.Open(exePath)
	if err != nil {
		return 0
	}
	defer f.Close()

	// Scan .rela.plt for JUMP_SLOT relocations
	symbols := extractJumpSlotSymbols(f)
	if symbols == nil {
		return 0
	}

	var result DetectResult

	// Check for HTTP server: need accept4 (or accept) + recv + send
	hasAccept := symbols["accept4"] || symbols["accept"]
	hasRecv := symbols["recv"]
	hasSend := symbols["send"]

	if hasAccept && hasRecv && hasSend {
		result |= HttpServerDetected
	}

	// Check for TLS: need SSL_read + SSL_write
	if symbols["SSL_read"] && symbols["SSL_write"] {
		result |= HttpServerTLSDetected
	}

	return result
}

// extractJumpSlotSymbols returns a set of symbol names that have
// R_X86_64_JUMP_SLOT (or equivalent) relocations in the ELF binary.
func extractJumpSlotSymbols(f *elf.File) map[string]bool {
	result := make(map[string]bool)

	// Try .rela.plt first (most common on x86_64)
	for _, secName := range []string{".rela.plt", ".rel.plt", ".rela.dyn"} {
		sec := f.Section(secName)
		if sec == nil {
			continue
		}

		data, err := sec.Data()
		if err != nil {
			continue
		}

		// Get dynamic symbol table
		dynsyms, err := f.DynamicSymbols()
		if err != nil {
			return nil
		}

		// Parse relocations based on ELF class
		switch f.Class {
		case elf.ELFCLASS64:
			parseRela64(data, dynsyms, f.ByteOrder, result)
		case elf.ELFCLASS32:
			parseRela32(data, dynsyms, f.ByteOrder, result)
		}
	}

	return result
}

func parseRela64(data []byte, dynsyms []elf.Symbol, bo binary.ByteOrder, result map[string]bool) {
	const relaSize = 24 // sizeof(Elf64_Rela)
	for i := 0; i+relaSize <= len(data); i += relaSize {
		info := bo.Uint64(data[i+8 : i+16])
		relType := info & 0xffffffff
		symIdx := info >> 32

		// R_X86_64_JUMP_SLOT = 7
		if relType == 7 && symIdx > 0 && int(symIdx-1) < len(dynsyms) {
			name := dynsyms[symIdx-1].Name
			// Strip version suffix (e.g., "recv@GLIBC_2.2.5" → "recv")
			if idx := strings.Index(name, "@"); idx >= 0 {
				name = name[:idx]
			}
			result[name] = true
		}
	}
}

func parseRela32(data []byte, dynsyms []elf.Symbol, bo binary.ByteOrder, result map[string]bool) {
	const relSize = 8 // sizeof(Elf32_Rel)
	for i := 0; i+relSize <= len(data); i += relSize {
		info := bo.Uint32(data[i+4 : i+8])
		relType := info & 0xff
		symIdx := info >> 8

		// R_386_JMP_SLOT = 7
		if relType == 7 && symIdx > 0 && int(symIdx-1) < len(dynsyms) {
			name := dynsyms[symIdx-1].Name
			if idx := strings.Index(name, "@"); idx >= 0 {
				name = name[:idx]
			}
			result[name] = true
		}
	}
}

