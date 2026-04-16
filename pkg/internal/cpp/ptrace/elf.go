// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ptrace // import "go.opentelemetry.io/obi/pkg/internal/cpp/ptrace"

import (
	"debug/elf"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// FindLibcBase scans /proc/<pid>/maps to find libc.so's base load address and
// the host-side file path. Returns the base virtual address, the path to the
// libc binary (accessible from the host), and any error.
func FindLibcBase(pid app.PID) (uintptr, string, error) {
	maps, err := procs.FindLibMaps(pid)
	if err != nil {
		return 0, "", fmt.Errorf("reading proc maps for pid %d: %w", pid, err)
	}

	return findLibcBaseFromMaps(pid, maps)
}

// findLibcBaseFromMaps extracts libc base address from an already loaded set of proc maps.
// We return the FIRST mapping (lowest address) of libc, which corresponds to
// the ELF load base.  This must NOT be filtered by execute permission because
// the first PT_LOAD segment is often read-only (r--p), while the executable
// segment (r-xp) is mapped at a higher address.
func findLibcBaseFromMaps(pid app.PID, maps []*procfs.ProcMap) (uintptr, string, error) {
	for _, m := range maps {
		if isLibc(m.Pathname) {
			hostPath := filepath.Join("/proc", strconv.Itoa(int(pid)), "root", m.Pathname)
			return uintptr(m.StartAddr), hostPath, nil
		}
	}
	return 0, "", fmt.Errorf("libc.so not found in /proc/%d/maps", pid)
}

// isLibc checks if a pathname corresponds to libc (glibc or musl).
func isLibc(pathname string) bool {
	base := filepath.Base(pathname)
	return strings.HasPrefix(base, "libc.so") ||
		strings.HasPrefix(base, "libc-") ||
		strings.HasPrefix(base, "ld-musl-")
}

// ResolveDynSymOffset parses the ELF .dynsym section of the given shared library
// and returns the offset (virtual address minus the base load address of the first
// PT_LOAD segment) of the named symbol.
func ResolveDynSymOffset(libPath string, symbolName string) (uintptr, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return 0, fmt.Errorf("opening ELF %s: %w", libPath, err)
	}
	defer f.Close()

	// Find the base virtual address (lowest PT_LOAD vaddr)
	var baseVAddr uint64
	foundLoad := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			if !foundLoad || prog.Vaddr < baseVAddr {
				baseVAddr = prog.Vaddr
				foundLoad = true
			}
		}
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("reading dynamic symbols from %s: %w", libPath, err)
	}

	for _, sym := range syms {
		if sym.Name == symbolName {
			// The offset is the symbol's virtual address minus the base load address
			offset := sym.Value - baseVAddr
			return uintptr(offset), nil
		}
	}

	return 0, fmt.Errorf("symbol %q not found in %s", symbolName, libPath)
}

// ResolveRuntimeAddr resolves the runtime virtual address of a symbol within
// libc.so loaded in the target process. It combines the base address from
// /proc/<pid>/maps with the symbol offset from the ELF binary.
func ResolveRuntimeAddr(pid app.PID, symbolName string) (uintptr, error) {
	base, hostPath, err := FindLibcBase(pid)
	if err != nil {
		return 0, err
	}

	offset, err := ResolveDynSymOffset(hostPath, symbolName)
	if err != nil {
		return 0, err
	}

	return base + offset, nil
}

// FindDlopenAddr resolves the runtime address of __libc_dlopen_mode in the
// target process. This is the internal glibc function used to dlopen shared
// libraries, which is always available in glibc-based systems.
func FindDlopenAddr(pid app.PID) (uintptr, error) {
	// Try __libc_dlopen_mode first (glibc internal)
	addr, err := ResolveRuntimeAddr(pid, "__libc_dlopen_mode")
	if err == nil {
		return addr, nil
	}

	// Fall back to dlopen (musl libc exports this directly)
	addr, err2 := ResolveRuntimeAddr(pid, "dlopen")
	if err2 == nil {
		return addr, nil
	}

	return 0, fmt.Errorf("neither __libc_dlopen_mode nor dlopen found: %w; %w", err, err2)
}
