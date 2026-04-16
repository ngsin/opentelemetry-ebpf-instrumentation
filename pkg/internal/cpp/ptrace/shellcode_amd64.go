// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package ptrace // import "go.opentelemetry.io/obi/pkg/internal/cpp/ptrace"

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

const (
	// RTLD_NOW | RTLD_LOCAL for dlopen flags
	rtldNow   = 0x2
	rtldLocal = 0x0
	dlopenFlags = rtldNow | rtldLocal
)

// BuildShellcode generates x86_64 shellcode that calls dlopen(path, RTLD_NOW|RTLD_LOCAL)
// and then triggers a SIGTRAP (int3) so the injector can regain control.
//
// The shellcode expects:
//   - pathAddr: address where the agent path string is stored in the target's memory
//   - dlopenAddr: runtime address of __libc_dlopen_mode or dlopen in the target
//
// After execution, RAX will contain the dlopen return value (handle or NULL).
func BuildShellcode(pathAddr, dlopenAddr uintptr) []byte {
	// x86_64 shellcode:
	//   movabs rdi, <pathAddr>        ; arg1 = path string
	//   movabs rsi, <dlopenFlags>     ; arg2 = RTLD_NOW | RTLD_LOCAL
	//   movabs rax, <dlopenAddr>      ; function to call
	//   call   rax                    ; dlopen(path, flags)
	//   int3                          ; SIGTRAP - hand control back to tracer
	//   nop                           ; padding
	var code []byte

	// movabs rdi, pathAddr (48 BF <8 bytes>)
	code = append(code, 0x48, 0xBF)
	code = appendUint64(code, uint64(pathAddr))

	// movabs rsi, dlopenFlags (48 BE <8 bytes>)
	code = append(code, 0x48, 0xBE)
	code = appendUint64(code, uint64(dlopenFlags))

	// movabs rax, dlopenAddr (48 B8 <8 bytes>)
	code = append(code, 0x48, 0xB8)
	code = appendUint64(code, uint64(dlopenAddr))

	// call rax (FF D0)
	code = append(code, 0xFF, 0xD0)

	// int3 (CC)
	code = append(code, 0xCC)

	// nop padding (90)
	code = append(code, 0x90)

	return code
}

// ShellcodeSize returns the expected size of the generated shellcode.
func ShellcodeSize() int {
	// 3 x movabs (10 bytes each) + call rax (2) + int3 (1) + nop (1) = 34
	return 34
}

func appendUint64(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

// WriteBytes writes arbitrary bytes to the target process memory via /proc/<pid>/mem.
// This is more reliable than PTRACE_POKEDATA in containerized environments and
// avoids word-alignment issues.  The target process must be ptrace-stopped.
func WriteBytes(pid int, addr uintptr, data []byte) error {
	memPath := filepath.Join("/proc", strconv.Itoa(pid), "mem")
	f, err := os.OpenFile(memPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("opening %s for write: %w", memPath, err)
	}
	defer f.Close()

	n, err := f.WriteAt(data, int64(addr))
	if err != nil {
		return fmt.Errorf("writing %d bytes at %#x via /proc/%d/mem: %w", len(data), addr, pid, err)
	}
	if n != len(data) {
		return fmt.Errorf("short write at %#x: wrote %d of %d bytes", addr, n, len(data))
	}
	return nil
}

// WriteString writes a null-terminated string to the target process memory.
func WriteString(pid int, addr uintptr, s string) error {
	// Append null terminator
	data := append([]byte(s), 0)
	return WriteBytes(pid, addr, data)
}

// ReadWord reads a single machine word from the target process memory via PTRACE_PEEKDATA.
func ReadWord(pid int, addr uintptr) (uintptr, error) {
	var buf [8]byte
	n, err := syscall.PtracePeekData(pid, addr, buf[:])
	if err != nil {
		return 0, fmt.Errorf("PTRACE_PEEKDATA at %#x: %w", addr, err)
	}
	if n != 8 {
		return 0, fmt.Errorf("PTRACE_PEEKDATA at %#x: short read %d bytes", addr, n)
	}
	return uintptr(binary.LittleEndian.Uint64(buf[:])), nil
}
