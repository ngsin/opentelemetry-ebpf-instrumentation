// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package ptrace // import "go.opentelemetry.io/obi/pkg/internal/cpp/ptrace"

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	// mmapSize is the size of the RWX region we allocate in the target
	// process for the shellcode + path string.  One page is plenty.
	mmapSize = 4096

	// x86_64 syscall numbers
	sysNoMmap   = 9
	sysNoMunmap = 11
)

// Inject performs the full ptrace injection sequence to load a shared library
// into the target process via dlopen. The sequence is:
//  1. Enumerate all threads, attach to all of them
//  2. Save registers on the main thread
//  3. Use ptrace to execute mmap() syscall in the target → get RWX page
//  4. Write agent path string + shellcode into the RWX page
//  5. Redirect RIP to shellcode, execute it
//  6. Wait for SIGTRAP (int3), verify RAX (dlopen result)
//  7. Use ptrace to execute munmap() to free the RWX page
//  8. Restore registers, detach all threads
//
// On any failure, registers are restored before detaching.
func Inject(pid int, agentPath string, dlopenAddr uintptr) error {
	// Pin this goroutine to the current OS thread for the entire ptrace
	// sequence.  Linux ptrace requires that all operations on a tracee
	// (attach, getregs, setregs, singlestep, cont, detach) originate from
	// the same tracer thread.  Without this, Go's scheduler may migrate
	// the goroutine mid-sequence, causing ESRCH and leaving the target
	// stuck in tracing-stop.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log := slog.With("component", "cpp.ptrace.Inject", "pid", pid)

	// Step 1: Enumerate and attach all threads
	tids, err := enumerateTIDs(pid)
	if err != nil {
		return fmt.Errorf("enumerating threads for pid %d: %w", pid, err)
	}

	attached := make([]int, 0, len(tids))
	defer func() {
		for _, tid := range attached {
			detachThread(tid)
		}
	}()

	for _, tid := range tids {
		if err := attachThread(tid); err != nil {
			return fmt.Errorf("attaching to tid %d: %w", tid, err)
		}
		attached = append(attached, tid)
	}

	log.Debug("attached to all threads", "count", len(attached))

	// Step 2: Save registers on main thread
	var origRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &origRegs); err != nil {
		return fmt.Errorf("PTRACE_GETREGS for pid %d: %w", pid, err)
	}

	log.Debug("original registers",
		"rip", fmt.Sprintf("%#x", origRegs.Rip),
		"rsp", fmt.Sprintf("%#x", origRegs.Rsp),
		"dlopenAddr", fmt.Sprintf("%#x", dlopenAddr),
		"agentPath", agentPath)

	// Find a 'syscall' instruction in the target process (we need it for
	// mmap/munmap).  The vDSO always contains one.
	syscallAddr, err := findSyscallInstruction(pid)
	if err != nil {
		return fmt.Errorf("finding syscall instruction in pid %d: %w", pid, err)
	}
	log.Debug("found syscall instruction", "addr", fmt.Sprintf("%#x", syscallAddr))

	// Step 3: Allocate an RWX page in the target via mmap syscall.
	rxPage, err := remoteMmap(pid, &origRegs, syscallAddr, mmapSize)
	if err != nil {
		return fmt.Errorf("remote mmap in pid %d: %w", pid, err)
	}
	log.Debug("allocated RWX page", "addr", fmt.Sprintf("%#x", rxPage))

	// Step 4: Write agent path + shellcode into the RWX page.
	pathAddr := rxPage
	shellcodeAddr := pathAddr + uintptr(len(agentPath)) + 1 // +1 null terminator
	shellcodeAddr = (shellcodeAddr + 7) &^ 7                // align to 8

	if err := WriteString(pid, pathAddr, agentPath); err != nil {
		remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)
		return fmt.Errorf("writing agent path: %w", err)
	}

	shellcode := BuildShellcode(pathAddr, dlopenAddr)
	if err := WriteBytes(pid, shellcodeAddr, shellcode); err != nil {
		remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)
		return fmt.Errorf("writing shellcode: %w", err)
	}

	// Step 5: Set RIP to shellcode and execute
	var modRegs syscall.PtraceRegs
	modRegs = origRegs
	modRegs.Rip = uint64(shellcodeAddr)
	// RSP must be 16-byte aligned before 'call' (x86_64 ABI).
	// Use the original RSP (which should already be aligned in a normal frame).
	modRegs.Rsp = origRegs.Rsp &^ 0xF
	// Prevent the kernel from restarting a pending syscall.
	modRegs.Orig_rax = ^uint64(0) // -1

	if err := syscall.PtraceSetRegs(pid, &modRegs); err != nil {
		remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)
		return fmt.Errorf("PTRACE_SETREGS for pid %d: %w", pid, err)
	}

	if err := syscall.PtraceCont(pid, 0); err != nil {
		remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)
		return fmt.Errorf("PTRACE_CONT for pid %d: %w", pid, err)
	}

	// Step 6: Wait for SIGTRAP (the int3 after dlopen returns)
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		restoreRegsAndDetach(pid, &origRegs)
		return fmt.Errorf("waiting for SIGTRAP from pid %d: %w", pid, err)
	}

	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP {
		var crashRegs syscall.PtraceRegs
		if err := syscall.PtraceGetRegs(pid, &crashRegs); err == nil {
			log.Warn("crash registers",
				"rip", fmt.Sprintf("%#x", crashRegs.Rip),
				"rsp", fmt.Sprintf("%#x", crashRegs.Rsp),
				"rax", fmt.Sprintf("%#x", crashRegs.Rax),
				"signal", ws.StopSignal())
		}
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)
		return fmt.Errorf("expected SIGTRAP from pid %d, got status %v", pid, ws)
	}

	// Check RAX for dlopen result
	var resultRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &resultRegs); err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)
		return fmt.Errorf("reading result registers: %w", err)
	}

	dlopenResult := resultRegs.Rax
	log.Debug("dlopen returned", "result", fmt.Sprintf("%#x", dlopenResult))

	// Step 7: Restore original registers
	if err := syscall.PtraceSetRegs(pid, &origRegs); err != nil {
		log.Warn("failed to restore registers", "error", err)
	}

	// Free the RWX page (best effort)
	remoteMunmap(pid, &origRegs, syscallAddr, rxPage, mmapSize)

	if dlopenResult == 0 {
		return fmt.Errorf("dlopen failed in target process pid %d (returned NULL); agent path: %s", pid, agentPath)
	}

	log.Info("successfully injected agent", "agent", agentPath, "handle", fmt.Sprintf("%#x", dlopenResult))
	return nil
}

// remoteSyscall executes a single syscall in the target process by:
//  1. Setting registers: RAX=syscall_nr, RDI/RSI/RDX/R10/R8/R9 = args
//  2. Setting RIP to a known 'syscall' instruction in the target
//  3. PTRACE_SINGLESTEP to execute exactly the syscall instruction
//  4. Reading RAX for the return value
//  5. Restoring original registers
func remoteSyscall(pid int, origRegs *syscall.PtraceRegs, syscallAddr uintptr,
	nr uint64, a1, a2, a3, a4, a5, a6 uint64) (uint64, error) {

	var regs syscall.PtraceRegs
	regs = *origRegs
	regs.Rax = nr
	regs.Rdi = a1
	regs.Rsi = a2
	regs.Rdx = a3
	regs.R10 = a4
	regs.R8 = a5
	regs.R9 = a6
	regs.Rip = uint64(syscallAddr)
	regs.Orig_rax = ^uint64(0)

	if err := syscall.PtraceSetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("set regs for syscall: %w", err)
	}

	// SINGLESTEP executes the syscall instruction and stops after it returns.
	if err := syscall.PtraceSingleStep(pid); err != nil {
		return 0, fmt.Errorf("singlestep syscall: %w", err)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("wait after syscall: %w", err)
	}

	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP {
		return 0, fmt.Errorf("unexpected status after syscall: %v", ws)
	}

	// Read the result
	var result syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &result); err != nil {
		return 0, fmt.Errorf("get regs after syscall: %w", err)
	}

	// Restore original registers
	if err := syscall.PtraceSetRegs(pid, origRegs); err != nil {
		return 0, fmt.Errorf("restore regs after syscall: %w", err)
	}

	return result.Rax, nil
}

// remoteMmap allocates an RWX page in the target process via the mmap syscall.
func remoteMmap(pid int, origRegs *syscall.PtraceRegs, syscallAddr uintptr, size int) (uintptr, error) {
	ret, err := remoteSyscall(pid, origRegs, syscallAddr,
		sysNoMmap,                                                       // __NR_mmap
		0,                                                               // addr = NULL (let kernel choose)
		uint64(size),                                                    // length
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,         // prot = RWX
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,                       // flags
		^uint64(0),                                                      // fd = -1
		0,                                                               // offset = 0
	)
	if err != nil {
		return 0, err
	}

	// Check for mmap error (returns -errno on failure)
	if int64(ret) < 0 && int64(ret) >= -4096 {
		return 0, fmt.Errorf("mmap failed with errno %d", -int64(ret))
	}

	return uintptr(ret), nil
}

// remoteMunmap frees a page in the target process via the munmap syscall.
func remoteMunmap(pid int, origRegs *syscall.PtraceRegs, syscallAddr uintptr, addr uintptr, size int) {
	_, _ = remoteSyscall(pid, origRegs, syscallAddr,
		sysNoMunmap,    // __NR_munmap
		uint64(addr),   // addr
		uint64(size),   // length
		0, 0, 0, 0,
	)
}

// execRegion represents a parsed executable memory mapping.
type execRegion struct {
	start uint64
	end   uint64
	name  string
}

// findSyscallInstruction scans the target process's executable memory mappings
// to locate a 'syscall' instruction (bytes 0F 05).  The vDSO is searched first
// since it's present in every process and always contains syscall instructions.
// Uses /proc/<pid>/mem for bulk reads (much faster and more reliable than
// per-word PTRACE_PEEKDATA, especially in containerized environments).
func findSyscallInstruction(pid int) (uintptr, error) {
	mapsPath := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", mapsPath, err)
	}

	// Collect all executable regions, prioritizing [vdso]
	var vdso []execRegion
	var others []execRegion

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		perms := fields[1]
		if len(perms) < 4 || perms[2] != 'x' {
			continue // not executable
		}

		parts := strings.Split(fields[0], "-")
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(parts[0], 16, 64)
		end, err2 := strconv.ParseUint(parts[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}

		name := ""
		if len(fields) >= 6 {
			name = fields[5]
		}

		region := execRegion{start: start, end: end, name: name}
		if name == "[vdso]" {
			vdso = append(vdso, region)
		} else {
			others = append(others, region)
		}
	}

	// Search vDSO first, then other executable regions
	regions := append(vdso, others...)

	// Open /proc/<pid>/mem for bulk memory reads.  This is more reliable than
	// PTRACE_PEEKDATA in containerised environments and orders of magnitude
	// faster for scanning multi-page regions.
	memPath := filepath.Join("/proc", strconv.Itoa(pid), "mem")
	memFile, err := os.Open(memPath)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", memPath, err)
	}
	defer memFile.Close()

	for _, region := range regions {
		size := region.end - region.start
		if size < 2 || size > 64*1024*1024 { // sanity: skip regions > 64MB
			continue
		}

		buf := make([]byte, size)
		n, err := memFile.ReadAt(buf, int64(region.start))
		if err != nil && n == 0 {
			slog.Debug("cannot read region", "name", region.name,
				"start", fmt.Sprintf("%#x", region.start), "error", err)
			continue // skip unreadable region
		}
		buf = buf[:n]

		// Scan for 'syscall' (0x0F 0x05)
		for i := 0; i < len(buf)-1; i++ {
			if buf[i] == 0x0F && buf[i+1] == 0x05 {
				return uintptr(region.start) + uintptr(i), nil
			}
		}
	}

	return 0, fmt.Errorf("no 'syscall' instruction found in executable mappings of pid %d", pid)
}

// enumerateTIDs returns all thread IDs for a given process.
func enumerateTIDs(pid int) ([]int, error) {
	taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", taskDir, err)
	}

	tids := make([]int, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.TrimSpace(name) == "" {
			continue
		}
		tid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		tids = append(tids, tid)
	}

	if len(tids) == 0 {
		return nil, fmt.Errorf("no threads found for pid %d", pid)
	}

	return tids, nil
}

// attachThread attaches to a thread and waits for it to stop.
func attachThread(tid int) error {
	if err := syscall.PtraceAttach(tid); err != nil {
		return fmt.Errorf("PTRACE_ATTACH tid %d: %w", tid, err)
	}

	var ws syscall.WaitStatus
	_, err := syscall.Wait4(tid, &ws, 0, nil)
	if err != nil {
		return fmt.Errorf("waiting for tid %d after attach: %w", tid, err)
	}

	if !ws.Stopped() {
		return fmt.Errorf("tid %d not stopped after attach, status: %v", tid, ws)
	}

	return nil
}

// detachThread detaches from a thread, continuing it with no signal.
func detachThread(tid int) {
	if err := syscall.PtraceDetach(tid); err != nil {
		slog.Warn("failed to detach from thread", "tid", tid, "error", err)
	}
}

// restoreRegsAndDetach attempts to restore registers before detaching.
func restoreRegsAndDetach(pid int, origRegs *syscall.PtraceRegs) {
	_ = syscall.PtraceSetRegs(pid, origRegs)
}
