# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a self-study learning repository for eBPF programming, structured as an 8-week curriculum based on the OpenTelemetry eBPF Instrumentation (OBI) project. The learner's background: Linux kernel concepts (familiar), C language (beginner), Go/Python (proficient), bpftrace/BCC tools (used before).

## Repository Structure

```
learning/
├── README.md           # Complete 8-week curriculum with daily tasks
├── PROGRESS.md         # Progress tracking (check current Week/Day status here)
├── exercises/          # Practice code organized by week/day
│   ├── week1-c-basics/     # C language fundamentals for eBPF
│   ├── week2-hello-ebpf/   # First eBPF program (kprobe)
│   ├── week3-maps/         # eBPF Maps and kernel-userspace communication
│   ├── week4-kprobes/      # Kernel function tracing
│   ├── week5-uprobes/      # Userspace function tracing
│   ├── week6-network/      # TC/XDP/Socket Filter
│   ├── week7-http-tracer/  # Comprehensive HTTP latency tracer project
│   └── week8-obi-deep-dive/ # OBI project architecture study
└── notes/              # Study notes and troubleshooting
```

## Building and Running

### C Exercise Files (Week 1)
```bash
gcc -o output exercises/week1-c-basics/dayN/filename.c && ./output
```

### eBPF Programs (Week 2+)
```bash
# Compile eBPF C to object file
clang -O2 -target bpf -c file.bpf.c -o file.bpf.o

# Quick verification with bpftrace (alternative to loading manually)
sudo bpftrace -e 'kprobe:sys_openat { printf("pid=%d\n", pid); }'

# View eBPF trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Go Userspace Programs
```bash
go run main.go
```

### Environment Setup (Ubuntu/Debian)
```bash
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r) bpftool linux-headers-$(uname -r)
go get github.com/cilium/ebpf
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

## Curriculum Context

The learning plan references the real OBI codebase for examples. Key OBI files mentioned:
- `bpf/generictracer/k_tracer.c` - Kernel tracing (kprobes)
- `bpf/gotracer/go_nethttp.c` - Go HTTP tracing (uprobes)
- `bpf/netolly/flows.c` - Network flow tracing (TC)
- `bpf/maps/` - eBPF Map definitions
- `bpf/common/ringbuf.h` - Event reporting to userspace

## Key Technical Concepts

- **Fixed-width types**: eBPF uses `u8/u16/u32/u64` (not `int/long`) for precise memory layout
- **PID/TID extraction**: `bpf_get_current_pid_tgid()` returns u64 with PID in high 32 bits
- **Memory safety**: Always use `__builtin_memcpy()`, never standard `memcpy`
- **Verifier compliance**: Bounded loops, stack limit 512 bytes, pointer bounds checks
- **SEC() macro**: Declares eBPF program type and attach point (e.g., `SEC("kprobe/tcp_sendmsg")`)

## Working with This Repository

1. Check `PROGRESS.md` to see current learning status and next task
2. Each exercise file contains inline comments explaining the concept
3. Files reference specific OBI source files for real-world examples
4. Week 7 builds a complete HTTP latency tracer as a capstone project
