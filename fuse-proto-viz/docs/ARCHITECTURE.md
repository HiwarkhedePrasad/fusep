# ARCHITECTURE — FuseViz Enterprise v2.0 (C++20)

## System Overview

FuseViz is an enterprise-grade FUSE filesystem protocol observability platform built with a C++20 backend for ultra-low-latency, systems-grade performance. The architecture spans five layers, from kernel-space eBPF kprobes through to a real-time React dashboard with AI-powered threat detection.

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 4: OBSERVABILITY UI                     │
│           React + Tailwind + Recharts + WebSocket               │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────┐  │
│   │ Event Log│ │Sequence  │ │Metrics   │ │Threat Intel     │  │
│   │ (Virtual │ │Diagram  │ │(P50/P90/ │ │Center (AI       │  │
│   │  Scroll) │ │(Live SVG)│ │ P99 + HW)│ │  Reports)       │  │
│   └──────────┘ └──────────┘ └──────────┘ └─────────────────┘  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ WebSocket (100ms batched flush)
┌───────────────────────┴─────────────────────────────────────────┐
│                  LAYER 3: SECURITY & INTELLIGENCE                │
│              C++20 + Ollama (Llama3 / Mistral)                   │
│   ┌──────────────────┐  ┌────────────────────────────────────┐ │
│   │ Sliding-Window   │  │ Agentic AI Supervisor              │ │
│   │ State Machine    │──│ (cpp-httplib → Ollama POST)        │ │
│   │ • std::deque per │  │ • Construct JSON threat payload    │ │
│   │   PID, 3s window │  │ • Autonomous evaluation → uWS     │ │
│   │ • Ransomware:    │  └────────────────────────────────────┘ │
│   │   100+ ops in 3s │                                        │
│   │ • Exfiltration:  │                                        │
│   │   200+ reads     │                                        │
│   └──────────────────┘                                        │
└───────────────────────┬─────────────────────────────────────────┘
                        │
┌───────────────────────┴─────────────────────────────────────────┐
│                 LAYER 2: C++20 SYSTEMS DAEMON                    │
│                                                                  │
│   ┌────────────┐  ┌────────────┐  ┌────────────┐               │
│   │ Ring Buffer │  │ Metadata   │  │ SQLite3    │               │
│   │ Poller     │──│ Enricher   │──│ WAL Batch  │               │
│   │ (libbpf)   │  │ (/proc +   │  │ Writer     │               │
│   │            │  │  unordered │  │ (500/batch)│               │
│   │ SPSC Queue │  │  _map cache│  │            │               │
│   └────────────┘  └────────────┘  └────────────┘               │
│          │                                     │                 │
│          ▼                                     ▼                 │
│   ┌────────────────────────────────────────────────────────┐   │
│   │ uWebSockets Broadcaster (nlohmann/json serialization)  │   │
│   │ JWT/API Key auth → fan-out to all connected clients    │   │
│   └────────────────────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────────────────────┘
                        │ bpf_ringbuf (lock-free, zero-copy)
┌───────────────────────┴─────────────────────────────────────────┐
│                 LAYER 1: eBPF KERNEL ENGINE (C)                  │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │  kprobe Hooks:                                            │  │
│   │  kprobe/fuse_dev_read   → FUSE request (in_header)      │  │
│   │  kprobe/fuse_dev_write  → FUSE response (out_header)    │  │
│   │                                                            │  │
│   │  Extracts: opcode, unique, nodeid, pid, uid, gid         │  │
│   │  Latency: Correlates read↔write by unique ID             │  │
│   │  Output:  bpf_ringbuf → packed fuse_trace_event structs  │  │
│   └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **C++20 over Go** | Direct access to libbpf, no GC pauses, zero-allocation parsing, predictable latency |
| **kprobe over tracepoint** | Hooks into kernel fuse_dev_* functions directly — deeper visibility than syscall tracepoints |
| **SPSC lock-free queue** | Zero-contention between producer (ring buffer poller) and consumer (enricher) |
| **libbpf over cilium/ebpf** | Native C API — no CGO overhead, no Go runtime between kernel and userspace |
| **uWebSockets** | Fastest C++ WebSocket library — handles 100K+ connections with minimal CPU |
| **nlohmann/json** | Industry-standard C++ JSON — compile-time type safety, fast serialization |
| **cpp-httplib** | Header-only HTTP client — zero-dependency Ollama integration |
| **std::deque sliding window** | O(1) push/pop at both ends, automatic eviction of stale entries |
| **Shared C struct header** | Binary contract between eBPF and C++ — no serialization, no parsing, cast directly |
| **SQLite WAL batch commits** | 500 events per transaction — amortizes fsync cost, 10K+ writes/sec |

## Memory Layout (Zero-Copy Pipeline)

```
Kernel eBPF → bpf_ringbuf → C++ cast* → SPSC queue → enrich → broadcast
                (zero-copy)  (no alloc)  (lock-free)   (cached)  (JSON)
```

The `fuse_trace_event` struct is defined once in `fuse_trace.h` and included by both the eBPF kernel program and the C++ userspace daemon. The ring buffer poller casts raw byte pointers directly to `const fuse_trace_event*` — no deserialization, no allocation.
