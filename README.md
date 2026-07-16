# FuseViz — Real-Time FUSE Filesystem Observability Dashboard

A production-grade observability platform for FUSE (Filesystem in Userspace) filesystems. Captures actual FUSE protocol events at the kernel level using eBPF, enriches them with process metadata, detects security threats, and displays everything in a real-time web dashboard.

## How It Works

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────┐    ┌───────────┐
│  FUSE Mount  │───▶│ Kernel FUSE  │───▶│  eBPF fexit │───▶│ C++20    │───▶│ Next.js   │
│  (any app)   │    │  dev layer   │    │  probes     │    │ daemon   │    │ dashboard │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────┘    └───────────┘
                                                                  │
                                                           ┌──────┴──────┐
                                                           │   SQLite    │
                                                           │   Ollama    │
                                                           └─────────────┘
```

The system hooks two kernel functions via eBPF `fexit` programs:

- **`fuse_dev_read`** — captures FUSE requests (opcode, nodeid, unique ID, caller credentials). For `FUSE_WRITE` requests, also captures the first 128 bytes of the write payload.
- **`fuse_dev_write`** — currently skipped (response headers lack opcode/nodeid; the read handler already captures all requests with real opcodes).

Events flow through a lock-free pipeline:

```
eBPF ring buffer → SPSC queue → Enricher (PID→process name) → SPSC queue →
  ├── WebSocket broadcaster (real-time to browser)
  ├── SQLite WAL batch writer (persistence)
  └── Security engine (threat detection + Ollama LLM)
```

## Features

- **Real FUSE tracing** — Not simulation. Captures actual FUSE protocol events from any mounted FUSE filesystem via eBPF.
- **All opcodes decoded** — Every FUSE operation shows its real name (READ, WRITE, LOOKUP, OPEN, etc.), no UNKNOWN events.
- **Write payload capture** — FUSE_WRITE events include the first 128 bytes of written data (text and base64), viewable in the event detail panel.
- **Real-time WebSocket streaming** — Sub-millisecond event delivery to the browser.
- **Threat detection** — Sliding-window heuristic engine detects ransomware patterns, data exfiltration, and anomalous behavior.
- **Ollama LLM integration** — Optional AI-powered threat analysis using local LLM models.
- **Process enrichment** — Automatically resolves PID to process name via `/proc/<pid>/comm`.
- **SQLite WAL persistence** — All events and alerts stored with write-ahead logging for concurrent reads.
- **Lock-free pipeline** — SPSC queues between stages minimize latency; no mutex contention on the hot path.

## Prerequisites

- **Kernel**: Linux 5.4+ with BPF support (tested on 6.17)
- **System packages**: `clang`, `llvm`, `libbpf-dev`, `libfuse3-dev`, `libsqlite3-dev`, `libssl-dev`, `nlohmann-json3-dev`, `cmake`, `g++`
- **Node.js**: 18+
- **Optional**: Ollama running locally for AI threat analysis

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libfuse3-dev libsqlite3-dev \
  libssl-dev nlohmann-json3-dev cmake g++ linux-headers-$(uname -r)
```

## Quick Start

### 1. Build the eBPF program

```bash
cd fuse-proto-viz/ebpf
make
sudo mkdir -p /opt/fuseviz/ebpf
sudo cp fuse_trace.bpf.o /opt/fuseviz/ebpf/
```

### 2. Build the C++ daemon

```bash
cd fuse-proto-viz/daemon
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### 3. Build the frontend

```bash
npm install
npm run build
```

### 4. Start everything

```bash
# Start the daemon (requires root for eBPF)
bash backend.sh

# In another terminal, start the frontend
npm run dev
```

Open `http://localhost:3000` in your browser.

## Backend Launcher

The `backend.sh` script handles the full lifecycle:

```bash
bash backend.sh
```

This will:
1. Check that the daemon binary and BPF object exist
2. Kill any existing daemon instance
3. Clean the old database
4. Configure kernel parameters for eBPF
5. Start the daemon with `sudo` (required for eBPF)
6. Report eBPF vs simulation mode status

## Testing with a FUSE Filesystem

To see events, you need a writable FUSE mount. Options:

### Option A: Compile the included test filesystem

```bash
cd fuse-proto-viz/ebpf
gcc -Wall /usr/share/doc/libfuse3-dev/examples/hello.c \
  $(pkg-config fuse3 --cflags --libs) -o /tmp/hello_fuse
mkdir -p /tmp/fuseviz_test
/tmp/hello_fuse /tmp/fuseviz_test
```

### Option B: Use the included writable test FUSE

```bash
# Compiled from fuse-proto-viz/test-fuse/
gcc -Wall fuse_test_write.c $(pkg-config fuse3 --cflags --libs) -o /tmp/fuse_test_write
mkdir -p /tmp/fuseviz_test
/tmp/fuse_test_write /tmp/fuseviz_test
```

### Option C: Use sshfs, gocryptfs, or any FUSE filesystem

```bash
# Example with sshfs
sshfs remotehost:/path /mnt/remote
# All FUSE operations on /mnt/remote will be captured
```

### Generate test events

```bash
echo "Hello from FuseViz!" > /tmp/fuseviz_test/testfile.txt
cat /tmp/fuseviz_test/testfile.txt
```

You should see READ, WRITE, OPEN, LOOKUP, RELEASE events appear in the dashboard.

## Architecture

### eBPF Layer (`fuse-proto-viz/ebpf/`)

| File | Purpose |
|------|---------|
| `fuse_trace.bpf.c` | eBPF fexit programs that hook `fuse_dev_read` and `fuse_dev_write` |
| `fuse_trace.h` | Shared binary contract between eBPF and C++ daemon |
| `vmlinux.h` | Kernel BTF types (auto-generated from running kernel) |

The eBPF program reads the `fuse_in_header` from the iov_iter at function return, extracting opcode, nodeid, and unique ID. For FUSE_WRITE requests, it also captures up to 128 bytes of the write payload by reading past the `fuse_write_in` struct.

### C++ Daemon (`fuse-proto-viz/daemon/`)

| Component | File | Purpose |
|-----------|------|---------|
| Orchestrator | `src/main.cpp` | Launches all pipeline threads, signal handling |
| BPF Loader | `src/bpf_loader.cpp` | Loads BPF object, attaches programs, polls ring buffer |
| Enricher | `src/enricher.cpp` | Resolves PID to process name via `/proc` |
| WebSocket | `src/ws_broadcaster.cpp` | Custom WebSocket server with RFC 6455 handshake |
| Storage | `src/storage.cpp` | SQLite WAL batch writer |
| Security | `src/security_engine.cpp` | Threat heuristic engine + Ollama integration |
| Queue | `include/spsc_queue.h` | Lock-free SPSC and MPMC queues |

### Frontend (`src/`)

| Component | File | Purpose |
|-----------|------|---------|
| WebSocket hook | `lib/fuse-context.tsx` | Connection management, reconnection, event buffering |
| Event log | `components/fuseviz/event-log-panel.tsx` | Live event stream with opcode sidebar |
| Detail panel | `components/fuseviz/right-panel.tsx` | Event inspection, write payload display, threat alerts |
| Charts | `components/fuseviz/metrics-charts.tsx` | Throughput, latency, opcode distribution |
| Sequence | `components/fuseviz/sequence-diagram.tsx` | SVG request/response flow diagram |
| Top bar | `components/fuseviz/top-bar.tsx` | Status indicators, connection state |

## Configuration

### Frontend

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_WS_TOKEN` | `fuseviz-dev-key` | WebSocket auth token |

Set in `.env`:

```
NEXT_PUBLIC_WS_TOKEN=fuseviz-dev-key
```

### Daemon

Configured via environment variables (set in `backend.sh`):

| Variable | Default | Description |
|----------|---------|-------------|
| `FUSEVIZ_BPF_OBJ` | `/opt/fuseviz/ebpf/fuse_trace.bpf.o` | Path to compiled BPF object |
| `FUSEVIZ_DB_PATH` | `./events.db` | SQLite database path |
| `FUSEVIZ_LISTEN_PORT` | `8080` | WebSocket server port |
| `FUSEVIZ_OLLAMA_URL` | `http://localhost:11434` | Ollama API URL |
| `FUSEVIZ_OLLAMA_MODEL` | `llama3` | LLM model for threat analysis |
| `FUSEVIZ_WS_SECRET` | `fuseviz-dev-key` | WebSocket auth token |

## FUSE Opcodes

| Code | Name | Description |
|------|------|-------------|
| 1 | LOOKUP | Look up a directory entry |
| 3 | GETATTR | Get file attributes |
| 4 | SETATTR | Set file attributes |
| 8 | MKNOD | Create a file node |
| 9 | MKDIR | Create a directory |
| 10 | UNLINK | Remove a file |
| 14 | OPEN | Open a file |
| 15 | READ | Read from a file |
| 16 | WRITE | Write to a file (payload captured) |
| 18 | RELEASE | Close a file |
| 20 | FSYNC | Sync file data |
| 25 | FLUSH | Flush pending writes |
| 27 | OPENDIR | Open a directory |
| 28 | READDIR | Read directory entries |
| 29 | RELEASEDIR | Close a directory |
| 35 | CREATE | Create and open a file |

## Docker Deployment

```bash
cd fuse-proto-viz/deploy
docker compose up --build
```

The Docker setup uses a multi-stage build:
1. **Stage 1**: Compile eBPF programs (requires `bpf` build target)
2. **Stage 2**: Build C++ daemon with libbpf
3. **Stage 3**: Build Next.js frontend
4. **Stage 4**: Runtime image with all components

## Troubleshooting

### "Undersized event" errors

The BPF object and daemon binary are out of sync. Rebuild both:

```bash
cd fuse-proto-viz/ebpf && make
sudo cp fuse_trace.bpf.o /opt/fuseviz/ebpf/
cd ../daemon/build && cmake --build .
```

### No events appearing

1. Check the daemon is running: `ps aux | grep fuseviz-daemon`
2. Check the log: `cat /tmp/fuseviz-daemon.log`
3. Verify eBPF loaded: look for `[BPF] Attached fexit/fuse_dev_read`
4. Ensure a FUSE mount exists: `mount | grep fuse`
5. Generate traffic on the FUSE mount: `echo test > /mnt/fuse/testfile`

### WebSocket connection drops

The frontend auto-reconnects with exponential backoff (1s → 10s max). Check:
- Daemon is listening on port 8080
- No firewall blocking the connection
- Browser console for validation errors

### eBPF fails to load

- Ensure kernel supports BPF: `ls /sys/kernel/btf/vmlinux`
- Check `perf_event_paranoid`: `sysctl kernel.perf_event_paranoid` (should be ≤ 1)
- Verify BPF object exists: `ls -la /opt/fuseviz/ebpf/fuse_trace.bpf.o`

## Project Structure

```
fuseviz-project/
├── backend.sh                    # One-command daemon launcher
├── fuse-proto-viz/
│   ├── ebpf/                     # eBPF kernel programs
│   │   ├── fuse_trace.bpf.c      # fexit hooks for fuse_dev_read/write
│   │   ├── fuse_trace.h          # Shared event struct (eBPF ↔ C++)
│   │   ├── vmlinux.h             # Kernel BTF types
│   │   └── Makefile              # BPF compilation
│   ├── daemon/                   # C++20 pipeline daemon
│   │   ├── include/              # Headers (types, queues, loaders)
│   │   ├── src/                  # Implementation
│   │   └── CMakeLists.txt        # Build configuration
│   ├── deploy/                   # Docker deployment
│   │   ├── Dockerfile            # Multi-stage build
│   │   ├── docker-compose.yml    # Container orchestration
│   │   └── fuseviz.conf          # Daemon configuration
│   └── docs/                     # Architecture documentation
├── src/                          # Next.js frontend
│   ├── app/                      # Pages and layout
│   ├── components/fuseviz/       # Dashboard components
│   └── lib/                      # Types, schemas, WebSocket hook
├── .env.example                  # Environment template
├── TESTPLAN.md                   # Comprehensive test plan
└── CONTRIBUTING.md               # Contribution guidelines
```

## License

MIT
