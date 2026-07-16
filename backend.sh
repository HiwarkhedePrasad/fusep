#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  FuseViz Backend Launcher (eBPF + C++20 Daemon)
#
#  - Kills any existing daemon
#  - Configures kernel for eBPF
#  - Starts daemon with sudo (required for kprobes)
# ═══════════════════════════════════════════════════════════════════════

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
DAEMON_BIN="$ROOT/fuse-proto-viz/daemon/build/fuseviz-daemon"
BPF_OBJ="/opt/fuseviz/ebpf/fuse_trace.bpf.o"
DB_PATH="$ROOT/fuse-proto-viz/daemon/events.db"
LOG="/tmp/fuseviz-daemon.log"

echo ""
echo " ╔═══════════════════════════════════════════════════════╗"
echo " ║           FuseViz C++20 Backend Launcher             ║"
echo " ╚═══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Check daemon binary exists ──
if [ ! -f "$DAEMON_BIN" ]; then
    echo "[ERROR] Daemon binary not found at: $DAEMON_BIN"
    echo "        Build it first: cd fuse-proto-viz/daemon/build && cmake .. && cmake --build ."
    exit 1
fi
echo "[OK] Daemon binary found"

# ── Step 2: Check BPF object exists ──
if [ ! -f "$BPF_OBJ" ]; then
    echo "[WARN] eBPF object not found at: $BPF_OBJ"
    echo "       Building eBPF program..."
    cd "$ROOT/fuse-proto-viz/ebpf"
    make clean && make
    sudo cp fuse_trace.bpf.o /opt/fuseviz/ebpf/
    cd "$ROOT"
    echo "[OK] eBPF object built and installed"
else
    echo "[OK] eBPF object: $BPF_OBJ"
fi

# ── Step 3: Kill any existing daemon (needs sudo since daemon runs as root) ──
EXISTING=$(pgrep -f fuseviz-daemon 2>/dev/null || true)
if [ -n "$EXISTING" ]; then
    echo "[..] Killing existing daemon (PID $EXISTING)..."
    sudo pkill -9 fuseviz-daemon 2>/dev/null || true
    sleep 2
    echo "[OK] Old daemon killed"
else
    echo "[OK] No existing daemon running"
fi

# ── Step 4: Clean old database ──
rm -f "$DB_PATH"*
echo "[OK] Database cleaned"

# ── Step 5: Configure kernel for eBPF ──
sudo sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
echo "[OK] kernel.perf_event_paranoid=1"

# ── Step 6: Start daemon ──
echo "[..] Starting daemon (requires sudo for eBPF)..."
echo ""
FUSEVIZ_DB_PATH="$DB_PATH" \
FUSEVIZ_BPF_OBJ="$BPF_OBJ" \
sudo -E nohup "$DAEMON_BIN" > "$LOG" 2>&1 &
DAEMON_PID=$!

sleep 4

if kill -0 $DAEMON_PID 2>/dev/null; then
    echo "  Daemon PID   : $DAEMON_PID"
    echo "  WebSocket    : ws://localhost:8080/ws"
    echo "  REST API     : http://localhost:8080/api/health"
    echo "  Logs         : $LOG"
    echo ""

    # Check if eBPF loaded or fell back to simulation
    if grep -q "Attached fexit" "$LOG" 2>/dev/null; then
        echo "  Mode         : REAL eBPF tracing"
        grep "Attached fexit" "$LOG"
    elif grep -q "SIM.*synthetic" "$LOG" 2>/dev/null; then
        echo "  Mode         : SIMULATION (eBPF failed to load)"
        grep -E "WARN|SIM|Permission" "$LOG" | head -3
    fi
    echo ""
    echo "  To stop: sudo pkill -f fuseviz-daemon"
else
    echo "[ERROR] Daemon failed to start. Last 10 lines of log:"
    tail -10 "$LOG"
    exit 1
fi
