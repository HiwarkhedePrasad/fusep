#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo " ╔═══════════════════════════════════════════════════════╗"
echo " ║              FuseViz Dashboard Launcher              ║"
echo " ╚═══════════════════════════════════════════════════════╝"
echo ""

if ! command -v node &>/dev/null; then
    echo "[ERROR] Node.js not found."
    exit 1
fi
echo "[OK] Node.js: $(node -v)"

if [ ! -d "$ROOT/node_modules" ]; then
    echo "[..] Installing npm dependencies..."
    cd "$ROOT"
    npm install
    echo "[OK] Dependencies installed."
else
    echo "[OK] node_modules found."
fi

DAEMON_BIN="$ROOT/fuse-proto-viz/daemon/build/fuseviz-daemon"
if [ -f "$DAEMON_BIN" ]; then
    echo ""
    echo "[..] Starting C++ daemon..."
    BPF_OBJ="$ROOT/fuse-proto-viz/ebpf/fuse_trace.bpf.o"
    DB_PATH="$ROOT/fuse-proto-viz/daemon/events.db"
    rm -f "$DB_PATH"*
    [ -f "$BPF_OBJ" ] && export FUSEVIZ_BPF_OBJ="$BPF_OBJ"
    export FUSEVIZ_DB_PATH="$DB_PATH"
    nohup "$DAEMON_BIN" > /tmp/fuseviz-daemon.log 2>&1 &
    DAEMON_PID=$!
    sleep 2
    if kill -0 $DAEMON_PID 2>/dev/null; then
        echo "[OK] Daemon running (PID $DAEMON_PID)"
    else
        echo "[WARN] Daemon failed to start — check /tmp/fuseviz-daemon.log"
    fi
else
    echo "[SKIP] Daemon not built at $DAEMON_BIN (frontend only)"
fi

echo ""
echo "[..] Starting Next.js frontend on http://localhost:3000..."
xdg-open http://localhost:3000 2>/dev/null || true
cd "$ROOT"
npm run dev
