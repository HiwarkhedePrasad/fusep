#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  FuseViz Enterprise — Entrypoint Script (C++ Daemon)
# ═══════════════════════════════════════════════════════════════════════
set -e

echo "[FuseViz] Enterprise Platform v2.0.0-cpp starting..."

# ── Ensure /dev/fuse is accessible ──
if [ ! -c /dev/fuse ]; then
    echo "[WARN] /dev/fuse not found — creating device node"
    mknod /dev/fuse c 10 229 2>/dev/null || true
fi
chmod 666 /dev/fuse 2>/dev/null || true

# ── Ensure mount point exists ──
mkdir -p /mnt/fuseviz

# ── Check eBPF availability ──
if [ -w /sys/kernel/debug ]; then
    echo "[eBPF] Debug filesystem accessible — kprobes available"
else
    echo "[WARN] /sys/kernel/debug not accessible — simulation mode"
    echo "[INFO] C++ daemon will fall back to synthetic event generation"
fi

# ── Start the C++ daemon ──
echo "[Daemon] Starting FuseViz C++20 systems daemon..."
/usr/local/bin/fuseviz-daemon &
DAEMON_PID=$!

# ── Start the Next.js UI ──
if [ -d /opt/fuseviz/ui ]; then
    echo "[UI] Starting Next.js observability dashboard..."
    cd /opt/fuseviz/ui
    node server.js &
    UI_PID=$!
fi

# ── Wait for any process to exit ──
wait -n $DAEMON_PID $UI_PID 2>/dev/null || true

# ── Cleanup ──
echo "[FuseViz] Shutting down..."
kill $DAEMON_PID $UI_PID 2>/dev/null || true
wait

echo "[FuseViz] Shutdown complete"
