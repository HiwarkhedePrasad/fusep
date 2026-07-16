#!/bin/bash
# Start FuseViz daemon with eBPF tracing
kill $(pgrep -f fuseviz-daemon) 2>/dev/null
sleep 1

ROOT="/home/hiwarkhedeprasad/Desktop/Agent/fuseviz-project"
DB_PATH="$ROOT/fuse-proto-viz/daemon/events.db"
DAEMON="$ROOT/fuse-proto-viz/daemon/build/fuseviz-daemon"

rm -f "$DB_PATH"*

export FUSEVIZ_DB_PATH="$DB_PATH"
export FUSEVIZ_BPF_OBJ="/opt/fuseviz/ebpf/fuse_trace.bpf.o"

echo "Starting daemon..."
echo "  BPF object: $FUSEVIZ_BPF_OBJ"
echo "  DB path:    $FUSEVIZ_DB_PATH"

nohup "$DAEMON" >/tmp/fuseviz-daemon.log 2>&1 &
DAEMON_PID=$!
sleep 3

if kill -0 $DAEMON_PID 2>/dev/null; then
    echo "Daemon running (PID $DAEMON_PID)"
    echo ""
    head -20 /tmp/fuseviz-daemon.log
else
    echo "Daemon failed to start!"
    cat /tmp/fuseviz-daemon.log
fi
