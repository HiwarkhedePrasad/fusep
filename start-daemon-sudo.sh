#!/bin/bash
# Start FuseViz daemon with eBPF tracing (requires sudo)
ROOT="/home/hiwarkhedeprasad/Desktop/Agent/fuseviz-project"
DB_PATH="$ROOT/fuse-proto-viz/daemon/events.db"
DAEMON="$ROOT/fuse-proto-viz/daemon/build/fuseviz-daemon"

rm -f "$DB_PATH"*

export FUSEVIZ_DB_PATH="$DB_PATH"
export FUSEVIZ_BPF_OBJ="/opt/fuseviz/ebpf/fuse_trace.bpf.o"

echo "Starting daemon with sudo (for eBPF)..."
nohup sudo -E "$DAEMON" >/tmp/fuseviz-daemon.log 2>&1 &
sleep 4
head -25 /tmp/fuseviz-daemon.log
