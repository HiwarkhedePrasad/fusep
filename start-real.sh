#!/bin/bash
sudo env "FUSEVIZ_BPF_OBJ=$(pwd)/fuse-proto-viz/ebpf/fuse_trace.bpf.o" \
         "FUSEVIZ_DB_PATH=$(pwd)/fuse-proto-viz/daemon/events.db" \
         nohup "$(pwd)/fuse-proto-viz/daemon/build/fuseviz-daemon" > /tmp/fuseviz-daemon.log 2>&1 &
echo "Daemon PID: $!"
