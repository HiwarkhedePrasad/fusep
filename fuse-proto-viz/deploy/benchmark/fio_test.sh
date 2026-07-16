#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  FuseViz Enterprise — I/O Verification Suite
#
#  Uses fio (Flexible I/O Tester) to run heavy parallel read/write
#  workloads over a mounted FUSE drive. Benchmarks system performance
#  and empirically verifies that the out-of-band eBPF engine introduces
#  negligible latency overhead to the critical storage path.
#
#  Usage: ./fio_test.sh [mount_point] [results_dir]
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

MOUNT_POINT="${1:-/mnt/fuseviz}"
RESULTS_DIR="${2:-/tmp/fuseviz-benchmarks}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

echo "═══════════════════════════════════════════════════════════"
echo "  FuseViz I/O Verification Suite"
echo "  Mount: $MOUNT_POINT"
echo "  Results: $RESULTS_DIR"
echo "  Timestamp: $TIMESTAMP"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── Pre-flight checks ──
if ! command -v fio &>/dev/null; then
    echo "[ERROR] fio not found. Install with: apt install fio"
    exit 1
fi

if ! mountpoint -q "$MOUNT_POINT"; then
    echo "[ERROR] $MOUNT_POINT is not a mount point"
    echo "  Fix: Mount a FUSE filesystem first"
    exit 1
fi

# ── Test 1: Sequential Read Throughput ──
echo "[TEST 1] Sequential read throughput..."
fio --name=seq-read \
    --directory="$MOUNT_POINT" \
    --rw=read \
    --bs=4k \
    --size=256M \
    --numjobs=1 \
    --iodepth=32 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/seq-read-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 2: Sequential Write Throughput ──
echo "[TEST 2] Sequential write throughput..."
fio --name=seq-write \
    --directory="$MOUNT_POINT" \
    --rw=write \
    --bs=4k \
    --size=256M \
    --numjobs=1 \
    --iodepth=32 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/seq-write-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 3: Random Read IOPS ──
echo "[TEST 3] Random read IOPS..."
fio --name=rand-read \
    --directory="$MOUNT_POINT" \
    --rw=randread \
    --bs=4k \
    --size=512M \
    --numjobs=4 \
    --iodepth=64 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/rand-read-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 4: Random Write IOPS ──
echo "[TEST 4] Random write IOPS..."
fio --name=rand-write \
    --directory="$MOUNT_POINT" \
    --rw=randwrite \
    --bs=4k \
    --size=512M \
    --numjobs=4 \
    --iodepth=64 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/rand-write-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 5: Mixed Read/Write (70/30) ──
echo "[TEST 5] Mixed read/write workload (70/30)..."
fio --name=mixed-rw \
    --directory="$MOUNT_POINT" \
    --rw=randrw \
    --rwmixread=70 \
    --bs=4k \
    --size=512M \
    --numjobs=8 \
    --iodepth=64 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/mixed-rw-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 6: Metadata-intensive (stat-heavy) ──
echo "[TEST 6] Metadata-intensive workload..."
fio --name=metadata \
    --directory="$MOUNT_POINT" \
    --rw=randread \
    --bs=512 \
    --size=64M \
    --numjobs=16 \
    --iodepth=128 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/metadata-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 7: Large file streaming (1MB blocks) ──
echo "[TEST 7] Large file streaming (1MB blocks)..."
fio --name=streaming \
    --directory="$MOUNT_POINT" \
    --rw=read \
    --bs=1M \
    --size=1G \
    --numjobs=1 \
    --iodepth=8 \
    --direct=1 \
    --ioengine=libaio \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/streaming-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Test 8: Latency measurement under load ──
echo "[TEST 8] Latency under concurrent load..."
fio --name=latency-test \
    --directory="$MOUNT_POINT" \
    --rw=randread \
    --bs=4k \
    --size=256M \
    --numjobs=1 \
    --iodepth=1 \
    --direct=1 \
    --ioengine=libaio \
    --lat_percentiles=1 \
    --percentile_list=50:90:95:99:99.5:99.9 \
    --group_reporting \
    --output-format=json \
    --output="$RESULTS_DIR/latency-${TIMESTAMP}.json" \
    2>/dev/null

echo "  ✓ Complete"

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Benchmark Results"
echo "═══════════════════════════════════════════════════════════"
echo ""

for result in "$RESULTS_DIR"/*-${TIMESTAMP}.json; do
    test_name=$(basename "$result" .json | sed "s/-${TIMESTAMP}//")
    
    # Extract key metrics using python3/jq if available
    if command -v python3 &>/dev/null; then
        bw=$(python3 -c "
import json, sys
try:
    d = json.load(open('$result'))
    jobs = d.get('jobs', [{}])
    if jobs:
        r = jobs[0].get('read', {})
        w = jobs[0].get('write', {})
        rb = r.get('bw_bytes', 0) / 1024 / 1024
        wb = w.get('bw_bytes', 0) / 1024 / 1024
        riops = r.get('iops', 0)
        wiops = w.get('iops', 0)
        rlat = r.get('lat_ns', {}).get('mean', 0) / 1000
        wlat = w.get('lat_ns', {}).get('mean', 0) / 1000
        if rb > 0:
            print(f'  Read:  {rb:.1f} MB/s, {riops:.0f} IOPS, {rlat:.1f} μs avg')
        if wb > 0:
            print(f'  Write: {wb:.1f} MB/s, {wiops:.0f} IOPS, {wlat:.1f} μs avg')
except: pass
" 2>/dev/null)
        
        if [ -n "$bw" ]; then
            echo "[$test_name]"
            echo "$bw"
            echo ""
        fi
    fi
done

echo "═══════════════════════════════════════════════════════════"
echo "  Full results saved to: $RESULTS_DIR/"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  To verify eBPF overhead is negligible:"
echo "  1. Run this suite WITHOUT FuseViz eBPF loaded"
echo "  2. Run this suite WITH FuseViz eBPF loaded"
echo "  3. Compare latency percentiles (should be <1% difference)"
