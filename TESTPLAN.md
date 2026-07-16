# Test Plan — FuseViz Real-World FUSE Tracing

This plan validates the project against real FUSE filesystem operations,
not simulated data. The primary target is **Google Drive via rclone**, a
production FUSE filesystem used by millions, but other options are listed.

---

## Prerequisites

- **Linux** with kernel 5.4+ (eBPF support, kprobes enabled)
- `/sys/kernel/debug` accessible (`mount -t debugfs none /sys/kernel/debug`)
- `docker` and `docker compose` (or build the C++ daemon natively)
- Node.js 18+ (for the frontend)

---

## 1. Setup a Real FUSE Filesystem

Pick one of the following FUSE filesystems to trace:

### Option A: Google Drive via rclone (recommended)

```bash
sudo apt install rclone fuse3
rclone config
# Follow the interactive setup:
#   - Choose "Google Drive"
#   - Complete OAuth in browser
#   - Accept default options
#   - Quit config

mkdir -p ~/gdrive
rclone mount gdrive: ~/gdrive --daemon --vfs-cache-mode writes
```

Verify it's mounted as FUSE:
```bash
mount | grep rclone
# Expected: rclone on /home/you/gdrive type fuse.rclone (rw,nosuid,nodev,relatime,user_id=1000,group_id=1000)
```

### Option B: sshfs (remote server)

```bash
sudo apt install sshfs fuse3
mkdir -p ~/remote
sshfs user@server:/path ~/remote
```

### Option C: unionfs-fuse (local overlay)

```bash
sudo apt install unionfs-fuse fuse3
mkdir -p ~/backing ~/mnt
unionfs-fuse ~/backing ~/mnt
```

---

## 2. Build & Run the Stack

### Using Docker (recommended for demo)

```bash
# Build and start all services
docker compose up --build -d

# Check logs
docker compose logs -f fuseviz
```

Expected log output:
```
[OK] SQLite WAL persistence opened
[OK] WebSocket broadcaster started on 0.0.0.0:8080
[OK] Distribution pipeline started
[OK] All pipelines active. Press Ctrl+C to exit.
```

If eBPF fails to load (no `/sys/kernel/debug`), the daemon auto-falls
back to simulation mode. For real tracing, ensure debugfs is mounted.

### Running Natively

```bash
# Build the daemon (see CMakeLists.txt)
mkdir -p daemon/build && cd daemon/build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ../..

# Build the frontend
npm install
npm run build

# Start the daemon
sudo ./daemon/build/fuseviz-daemon

# In another terminal, start the frontend
npm run start
```

---

## 3. Verify Real-Time Event Tracing

### Step 3.1: Confirm eBPF is capturing

Check the daemon logs for eBPF attachment messages:
```
[BPF] Attached kprobe/fuse_dev_read
[BPF] Attached kprobe/fuse_dev_write
[BPF] eBPF engine loaded and ready
```

If you see `[WARN] eBPF load failed — falling back to simulation mode`,
the test will run on fake data. Real tracing requires eBPF kernel support.

### Step 3.2: Generate Real FUSE Activity

Run these commands while watching the dashboard at `http://localhost:3000`:

```bash
# File listing (triggers FUSE_LOOKUP, FUSE_GETATTR, FUSE_READDIR)
ls -laR ~/gdrive/ 2>/dev/null | head -100 &

# File reads (triggers FUSE_READ)
cat ~/gdrive/some-document.pdf > /dev/null 2>&1 &

# File writes (triggers FUSE_WRITE)
echo "test" > ~/gdrive/test-file.txt 2>/dev/null

# File deletes (triggers FUSE_UNLINK)
rm ~/gdrive/test-file.txt 2>/dev/null

# Metadata queries (triggers FUSE_GETATTR, FUSE_ACCESS)
stat ~/gdrive/* 2>/dev/null | head -20 &

# Search (triggers FUSE_READDIRPLUS)
find ~/gdrive/ -name "*.pdf" 2>/dev/null &
```

### Step 3.3: Dashboard Validation Checklist

| Check | What to Look For | Pass Criteria |
|-------|-----------------|---------------|
| **Event Log** | Events appear in the left panel | Events visible within 5s of activity |
| **Opcode Filter** | Click an opcode in the sidebar | Only matching events shown |
| **Search** | Type a PID or filename | Filtered results appear |
| **Event Detail** | Click an event row | Right panel shows opcode, PID, latency, direction |
| **Direction** | `"enter"`/`"exit"` labels | Events show correct direction strings |
| **Timestamp** | Timestamp column | Shows wall-clock time (not boot time) |
| **Latency** | Latency column | Shows microseconds/milliseconds |
| **Sequence Diagram** | Open "Sequence" tab | Arrows between Kernel → FuseViz → VFS |
| **Throughput Chart** | Open "Metrics" tab | Line chart shows events per second |
| **Latency P50/P90/P99** | Latency metrics | Shows correct percentile values |
| **Opcode Distribution** | Bar chart | Shows top opcodes by count |
| **Top Bar Stats** | Top bar counters | Total events, ev/s, P99, uptime update |
| **Connection Status** | Top bar indicator | Shows LIVE when connected |
| **Export** | Click Export button | Downloads NDJSON file |
| **Pause/Resume** | Click Pause button | Events stop appearing, resume works |

### Step 3.4: Threat Detection (Optional)

If Ollama is running alongside the daemon:

```bash
# Simulate ransomware pattern (rapid writes + deletes)
for i in $(seq 1 100); do
  echo "data$i" > ~/gdrive/file$i.txt 2>/dev/null
  rm ~/gdrive/file$i.txt 2>/dev/null
done
```

Check the "Threats" tab in the right panel for ransomware alerts.

---

## 4. Edge Case Tests

### 4.1. Disconnect / Reconnect

```bash
# Restart the daemon
docker compose restart fuseviz
```

Expected: Frontend shows OFFLINE → reconnects → shows LIVE again with events.

### 4.2. High Throughput

```bash
# Generate rapid file operations
for i in $(seq 1 1000); do
  echo "content" > ~/gdrive/batch-$i.txt 2>/dev/null
done
```

Expected: Events stream in, throughput chart updates, no memory issues.

### 4.3. Multiple Concurrent Operations

```bash
# Run parallel workloads
find ~/gdrive/ -type f -exec cat {} \; > /dev/null 2>&1 &
find ~/gdrive/ -type d -exec ls {} \; > /dev/null 2>&1 &
stat ~/gdrive/*/* 2>/dev/null &
```

Expected: All events captured, no queue overflow, all frontend panels update.

### 4.4. Mixed FUSE Filesystems (Advanced)

If multiple FUSE filesystems are mounted simultaneously:

```bash
# Mount a second FUSE filesystem
mkdir -p ~/union-mount ~/backing2
unionfs-fuse ~/backing2 ~/union-mount
ls ~/union-mount/ &
ls ~/gdrive/ &
```

Expected: Events from both filesystems appear in the log (distinguishable
by process name or node ID).

---

## 5. Known Demo-Killer Bugs

The following bugs cause the demo to visibly fail:

| Bug | Symptom | Status |
|-----|---------|--------|
| Direction field mismatch | No events appear (Zod validation rejects all) | Fixed |
| eventsPerSec stat wrong | Shows total count, not per-second rate | Fixed |
| Timestamps show boot time | Detail panel shows wrong absolute time | Fixed |
| Sequence diagram wrong arrows | Always shows wrong direction | Fixed |
| Enricher drops silently | Events vanish without counter | Fixed |

If testing on unmodified code, these must be fixed first.

---

## 6. FAQ

**Q: The dashboard shows "Waiting for events" — what's wrong?**
A: Check daemon logs. If you see `eBPF load failed`, you're in simulation
mode — that's fine, just verify the daemon is running and connected.

**Q: Events appear in the log but the sequence diagram is empty.**
A: The sequence diagram requires events with the `dir` field set to
`"enter"`/`"exit"`. Check that the C++ daemon sends string directions,
not raw integers.

**Q: The timestamp shows a time from 1970 or 1601.**
A: The eBPF clock is boot-relative. The daemon must convert timestamps
to Unix epoch before sending to the frontend.

**Q: Can I test without a real FUSE filesystem?**
A: Yes. If eBPF fails to load, the daemon auto-generates synthetic events.
The dashboard works identically, but data is fake.

**Q: Do I need root to run this?**
A: For eBPF, yes (or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`).
The Docker setup handles this via `cap_add`.
