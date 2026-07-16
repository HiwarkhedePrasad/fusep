/* ═══════════════════════════════════════════════════════════════════════
 *  fuse_trace.h  —  Shared Ring Buffer Contract
 *
 *  This header is included by BOTH the eBPF kernel program and the
 *  C++ userspace daemon. It defines the exact binary layout of the
 *  event payload pushed through bpf_ringbuf.
 *
 *  CRITICAL: Any modification to this struct must be synchronized
 *  across both the .bpf.c and the C++ consumer. Memory alignment
 *  and field order are a binary contract — no padding differences
 *  tolerated.
 * ═══════════════════════════════════════════════════════════════════════ */

#ifndef FUSE_TRACE_H
#define FUSE_TRACE_H

#ifndef __BPF__
#include <stdint.h>
#endif

/* ── FUSE opcode constants (mirrors linux/fuse.h) ── */
#define FUSE_LOOKUP         1
#define FUSE_FORGET         2
#define FUSE_GETATTR        3
#define FUSE_SETATTR        4
#define FUSE_READLINK       5
#define FUSE_SYMLINK        6
#define FUSE_MKNOD          8
#define FUSE_MKDIR          9
#define FUSE_UNLINK         10
#define FUSE_RMDIR          11
#define FUSE_RENAME         12
#define FUSE_LINK           13
#define FUSE_OPEN           14
#define FUSE_READ           15
#define FUSE_WRITE          16
#define FUSE_STATFS         17
#define FUSE_RELEASE        18
#define FUSE_FSYNC          20
#define FUSE_SETXATTR       21
#define FUSE_GETXATTR       22
#define FUSE_LISTXATTR      23
#define FUSE_REMOVEXATTR    24
#define FUSE_FLUSH          25
#define FUSE_INIT           26
#define FUSE_OPENDIR        27
#define FUSE_READDIR        28
#define FUSE_RELEASEDIR     29
#define FUSE_FSYNCDIR       30
#define FUSE_ACCESS         34
#define FUSE_CREATE         35
#define FUSE_INTERRUPT      36
#define FUSE_BMAP           37
#define FUSE_DESTROY        38
#define FUSE_IOCTL          39
#define FUSE_POLL           40
#define FUSE_BATCH_FORGET   42
#define FUSE_READDIRPLUS    43
#define FUSE_RENAME2        44
#define FUSE_LSEEK          45
#define FUSE_COPY_FILE_RANGE 46

/* ── Direction flags ── */
#define FUSE_DIR_READ_ENTER   1   /* kprobe/fuse_dev_read entry  */
#define FUSE_DIR_READ_EXIT    2   /* kprobe/fuse_dev_read return */
#define FUSE_DIR_WRITE_ENTER  3   /* kprobe/fuse_dev_write entry */
#define FUSE_DIR_WRITE_EXIT   4   /* kprobe/fuse_dev_write return */

/* ── Maximum bytes of write payload to capture ── */
#define WRITE_DATA_MAX 128

/* ── Ring buffer event structure (packed, no padding) ──
 *
 *  Each event represents one kprobe hit on fuse_dev_read or
 *  fuse_dev_write. The C++ decoder correlates read/write pairs
 *  by matching the `unique` transaction ID.
 */
struct fuse_trace_event {
    uint64_t timestamp_ns;    /* bpf_ktime_get_ns()              */
    uint8_t  direction;       /* FUSE_DIR_* constant             */
    uint8_t  _pad0[3];

    /* ── FUSE protocol headers ── */
    uint32_t opcode;          /* fuse_in_header.opcode           */
    uint64_t unique;          /* Transaction ID for correlation  */
    uint64_t nodeid;          /* fuse_in_header.nodeid           */

    /* ── Caller credentials ── */
    uint32_t pid;             /* tgid (userspace PID)            */
    uint32_t uid;
    uint32_t gid;
    uint32_t _pad1;

    /* ── Response-specific ── */
    int32_t  error;           /* fuse_out_header.error           */
    uint32_t data_len;        /* payload bytes (excl. headers)   */

    /* ── Latency (filled by userspace correlator) ── */
    uint64_t latency_ns;      /* 0 until correlated             */

    /* ── Write payload capture (FUSE_WRITE only) ── */
    uint8_t  write_data[WRITE_DATA_MAX];  /* first N bytes of write    */
    uint8_t  write_data_len;              /* bytes actually captured   */
    uint8_t  _pad2[7];                    /* alignment padding         */
};

#endif /* FUSE_TRACE_H */
