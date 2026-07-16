/* ═══════════════════════════════════════════════════════════════════════
 *  fuse_trace.bpf.c  —  eBPF fexit Programs for FUSE Device Tracing
 *
 *  Kernel 6.17 (from BTF + uio.h):
 *    ssize_t fuse_dev_read(struct file *file, struct iov_iter *iov)
 *    ssize_t fuse_dev_write(struct file *file, struct iov_iter *iov)
 *
 *  Strategy:
 *  - fuse_dev_read: captures FUSE requests (has opcode, nodeid, unique)
 *    Stores {opcode, nodeid} in unique_info map keyed by unique ID.
 *  - fuse_dev_write: captures FUSE responses (only has unique, error, len)
 *    Looks up opcode/nodeid from unique_info map using the unique ID.
 *
 *  This eliminates UNKNOWN events by correlating responses with requests.
 * ═══════════════════════════════════════════════════════════════════════ */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fuse_trace.h"

#define ITER_IOVEC   1
#define ITER_UBUF    0

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} fuse_events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, uint64_t);
    __type(value, uint64_t);
} unique_ts SEC(".maps");

/* Map to store opcode+nodeid from requests, keyed by unique ID.
 * Value packs opcode (lower 32 bits) and nodeid (upper 32 bits). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, uint64_t);
    __type(value, uint64_t);
} unique_info SEC(".maps");

struct fuse_in_header_k {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

/* fuse_write_in: 40 bytes, sits right after fuse_in_header in WRITE requests */
struct fuse_write_in_k {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t write_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_out_header_k {
    uint32_t len;
    int32_t  error;
    uint64_t unique;
};

/* ═══════════════════════════════════════════════════════════════════════
 *  Read FUSE header from an iov_iter.
 *  Handles both ITER_IOVEC (kernel memory) and ITER_UBUF (userspace).
 * ═══════════════════════════════════════════════════════════════════════ */
static __always_inline int read_fuse_header_from_iter(
    struct iov_iter *iov, void *out_hdr, size_t hdr_size)
{
    u8 iter_type = 0;
    const void *data_ptr = 0;

    if (bpf_probe_read(&iter_type, sizeof(iter_type), iov) < 0)
        return -1;

    if (bpf_probe_read(&data_ptr, sizeof(data_ptr), (char *)iov + 16) < 0)
        return -1;

    if (!data_ptr)
        return -1;

    if (iter_type == ITER_IOVEC) {
        const void *iov_base = 0;
        if (bpf_probe_read(&iov_base, sizeof(iov_base), data_ptr) < 0)
            return -1;
        if (!iov_base)
            return -1;
        if (bpf_probe_read(out_hdr, hdr_size, iov_base) < 0)
            return -1;
    } else {
        if (bpf_probe_read_user(out_hdr, hdr_size, data_ptr) < 0)
            return -1;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Read data from an offset within the iov_iter buffer.
 *  Used to capture write payload after fuse_in_header + fuse_write_in.
 * ═══════════════════════════════════════════════════════════════════════ */
static __always_inline int read_from_iter_offset(
    struct iov_iter *iov, size_t offset, void *out, size_t out_size)
{
    u8 iter_type = 0;
    const void *data_ptr = 0;

    if (bpf_probe_read(&iter_type, sizeof(iter_type), iov) < 0)
        return -1;

    if (bpf_probe_read(&data_ptr, sizeof(data_ptr), (char *)iov + 16) < 0)
        return -1;

    if (!data_ptr)
        return -1;

    if (iter_type == ITER_IOVEC) {
        const void *iov_base = 0;
        if (bpf_probe_read(&iov_base, sizeof(iov_base), data_ptr) < 0)
            return -1;
        if (!iov_base)
            return -1;
        const void *target = (const char *)iov_base + offset;
        if (bpf_probe_read(out, out_size, target) < 0)
            return -1;
    } else {
        const void *target = (const char *)data_ptr + offset;
        if (bpf_probe_read_user(out, out_size, target) < 0)
            return -1;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  fexit/fuse_dev_read — captures FUSE requests
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("fexit/fuse_dev_read")
int BPF_PROG(fuse_dev_read_exit, struct file *file, struct iov_iter *iov)
{
    struct fuse_trace_event *evt;
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t uid_gid  = bpf_get_current_uid_gid();

    evt = bpf_ringbuf_reserve(&fuse_events_rb, sizeof(*evt), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->direction    = FUSE_DIR_READ_EXIT;
    evt->pid          = pid_tgid >> 32;
    evt->uid          = uid_gid & 0xFFFFFFFF;
    evt->gid          = uid_gid >> 32;

    if (iov) {
        struct fuse_in_header_k in_hdr;
        if (read_fuse_header_from_iter(iov, &in_hdr, sizeof(in_hdr)) == 0) {
            evt->opcode  = in_hdr.opcode;
            evt->unique  = in_hdr.unique;
            evt->nodeid  = in_hdr.nodeid;
            evt->data_len = in_hdr.len > sizeof(struct fuse_in_header_k)
                ? in_hdr.len - sizeof(struct fuse_in_header_k) : 0;

            /* Store opcode+nodeid in map for write handler to look up */
            if (evt->unique != 0) {
                uint64_t key = evt->unique;
                uint64_t val = ((uint64_t)evt->opcode << 32) | (uint64_t)evt->nodeid;
                bpf_map_update_elem(&unique_info, &key, &val, BPF_ANY);
            }

            /* Capture write payload for FUSE_WRITE requests.
             * Layout: [fuse_in_header (40)] [fuse_write_in (40)] [data...]
             * We capture up to WRITE_DATA_MAX bytes of the actual data. */
            if (evt->opcode == FUSE_WRITE && evt->data_len > sizeof(struct fuse_write_in_k)) {
                uint32_t payload_offset = sizeof(struct fuse_in_header_k)
                                        + sizeof(struct fuse_write_in_k);
                uint32_t payload_len = evt->data_len - sizeof(struct fuse_write_in_k);
                if (payload_len > WRITE_DATA_MAX)
                    payload_len = WRITE_DATA_MAX;

                if (read_from_iter_offset(iov, payload_offset,
                                          evt->write_data, payload_len) == 0) {
                    evt->write_data_len = payload_len;
                }
            }
        }
    }

    if (evt->unique != 0) {
        uint64_t key = evt->unique;
        uint64_t val = evt->timestamp_ns;
        bpf_map_update_elem(&unique_ts, &key, &val, BPF_ANY);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  fexit/fuse_dev_write — captures FUSE responses
 *
 *  fuse_out_header only has {len, error, unique} — no opcode/nodeid.
 *  The userspace buffer (ITER_UBUF) is not accessible via bpf_probe_read_user
 *  at fexit time, so we skip emitting write events entirely.
 *  The read handler already captures all FUSE requests with real opcodes.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("fexit/fuse_dev_write")
int BPF_PROG(fuse_dev_write_exit, struct file *file, struct iov_iter *iov)
{
    /* Skip — fuse_out_header has no opcode/nodeid, and userspace buffer
     * (ITER_UBUF) is not accessible via bpf_probe_read_user at fexit.
     * The read handler captures all FUSE requests with real opcodes. */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
