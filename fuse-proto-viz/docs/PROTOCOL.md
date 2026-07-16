# PROTOCOL — FUSE Kernel Protocol Reference

## Overview

FUSE (Filesystem in Userspace) is a Linux kernel interface that allows filesystem implementations to run in unprivileged userspace. The kernel communicates with userspace daemons via `/dev/fuse`, a character device (major 10, minor 229).

## Protocol Frame Format

### Request (Kernel → Userspace)

```
┌──────────────────┬──────────────────┐
│ fuse_in_header   │ opcode-specific  │
│ (40 bytes)       │ payload          │
└──────────────────┴──────────────────┘
```

**fuse_in_header:**
| Offset | Size | Field    | Description                    |
|--------|------|----------|--------------------------------|
| 0      | 4    | len      | Total message length (bytes)   |
| 4      | 4    | opcode   | Operation code (see below)     |
| 8      | 8    | unique   | Unique transaction ID          |
| 16     | 8    | nodeid   | Inode number                   |
| 24     | 4    | uid      | Caller's User ID               |
| 28     | 4    | gid      | Caller's Group ID              |
| 32     | 4    | pid      | Caller's Thread Group ID       |
| 36     | 4    | padding  | Reserved                       |

### Response (Userspace → Kernel)

```
┌──────────────────┬──────────────────┐
│ fuse_out_header  │ opcode-specific  │
│ (16 bytes)       │ payload          │
└──────────────────┴──────────────────┘
```

**fuse_out_header:**
| Offset | Size | Field    | Description                    |
|--------|------|----------|--------------------------------|
| 0      | 4    | len      | Total message length (bytes)   |
| 4      | 4    | error    | 0 on success, -errno on error  |
| 8      | 8    | unique   | Must match request's unique    |

## Opcode Reference (FUSE 7.x)

| Opcode | Value | Name             | Has Request Payload | Has Response Payload |
|--------|-------|------------------|---------------------|----------------------|
| 1      | FUSE_LOOKUP       | filename string    | fuse_entry_out      |
| 2      | FUSE_FORGET       | fuse_forget_in     | (no response)       |
| 3      | FUSE_GETATTR      | fuse_getattr_in    | fuse_attr_out       |
| 4      | FUSE_SETATTR      | fuse_setattr_in    | fuse_attr_out       |
| 5      | FUSE_READLINK     | (none)             | link target string  |
| 14     | FUSE_OPEN         | fuse_open_in       | fuse_open_out       |
| 15     | FUSE_READ         | fuse_read_in       | data bytes          |
| 16     | FUSE_WRITE        | fuse_write_in+data | fuse_write_out      |
| 17     | FUSE_STATFS       | (none)             | fuse_statfs_out     |
| 18     | FUSE_RELEASE      | fuse_release_in    | (none)              |
| 26     | FUSE_INIT         | fuse_init_in       | fuse_init_out       |
| 27     | FUSE_OPENDIR      | fuse_open_in       | fuse_open_out       |
| 28     | FUSE_READDIR      | fuse_read_in       | dir entries         |
| 43     | FUSE_READDIRPLUS  | fuse_read_in       | dir entries+attrs   |

## Latency Correlation

The `unique` field in both request and response headers serves as the transaction ID for correlating FUSE operations. By matching `fuse_in_header.unique` with `fuse_out_header.unique`, we compute precise sub-millisecond protocol latency:

```
latency = response_timestamp - request_timestamp
```

## eBPF Observation Model

Our out-of-band observation hooks into the syscall tracepoints around `/dev/fuse` reads and writes:

- `sys_enter_read` + `sys_exit_read`: Captures FUSE requests (kernel → daemon)
- `sys_enter_write` + `sys_exit_write`: Captures FUSE responses (daemon → kernel)

The eBPF programs filter by the /dev/fuse device's major/minor numbers (10/229) and extract the protocol headers from the syscall buffers, pushing structured events to a lock-free ring buffer for userspace consumption.
