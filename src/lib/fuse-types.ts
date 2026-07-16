/**
 * FuseViz shared types
 *
 * Mirrors the Go daemon's event structures for end-to-end type safety.
 */

// ── FUSE Opcode constants ──
export const FUSE_OPCODES: Record<number, string> = {
  1: "FUSE_LOOKUP",
  2: "FUSE_FORGET",
  3: "FUSE_GETATTR",
  4: "FUSE_SETATTR",
  5: "FUSE_READLINK",
  6: "FUSE_SYMLINK",
  8: "FUSE_MKNOD",
  9: "FUSE_MKDIR",
  10: "FUSE_UNLINK",
  11: "FUSE_RMDIR",
  12: "FUSE_RENAME",
  13: "FUSE_LINK",
  14: "FUSE_OPEN",
  15: "FUSE_READ",
  16: "FUSE_WRITE",
  17: "FUSE_STATFS",
  18: "FUSE_RELEASE",
  20: "FUSE_FSYNC",
  21: "FUSE_SETXATTR",
  22: "FUSE_GETXATTR",
  23: "FUSE_LISTXATTR",
  24: "FUSE_REMOVEXATTR",
  25: "FUSE_FLUSH",
  26: "FUSE_INIT",
  27: "FUSE_OPENDIR",
  28: "FUSE_READDIR",
  29: "FUSE_RELEASEDIR",
  30: "FUSE_FSYNCDIR",
  34: "FUSE_ACCESS",
  35: "FUSE_CREATE",
  36: "FUSE_INTERRUPT",
  37: "FUSE_BMAP",
  38: "FUSE_DESTROY",
  39: "FUSE_IOCTL",
  40: "FUSE_POLL",
  42: "FUSE_BATCH_FORGET",
  43: "FUSE_READDIRPLUS",
  44: "FUSE_RENAME2",
  45: "FUSE_LSEEK",
  46: "FUSE_COPY_FILE_RANGE",
};

// ── Opcode color map ──
export const OPCODE_COLORS: Record<string, string> = {
  FUSE_INIT: "#a78bfa",
  FUSE_GETATTR: "#38bdf8",
  FUSE_LOOKUP: "#4ade80",
  FUSE_OPEN: "#fbbf24",
  FUSE_READ: "#2dd4bf",
  FUSE_READDIR: "#34d399",
  FUSE_READDIRPLUS: "#34d399",
  FUSE_WRITE: "#fb7185",
  FUSE_RELEASE: "#f97316",
  FUSE_UNLINK: "#ef4444",
  FUSE_RENAME: "#ec4899",
  FUSE_FLUSH: "#8b5cf6",
  FUSE_ACCESS: "#6366f1",
  FUSE_CREATE: "#10b981",
  FUSE_MKDIR: "#14b8a6",
  FUSE_OPENDIR: "#f59e0b",
  FUSE_STATFS: "#64748b",
  FUSE_SETATTR: "#06b6d4",
  FUSE_FORGET: "#475569",
  FUSE_DESTROY: "#94a3b8",
};

export const DEFAULT_OPCODE_COLOR = "#94a3b8";

// ── Enriched FUSE event (from Go daemon) ──
export interface FUSEEvent {
  ts: number;
  op: number;
  op_name: string;
  node: number;
  unique: number;
  pid: number;
  tid?: number;
  uid: number;
  gid: number;
  dir: "enter" | "exit";
  syscall?: "read" | "write";
  error: number;
  data_len: number;
  latency_ns: number;
  ret_val?: number;
  process_name: string;
  container_id: string;
  pod_name: string;
  namespace: string;
  write_data_b64?: string;
  write_data_text?: string;
  write_data_len?: number;
}

// ── Threat alert ──
export interface ThreatAlert {
  ts: number;
  type: "ransomware_pattern" | "data_exfiltration" | "anomaly_detected";
  severity: "low" | "medium" | "high" | "critical";
  pid: number;
  process_name: string;
  details: Record<string, unknown>;
  ai_analysis: string;
}

// ── Stats payload ──
export interface FUSEStats {
  totalEvents: number;
  eventsPerSec: number;
  uptimeSec: number;
  dropped?: number;
  latency: {
    p50: number;
    p90: number;
    p99: number;
  };
  opcodeDistribution: Record<string, number>;
  throughputHistory: number[];
  activeClients: number;
}

// ── Severity badge config ──
export const SEVERITY_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
  low: { color: "#4ade80", bg: "#4ade8015", label: "LOW" },
  medium: { color: "#fbbf24", bg: "#fbbf2415", label: "MED" },
  high: { color: "#fb7185", bg: "#fb718515", label: "HIGH" },
  critical: { color: "#ef4444", bg: "#ef444415", label: "CRIT" },
};

export const ALERT_TYPE_LABELS: Record<string, string> = {
  ransomware_pattern: "Ransomware Pattern",
  data_exfiltration: "Data Exfiltration",
  anomaly_detected: "Anomaly Detected",
};
