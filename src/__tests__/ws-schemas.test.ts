import { describe, it, expect } from "vitest";
import {
  FUSEEventSchema,
  ThreatAlertSchema,
  FUSEStatsSchema,
  WSMessageSchema,
} from "@/lib/ws-schemas";

describe("FUSEEventSchema", () => {
  const validEvent = {
    ts: 1000,
    op: 15,
    op_name: "FUSE_READ",
    node: 42,
    unique: 1,
    pid: 1234,
    tid: 5678,
    uid: 0,
    gid: 0,
    dir: "enter",
    syscall: "read",
    error: 0,
    data_len: 4096,
    latency_ns: 500,
    ret_val: 4096,
    process_name: "cat",
    container_id: "c1",
    pod_name: "pod1",
    namespace: "default",
  };

  it("accepts a complete event", () => {
    const result = FUSEEventSchema.safeParse(validEvent);
    expect(result.success).toBe(true);
  });

  it("accepts an event without optional fields", () => {
    const { tid, syscall, ret_val, ...minimal } = validEvent;
    const result = FUSEEventSchema.safeParse(minimal);
    expect(result.success).toBe(true);
  });

  it("rejects invalid dir value", () => {
    const bad = { ...validEvent, dir: "sideways" };
    const result = FUSEEventSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects non-integer pid", () => {
    const bad = { ...validEvent, pid: 12.34 };
    const result = FUSEEventSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });
});

describe("ThreatAlertSchema", () => {
  const validAlert = {
    ts: 2000,
    type: "anomaly_detected",
    severity: "high",
    pid: 999,
    process_name: "malware",
    details: { file: "/etc/passwd" },
    ai_analysis: "Suspicious write pattern detected",
  };

  it("accepts a valid alert", () => {
    const result = ThreatAlertSchema.safeParse(validAlert);
    expect(result.success).toBe(true);
  });

  it("rejects unknown alert type", () => {
    const bad = { ...validAlert, type: "unknown_threat" };
    const result = ThreatAlertSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects invalid severity", () => {
    const bad = { ...validAlert, severity: "extreme" };
    const result = ThreatAlertSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });
});

describe("FUSEStatsSchema", () => {
  const validStats = {
    totalEvents: 100000,
    eventsPerSec: 500,
    uptimeSec: 3600,
    dropped: 42,
    latency: { p50: 10, p90: 50, p99: 200 },
    opcodeDistribution: { FUSE_GETATTR: 40000, FUSE_READ: 30000 },
    throughputHistory: [100, 200, 300],
    activeClients: 2,
  };

  it("accepts valid stats", () => {
    const result = FUSEStatsSchema.safeParse(validStats);
    expect(result.success).toBe(true);
  });

  it("accepts stats without dropped field", () => {
    const { dropped, ...noDropped } = validStats;
    const result = FUSEStatsSchema.safeParse(noDropped);
    expect(result.success).toBe(true);
  });

  it("rejects missing latency fields", () => {
    const bad = { ...validStats, latency: { p50: 10 } };
    const result = FUSEStatsSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });
});

describe("WSMessageSchema", () => {
  it("dispatches event messages", () => {
    const msg = {
      type: "event",
      data: {
        ts: 1,
        op: 15,
        op_name: "FUSE_READ",
        node: 1,
        unique: 1,
        pid: 100,
        uid: 0,
        gid: 0,
        dir: "enter",
        error: 0,
        data_len: 0,
        latency_ns: 0,
        process_name: "test",
        container_id: "",
        pod_name: "",
        namespace: "",
      },
    };
    const result = WSMessageSchema.safeParse(msg);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe("event");
    }
  });

  it("dispatches alert messages", () => {
    const msg = {
      type: "alert",
      data: {
        ts: 1,
        type: "ransomware_pattern",
        severity: "critical",
        pid: 100,
        process_name: "test",
        details: {},
        ai_analysis: "",
      },
    };
    const result = WSMessageSchema.safeParse(msg);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe("alert");
    }
  });

  it("dispatches stats messages", () => {
    const msg = {
      type: "stats",
      data: {
        totalEvents: 0,
        eventsPerSec: 0,
        uptimeSec: 0,
        latency: { p50: 0, p90: 0, p99: 0 },
        opcodeDistribution: {},
        throughputHistory: [],
        activeClients: 0,
      },
    };
    const result = WSMessageSchema.safeParse(msg);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.type).toBe("stats");
    }
  });

  it("rejects unknown message type", () => {
    const msg = { type: "unknown", data: {} };
    const result = WSMessageSchema.safeParse(msg);
    expect(result.success).toBe(false);
  });
});
