import { z } from "zod";

export const FUSEEventSchema = z.object({
  ts: z.number(),
  op: z.number().int(),
  op_name: z.string(),
  node: z.number(),
  unique: z.number(),
  pid: z.number().int(),
  tid: z.number().int().optional(),
  uid: z.number().int(),
  gid: z.number().int(),
  dir: z.enum(["enter", "exit"]),
  syscall: z.enum(["read", "write"]).optional(),
  error: z.number(),
  data_len: z.number(),
  latency_ns: z.number(),
  ret_val: z.number().optional(),
  process_name: z.string(),
  container_id: z.string(),
  pod_name: z.string(),
  namespace: z.string(),
  write_data_b64: z.string().optional(),
  write_data_text: z.string().optional(),
  write_data_len: z.number().optional(),
});

export const ThreatAlertSchema = z.object({
  ts: z.number(),
  type: z.enum(["ransomware_pattern", "data_exfiltration", "anomaly_detected"]),
  severity: z.enum(["low", "medium", "high", "critical"]),
  pid: z.number().int(),
  process_name: z.string(),
  details: z.record(z.string(), z.unknown()),
  ai_analysis: z.string(),
});

export const FUSEStatsSchema = z.object({
  totalEvents: z.number(),
  eventsPerSec: z.number(),
  uptimeSec: z.number(),
  dropped: z.number().optional(),
  latency: z.object({
    p50: z.number(),
    p90: z.number(),
    p99: z.number(),
  }),
  opcodeDistribution: z.record(z.string(), z.number()),
  throughputHistory: z.array(z.number()),
  activeClients: z.number(),
});

export const WSMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("event"), data: FUSEEventSchema }),
  z.object({ type: z.literal("alert"), data: ThreatAlertSchema }),
  z.object({ type: z.literal("stats"), data: FUSEStatsSchema }),
]);