"use client";

import { useFuseViz } from "@/lib/fuse-context";
import { OPCODE_COLORS, DEFAULT_OPCODE_COLOR } from "@/lib/fuse-types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from "recharts";

function formatLatency(ns: number): string {
  if (ns < 1000) return `${ns}ns`;
  if (ns < 1_000_000) return `${(ns / 1000).toFixed(1)}μs`;
  return `${(ns / 1_000_000).toFixed(2)}ms`;
}

const tooltipStyle = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 6,
  fontSize: 10,
  fontFamily: "monospace",
} as const;

export function ThroughputChart() {
  const { stats } = useFuseViz();

  const data = (stats?.throughputHistory ?? []).map((val, i) => ({
    sec: `-${59 - i}s`,
    events: val,
  }));

  return (
    <Card className="bg-card/50 border-border h-full">
      <CardHeader className="pb-2 pt-3 px-4">
        <CardTitle className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
          Throughput (ev/s)
        </CardTitle>
      </CardHeader>
      <CardContent className="px-2 pb-2">
        <ResponsiveContainer width="100%" height={80}>
          <LineChart data={data}>
            <XAxis dataKey="sec" hide />
            <YAxis hide />
            <Tooltip
              contentStyle={tooltipStyle}
              labelStyle={{ color: "hsl(var(--muted-foreground))" }}
              itemStyle={{ color: "hsl(var(--primary))" }}
            />
            <Line
              type="monotone"
              dataKey="events"
              stroke="#38bdf8"
              strokeWidth={1.5}
              dot={false}
              fill="url(#throughputGradient)"
            />
            <defs>
              <linearGradient id="throughputGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
              </linearGradient>
            </defs>
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

export function LatencySparklines() {
  const { stats } = useFuseViz();

  const lat = stats?.latency ?? { p50: 0, p90: 0, p99: 0 };

  const metrics = [
    { label: "P50", value: lat.p50, color: "#4ade80" },
    { label: "P90", value: lat.p90, color: "#fbbf24" },
    { label: "P99", value: lat.p99, color: "#fb7185" },
  ];

  return (
    <Card className="bg-card/50 border-border">
      <CardHeader className="pb-2 pt-3 px-4">
        <CardTitle className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
          Latency Percentiles
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-3">
        <div className="grid grid-cols-3 gap-2">
          {metrics.map((m) => (
            <div key={m.label} className="text-center">
              <div className="text-[9px] uppercase tracking-wider text-muted-foreground mb-1">
                {m.label}
              </div>
              <div
                className="text-sm font-mono font-bold"
                style={{ color: m.color }}
              >
                {formatLatency(m.value)}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function OpcodeBarChart() {
  const { stats } = useFuseViz();

  const dist = stats?.opcodeDistribution ?? {};
  const data = Object.entries(dist)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, count]) => ({
      name: name.replace("FUSE_", ""),
      count,
      color: OPCODE_COLORS[name] || DEFAULT_OPCODE_COLOR,
    }));

  return (
    <Card className="bg-card/50 border-border">
      <CardHeader className="pb-2 pt-3 px-4">
        <CardTitle className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
          Opcode Distribution
        </CardTitle>
      </CardHeader>
      <CardContent className="px-2 pb-2">
        <ResponsiveContainer width="100%" height={100}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="name"
              width={60}
              tick={{ fontSize: 8, fontFamily: "monospace", fill: "#64748b" }}
            />
            <Tooltip contentStyle={tooltipStyle} />
            <Bar dataKey="count" radius={[0, 3, 3, 0]}>
              {data.map((entry, i) => (
                <Cell key={i} fill={`${entry.color}80`} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
