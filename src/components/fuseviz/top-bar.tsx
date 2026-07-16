"use client";

import { useFuseViz } from "@/lib/fuse-context";
import { Cpu, WifiHigh, WifiSlash } from "@phosphor-icons/react";

function formatLatency(ns: number): string {
  if (ns < 1000) return `${ns}ns`;
  if (ns < 1_000_000) return `${(ns / 1000).toFixed(0)}μs`;
  return `${(ns / 1_000_000).toFixed(1)}ms`;
}

function formatUptime(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return `${h}h ${m}m`;
}

export function TopBar() {
  const { connected, stats, paused, alerts } = useFuseViz();

  const criticalAlerts = alerts.filter(
    (a) => a.severity === "critical" || a.severity === "high"
  ).length;

  return (
    <header className="h-11 border-b border-border bg-card flex items-center gap-4 px-4 shrink-0 select-none">
      <div className="flex items-center gap-2">
        <Cpu className="w-4 h-4 text-primary" weight="fill" />
        <span className="font-mono font-semibold text-sm tracking-tight">
          fuse<span className="text-muted-foreground/60">-proto-</span>
          <span className="text-primary">viz</span>
        </span>
        <span className="text-[9px] font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded-sm">
          C++
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        {connected ? (
          <WifiHigh className="w-3.5 h-3.5 text-emerald-400" weight="fill" />
        ) : (
          <WifiSlash className="w-3.5 h-3.5 text-destructive" weight="fill" />
        )}
        <span className="text-[10px] font-mono text-muted-foreground tabular-nums">
          {connected ? "LIVE" : "OFFLINE"}
        </span>
        {paused && connected && (
          <span className="text-[9px] font-mono text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded-sm ml-1">
            PAUSED
          </span>
        )}
      </div>

      <div className="flex-1" />

      <div className="flex items-center gap-4">
        <div className="flex flex-col items-end">
          <span className="text-sm font-mono font-bold text-foreground leading-none tabular-nums">
            {stats?.totalEvents?.toLocaleString() ?? "0"}
          </span>
          <span className="text-[8px] uppercase tracking-widest text-muted-foreground">
            Events
          </span>
        </div>

        <div className="w-px h-7 bg-border" />

        <div className="flex flex-col items-end">
          <span className="text-sm font-mono font-bold text-primary leading-none tabular-nums">
            {stats?.eventsPerSec ?? 0}
          </span>
          <span className="text-[8px] uppercase tracking-widest text-muted-foreground">
            Ev/s
          </span>
        </div>

        <div className="w-px h-7 bg-border" />

        <div className="flex flex-col items-end">
          <span className="text-sm font-mono font-bold text-amber-400 leading-none tabular-nums">
            {formatLatency(stats?.latency.p99 ?? 0)}
          </span>
          <span className="text-[8px] uppercase tracking-widest text-muted-foreground">
            P99
          </span>
        </div>

        <div className="w-px h-7 bg-border" />

        <div className="flex items-center gap-1.5">
          <div className={`w-2 h-2 rounded-full ${criticalAlerts > 0 ? "bg-destructive" : "bg-muted-foreground/40"}`} />
          <div className="flex flex-col items-end">
            <span
              className={`text-sm font-mono font-bold leading-none tabular-nums ${
                criticalAlerts > 0 ? "text-destructive" : "text-foreground"
              }`}
            >
              {criticalAlerts}
            </span>
            <span className="text-[8px] uppercase tracking-widest text-muted-foreground">
              Threats
            </span>
          </div>
        </div>

        <div className="w-px h-7 bg-border" />

        <div className="flex flex-col items-end">
          <span className="text-sm font-mono font-bold text-muted-foreground leading-none tabular-nums">
            {formatUptime(stats?.uptimeSec ?? 0)}
          </span>
          <span className="text-[8px] uppercase tracking-widest text-muted-foreground">
            Uptime
          </span>
        </div>
      </div>
    </header>
  );
}
