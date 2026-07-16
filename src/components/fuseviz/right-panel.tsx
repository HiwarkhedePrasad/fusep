"use client";

import { useFuseViz } from "@/lib/fuse-context";
import {
  OPCODE_COLORS,
  DEFAULT_OPCODE_COLOR,
  SEVERITY_CONFIG,
  ALERT_TYPE_LABELS,
} from "@/lib/fuse-types";
import type { ThreatAlert, FUSEEvent } from "@/lib/fuse-types";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ShieldWarning, Brain, ChartLine } from "@phosphor-icons/react";

function formatTimestamp(ns: number): string {
  return new Date(ns / 1e6).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}

function EventDetail({ evt }: { evt: FUSEEvent }) {
  const color = OPCODE_COLORS[evt.op_name] || DEFAULT_OPCODE_COLOR;

  return (
    <div className="space-y-3 p-3">
      <div className="space-y-2">
        <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
          Event Details
        </h4>
        <div className="space-y-1.5">
          {[
            ["Opcode", evt.op_name, color],
            ["Opcode #", String(evt.op)],
            ["Node ID", String(evt.node)],
            ["Unique", String(evt.unique)],
            ["Direction", evt.dir],
            ["Syscall", evt.syscall || "—"],
            ["PID", String(evt.pid)],
            ["TID", evt.tid != null ? String(evt.tid) : "—"],
            ["UID", String(evt.uid)],
            ["GID", String(evt.gid)],
            ["Error", String(evt.error)],
            ["Data Len", `${evt.data_len} bytes`],
            ["Latency", `${(evt.latency_ns / 1e6).toFixed(3)}ms`],
            ["Timestamp", formatTimestamp(evt.ts)],
          ].map(([key, val, c]) => (
            <div
              key={key}
              className="flex justify-between items-center py-0.5 border-b border-border/30"
            >
              <span className="text-[10px] text-muted-foreground">{key}</span>
              <span
                className="text-[10px] font-mono font-semibold tabular-nums"
                style={c ? { color: c } : {}}
              >
                {val}
              </span>
            </div>
          ))}
        </div>
      </div>

      {evt.process_name && (
        <div className="space-y-2">
          <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
            Process Metadata
          </h4>
          <div className="space-y-1.5">
            {[
              ["Process", evt.process_name],
              ["Container", evt.container_id || "—"],
              ["Pod", evt.pod_name || "—"],
              ["Namespace", evt.namespace || "—"],
            ].map(([key, val]) => (
              <div
                key={key}
                className="flex justify-between items-center py-0.5 border-b border-border/30"
              >
                <span className="text-[10px] text-muted-foreground">{key}</span>
                <span className="text-[10px] font-mono tabular-nums">{val}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {evt.op_name === "FUSE_WRITE" && evt.write_data_text && (
        <div className="space-y-2">
          <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
            Write Payload
          </h4>
          <div className="space-y-1.5">
            <div className="flex justify-between items-center py-0.5 border-b border-border/30">
              <span className="text-[10px] text-muted-foreground">Captured</span>
              <span className="text-[10px] font-mono tabular-nums">
                {evt.write_data_len ?? 0} bytes
              </span>
            </div>
            <div className="bg-background/50 rounded-sm border border-border/30 p-2">
              <div className="text-[9px] text-muted-foreground mb-1">Text:</div>
              <pre className="text-[10px] font-mono text-foreground/90 whitespace-pre-wrap break-all leading-relaxed">
                {evt.write_data_text}
              </pre>
            </div>
            {evt.write_data_b64 && (
              <div className="bg-background/50 rounded-sm border border-border/30 p-2">
                <div className="text-[9px] text-muted-foreground mb-1">Base64:</div>
                <pre className="text-[9px] font-mono text-muted-foreground whitespace-pre-wrap break-all leading-relaxed max-h-16 overflow-y-auto">
                  {evt.write_data_b64}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="space-y-2">
        <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
          Raw JSON
        </h4>
        <pre className="text-[9px] font-mono text-muted-foreground bg-background/50 p-2 rounded-sm overflow-x-auto max-h-32">
          {JSON.stringify(evt, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function AlertDetail({ alert }: { alert: ThreatAlert }) {
  const sev = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.medium;

  return (
    <div className="space-y-3 p-3">
      <div
        className="rounded-sm p-3 border"
        style={{
          borderColor: `${sev.color}40`,
          backgroundColor: sev.bg,
        }}
      >
        <div className="flex items-center gap-2 mb-2">
          <ShieldWarning className="w-4 h-4" style={{ color: sev.color }} weight="fill" />
          <span className="text-xs font-semibold" style={{ color: sev.color }}>
            {ALERT_TYPE_LABELS[alert.type] || alert.type}
          </span>
          <Badge
            variant="outline"
            className="text-[8px] h-4 px-1 font-bold rounded-sm"
            style={{
              color: sev.color,
              borderColor: `${sev.color}60`,
              backgroundColor: sev.bg,
            }}
          >
            {sev.label}
          </Badge>
        </div>
        <div className="space-y-1 text-[10px] font-mono">
          {Object.entries(alert.details).map(([key, val]) => (
            <div key={key} className="flex justify-between">
              <span className="text-muted-foreground">{key}:</span>
              <span className="text-foreground tabular-nums">{String(val)}</span>
            </div>
          ))}
        </div>
      </div>

      {alert.ai_analysis && (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5">
            <Brain className="w-3 h-3 text-purple-400" weight="fill" />
            <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
              AI Threat Analysis
            </h4>
          </div>
          <div className="bg-purple-500/5 border border-purple-500/20 rounded-sm p-3">
            <p className="text-[10px] text-foreground/90 leading-relaxed whitespace-pre-wrap">
              {alert.ai_analysis}
            </p>
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
          Source Process
        </h4>
        {[
          ["PID", String(alert.pid)],
          ["Process", alert.process_name],
          ["Time", formatTimestamp(alert.ts)],
        ].map(([key, val]) => (
          <div
            key={key}
            className="flex justify-between items-center py-0.5 border-b border-border/30"
          >
            <span className="text-[10px] text-muted-foreground">{key}</span>
            <span className="text-[10px] font-mono tabular-nums">{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RightPanel() {
  const { selectedEvent, selectedAlert, alerts, selectEvent, selectAlert } =
    useFuseViz();

  const recentAlerts = alerts.slice(-20).reverse();
  const recentCritical = alerts.filter(
    (a) => a.severity === "critical" || a.severity === "high"
  ).length;

  return (
    <div className="flex flex-col h-full border-l border-border">
      <div className="flex border-b border-border">
        <button
          onClick={() => selectAlert(null)}
          className={`flex-1 py-2.5 text-[10px] uppercase tracking-widest font-semibold transition-colors border-b-2 active:bg-muted/20 ${
            !selectedAlert
              ? "text-primary border-primary"
              : "text-muted-foreground border-transparent hover:text-foreground"
          }`}
        >
          <ChartLine className="w-3 h-3 inline mr-1" />
          Detail
        </button>
        <button
          onClick={() => selectEvent(null)}
          className={`flex-1 py-2.5 text-[10px] uppercase tracking-widest font-semibold transition-colors border-b-2 relative active:bg-muted/20 ${
            selectedAlert || recentCritical > 0
              ? "text-primary border-primary"
              : "text-muted-foreground border-transparent hover:text-foreground"
          }`}
        >
          <ShieldWarning className="w-3 h-3 inline mr-1" weight="fill" />
          Threats
          {recentCritical > 0 && (
            <span className="absolute -top-0.5 -right-1 bg-destructive text-destructive-foreground text-[7px] font-bold px-1 py-0 rounded-full">
              {recentCritical}
            </span>
          )}
        </button>
      </div>

      <ScrollArea className="flex-1 fuse-scroll">
        {selectedAlert ? (
          <AlertDetail alert={selectedAlert} />
        ) : selectedEvent ? (
          <EventDetail evt={selectedEvent} />
        ) : recentAlerts.length > 0 ? (
          <div className="p-3 space-y-2">
            <h4 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold mb-2">
              Recent Threat Alerts
            </h4>
            {recentAlerts.map((alert, i) => {
              const sev = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.medium;
              return (
                <div
                  key={i}
                  onClick={() => selectAlert(alert)}
                  className="rounded-sm p-2.5 border cursor-pointer transition-all hover:bg-muted/30 active:scale-[0.99]"
                  style={{
                    borderColor: `${sev.color}30`,
                    backgroundColor: sev.bg,
                  }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span
                      className="text-[10px] font-semibold"
                      style={{ color: sev.color }}
                    >
                      {ALERT_TYPE_LABELS[alert.type] || alert.type}
                    </span>
                    <Badge
                      variant="outline"
                      className="text-[7px] h-3.5 px-1 font-bold rounded-sm"
                      style={{
                        color: sev.color,
                        borderColor: `${sev.color}60`,
                      }}
                    >
                      {sev.label}
                    </Badge>
                  </div>
                  <div className="text-[9px] font-mono text-muted-foreground tabular-nums">
                    PID {alert.pid} ({alert.process_name})
                  </div>
                  {alert.ai_analysis && (
                    <p className="text-[9px] text-foreground/60 mt-1 line-clamp-2">
                      {alert.ai_analysis.substring(0, 100)}...
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground text-xs gap-3 p-8">
            <div className="w-10 h-10 rounded-lg border border-border/50 bg-card flex items-center justify-center">
              <ChartLine className="w-5 h-5 text-muted-foreground/30" />
            </div>
            <div className="text-center">
              <p className="text-[11px] font-medium text-foreground/60">No selection</p>
              <p className="text-[9px] text-muted-foreground mt-1">Click an event row to inspect its details, or select a threat alert</p>
            </div>
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
