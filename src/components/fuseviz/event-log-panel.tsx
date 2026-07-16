"use client";

import { useFuseViz } from "@/lib/fuse-context";
import { OPCODE_COLORS, DEFAULT_OPCODE_COLOR } from "@/lib/fuse-types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  MagnifyingGlass,
  Pause,
  Play,
  Trash,
  Download,
  WifiHigh,
  WifiSlash,
} from "@phosphor-icons/react";
import { useCallback, useMemo, useRef, useEffect } from "react";
import type { FUSEEvent } from "@/lib/fuse-types";

function formatLatency(ns: number): string {
  if (ns < 1000) return `${ns}ns`;
  if (ns < 1_000_000) return `${(ns / 1000).toFixed(1)}μs`;
  return `${(ns / 1_000_000).toFixed(2)}ms`;
}

function formatTimestamp(ns: number): string {
  const ms = ns / 1e6;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function EventRow({
  evt,
  isSelected,
  onClick,
}: {
  evt: FUSEEvent;
  isSelected: boolean;
  onClick: () => void;
}) {
  const color = OPCODE_COLORS[evt.op_name] || DEFAULT_OPCODE_COLOR;

  return (
    <div
      onClick={onClick}
      className={`grid grid-cols-[80px_100px_80px_80px_1fr] items-center gap-1 px-3 h-8 cursor-pointer transition-colors border-b border-border/30 text-xs font-mono ${
        isSelected
          ? "bg-primary/10 border-l-2 border-l-primary"
          : "hover:bg-muted/40 active:bg-muted/60 border-l-2 border-l-transparent"
      }`}
    >
      <span className="text-muted-foreground text-[10px] tabular-nums">
        {formatTimestamp(evt.ts)}
      </span>
      <span>
        <Badge
          variant="outline"
          className="text-[9px] font-semibold px-1.5 py-0 h-5 border rounded-sm"
          style={{
            color,
            borderColor: `${color}60`,
            backgroundColor: `${color}15`,
          }}
        >
          {evt.op_name.replace("FUSE_", "")}
        </Badge>
      </span>
      <span className="text-muted-foreground text-[10px] tabular-nums">n:{evt.node}</span>
      <span className="text-muted-foreground text-[10px] tabular-nums">
        {formatLatency(evt.latency_ns)}
      </span>
      <span className="text-foreground/80 truncate text-[10px]">
        {evt.process_name || `pid:${evt.pid}`}
        {evt.container_id ? ` [${evt.container_id.slice(0, 8)}]` : ""}
      </span>
    </div>
  );
}

export function EventLogPanel() {
  const {
    events,
    alerts,
    stats,
    connected,
    paused,
    filterOpcodes,
    searchQuery,
    selectedEvent,
    togglePause,
    selectEvent,
    toggleOpcodeFilter,
    setSearchQuery,
    clearEvents,
  } = useFuseViz();

  const scrollRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);

  const filteredEvents = useMemo(() => {
    let result = events;
    if (filterOpcodes.size > 0) {
      result = result.filter((e) => filterOpcodes.has(e.op_name));
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (e) =>
          e.op_name.toLowerCase().includes(q) ||
          e.process_name.toLowerCase().includes(q) ||
          String(e.pid).includes(q) ||
          String(e.node).includes(q)
      );
    }
    return result;
  }, [events, filterOpcodes, searchQuery]);

  const opcodeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const evt of events) {
      counts[evt.op_name] = (counts[evt.op_name] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [events]);

  useEffect(() => {
    if (autoScrollRef.current && scrollRef.current && !paused) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredEvents, paused]);

  const handleScroll = useCallback(() => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    autoScrollRef.current = scrollTop + clientHeight >= scrollHeight - 50;
  }, []);

  const exportEvents = useCallback(() => {
    const data = events.map((e) => JSON.stringify(e)).join("\n");
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fuseviz_events_${Date.now()}.ndjson`;
    a.click();
    URL.revokeObjectURL(url);
  }, [events]);

  const total = opcodeCounts.reduce((sum, [, c]) => sum + c, 0) || 1;

  return (
    <div className="flex h-full">
      <div className="w-52 border-r border-border flex flex-col shrink-0">
        <div className="p-3 border-b border-border">
          <h3 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
            Opcodes
          </h3>
        </div>
        <ScrollArea className="flex-1 fuse-scroll">
          <div className="p-2 space-y-0.5">
            {opcodeCounts.map(([name, count]) => {
              const color = OPCODE_COLORS[name] || DEFAULT_OPCODE_COLOR;
              const pct = Math.round((count / total) * 100);
              const active = filterOpcodes.has(name);
              return (
                <div
                  key={name}
                  onClick={() => toggleOpcodeFilter(name)}
                  className={`flex items-center gap-2 px-2 py-1.5 rounded-sm cursor-pointer transition-colors text-xs ${
                    active
                      ? "bg-primary/10 border border-primary/30"
                      : "hover:bg-muted/40 active:bg-muted/60 border border-transparent"
                  }`}
                >
                  <span
                    className="font-mono font-semibold text-[10px] w-16 truncate"
                    style={{ color }}
                  >
                    {name.replace("FUSE_", "")}
                  </span>
                  <div className="flex-1 h-1 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: `${color}40`,
                      }}
                    />
                  </div>
                  <span className="text-muted-foreground text-[9px] font-mono w-8 text-right tabular-nums">
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </ScrollArea>
      </div>

      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex items-center gap-2 px-4 py-2 border-b border-border">
          <h3 className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
            Event Log
          </h3>
          <div className="ml-auto flex items-center gap-1.5">
            <div className="relative">
              <MagnifyingGlass className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
              <Input
                placeholder="search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-7 w-32 text-[10px] pl-6 font-mono bg-background border-border"
              />
            </div>
            <Separator orientation="vertical" className="h-5" />
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-[10px] active:scale-[0.97]"
              onClick={togglePause}
            >
              {paused ? (
                <Play className="w-3 h-3 mr-1" weight="fill" />
              ) : (
                <Pause className="w-3 h-3 mr-1" weight="fill" />
              )}
              {paused ? "Resume" : "Pause"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-[10px] text-destructive active:scale-[0.97]"
              onClick={clearEvents}
            >
              <Trash className="w-3 h-3 mr-1" />
              Clear
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-[10px] active:scale-[0.97]"
              onClick={exportEvents}
            >
              <Download className="w-3 h-3 mr-1" />
              Export
            </Button>
          </div>
        </div>

        {paused && (
          <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 py-1 text-[10px] font-mono text-amber-400 text-center">
            PAUSED — events are being buffered
          </div>
        )}

        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="flex-1 overflow-y-auto fuse-scroll font-mono"
        >
          {filteredEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-muted-foreground text-xs gap-3 p-8">
              {connected ? (
                <>
                  <div className="w-10 h-10 rounded-lg border border-border/50 bg-card flex items-center justify-center">
                    <WifiHigh className="w-5 h-5 text-primary/40" weight="fill" />
                  </div>
                  <div className="text-center">
                    <p className="text-[11px] font-medium text-foreground/60">Waiting for events</p>
                    <p className="text-[9px] text-muted-foreground mt-1">The daemon is connected but no FUSE operations have been captured yet</p>
                  </div>
                </>
              ) : (
                <>
                  <div className="w-10 h-10 rounded-lg border border-border/50 bg-card flex items-center justify-center">
                    <WifiSlash className="w-5 h-5 text-destructive/40" weight="fill" />
                  </div>
                  <div className="text-center">
                    <p className="text-[11px] font-medium text-foreground/60">Disconnected</p>
                    <p className="text-[9px] text-muted-foreground mt-1">Connecting to daemon at ws://localhost:8080/ws</p>
                  </div>
                </>
              )}
            </div>
          ) : (
            filteredEvents.map((evt, i) => (
              <EventRow
                key={`${evt.unique}-${i}`}
                evt={evt}
                isSelected={selectedEvent?.unique === evt.unique}
                onClick={() => selectEvent(evt)}
              />
            ))
          )}
        </div>

        <div className="flex items-center gap-3 px-4 py-1.5 border-t border-border text-[9px] font-mono text-muted-foreground">
          <span className="tabular-nums">{filteredEvents.length} events</span>
          <Separator orientation="vertical" className="h-3" />
          <span className="tabular-nums">{stats?.eventsPerSec ?? 0} ev/s</span>
          <Separator orientation="vertical" className="h-3" />
          <span className="tabular-nums">P50: {formatLatency(stats?.latency.p50 ?? 0)}</span>
          <span className="tabular-nums">P90: {formatLatency(stats?.latency.p90 ?? 0)}</span>
          <span className="tabular-nums">P99: {formatLatency(stats?.latency.p99 ?? 0)}</span>
        </div>
      </div>
    </div>
  );
}
