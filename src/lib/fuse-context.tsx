"use client";

import React, {
  createContext,
  useContext,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import type { FUSEEvent, ThreatAlert, FUSEStats } from "./fuse-types";
import { WSMessageSchema } from "./ws-schemas";

interface FuseVizState {
  connected: boolean;
  backend: string;
  events: FUSEEvent[];
  alerts: ThreatAlert[];
  stats: FUSEStats | null;
  paused: boolean;
  selectedEvent: FUSEEvent | null;
  selectedAlert: ThreatAlert | null;
  filterOpcodes: Set<string>;
  searchQuery: string;
  togglePause: () => void;
  selectEvent: (evt: FUSEEvent | null) => void;
  selectAlert: (alert: ThreatAlert | null) => void;
  toggleOpcodeFilter: (opcode: string) => void;
  setSearchQuery: (q: string) => void;
  clearEvents: () => void;
}

function useWebSocket(url: string, paused: boolean,
  onEvent: (evt: FUSEEvent) => void,
  onAlert: (alert: ThreatAlert) => void,
  onStats: (stats: FUSEStats) => void,
  onConnected: (connected: boolean) => void)
{
  const reconnectRef = useRef<number>(0);
  const timerRef = useRef<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const mountedRef = useRef(true);
  const connectingRef = useRef(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return;
    // Cap at 10s max, not 30s — faster recovery for demo
    const delay = Math.min(1000 * Math.pow(1.5, reconnectRef.current), 10000);
    reconnectRef.current++;
    console.log(`[WS] Reconnecting in ${Math.round(delay)}ms (attempt ${reconnectRef.current})`);
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      if (mountedRef.current) doConnect();
    }, delay);
  }, []);

  const doConnect = useCallback(() => {
    if (!mountedRef.current) return;
    // Prevent double-connect (React strict mode, rapid reconnect)
    if (connectingRef.current) return;
    connectingRef.current = true;

    // Cancel any pending reconnect timer
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }

    // Close old socket cleanly (detach handlers first to avoid loop)
    if (wsRef.current) {
      const oldWs = wsRef.current;
      oldWs.onclose = null;
      oldWs.onerror = null;
      oldWs.onmessage = null;
      oldWs.onopen = null;
      try { oldWs.close(); } catch {}
      wsRef.current = null;
    }

    const wsToken = process.env.NEXT_PUBLIC_WS_TOKEN || "fuseviz-dev-key";
    const ws = new WebSocket(url, [wsToken]);
    wsRef.current = ws;
    let settled = false;

    ws.onopen = () => {
      if (settled) return;
      settled = true;
      connectingRef.current = false;
      reconnectRef.current = 0;
      onConnected(true);
    };

    ws.onclose = (ev) => {
      if (settled) return;
      settled = true;
      connectingRef.current = false;
      onConnected(false);
      wsRef.current = null;
      // Don't reconnect if component is unmounting
      if (mountedRef.current) scheduleReconnect();
    };

    ws.onerror = () => {
      // onerror is always followed by onclose — don't do anything here
      // to avoid double-handling. The onclose handler will manage reconnection.
    };

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        const result = WSMessageSchema.safeParse(parsed);
        if (!result.success) {
          console.warn("[WS] Validation failed:", result.error.flatten());
          return;
        }
        const msg = result.data;
        if (msg.type === "event") {
          if (!pausedRef.current) onEvent(msg.data as FUSEEvent);
        } else if (msg.type === "alert") {
          onAlert(msg.data as ThreatAlert);
        } else if (msg.type === "stats") {
          onStats(msg.data as FUSEStats);
        }
      } catch (e) { console.error("[WS] Parse error:", e); }
    };

    // Settle guard: if onopen AND onclose both fire (e.g. immediate reject),
    // only the first one should handle state
    setTimeout(() => {
      if (!settled) {
        settled = true;
        connectingRef.current = false;
        if (ws.readyState !== WebSocket.OPEN) {
          onConnected(false);
          wsRef.current = null;
          if (mountedRef.current) scheduleReconnect();
        }
      }
    }, 5000);
  }, [url, onEvent, onAlert, onStats, onConnected, scheduleReconnect]);

  useEffect(() => {
    mountedRef.current = true;
    doConnect();
    return () => {
      mountedRef.current = false;
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      if (wsRef.current) {
        const oldWs = wsRef.current;
        oldWs.onclose = null;
        oldWs.onerror = null;
        oldWs.onmessage = null;
        oldWs.onopen = null;
        try { oldWs.close(); } catch {}
        wsRef.current = null;
      }
    };
  }, [doConnect]);
}

const FuseVizContext = createContext<FuseVizState | null>(null);

export function useFuseViz() {
  const ctx = useContext(FuseVizContext);
  if (!ctx) throw new Error("useFuseViz must be used within FuseVizProvider");
  return ctx;
}

const MAX_EVENTS = 2000;
const MAX_ALERTS = 200;

export function FuseVizProvider({ children }: { children: React.ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [backend] = useState<string>("C++20 / simple_ws");
  const [events, setEvents] = useState<FUSEEvent[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [stats, setStats] = useState<FUSEStats | null>(null);
  const [paused, setPaused] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<FUSEEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [filterOpcodes, setFilterOpcodes] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");

  const eventBufferRef = useRef<FUSEEvent[]>([]);
  const alertBufferRef = useRef<ThreatAlert[]>([]);
  const rafIdRef = useRef<number>(0);

  const pushEvent = useCallback((evt: FUSEEvent) => {
    eventBufferRef.current.push(evt);
  }, []);

  const pushAlert = useCallback((alert: ThreatAlert) => {
    alertBufferRef.current.push(alert);
  }, []);

  const setStatsCb = useCallback((s: FUSEStats) => {
    setStats(s);
  }, []);

  const flushBuffers = useCallback(() => {
    if (eventBufferRef.current.length > 0) {
      const newEvents = eventBufferRef.current;
      eventBufferRef.current = [];
      setEvents((prev) => {
        const combined = [...prev, ...newEvents];
        return combined.length > MAX_EVENTS
          ? combined.slice(combined.length - MAX_EVENTS)
          : combined;
      });
    }
    if (alertBufferRef.current.length > 0) {
      const newAlerts = alertBufferRef.current;
      alertBufferRef.current = [];
      setAlerts((prev) => {
        const combined = [...prev, ...newAlerts];
        return combined.length > MAX_ALERTS
          ? combined.slice(combined.length - MAX_ALERTS)
          : combined;
      });
    }
  }, []);

  useEffect(() => {
    const loop = () => {
      flushBuffers();
      rafIdRef.current = requestAnimationFrame(loop);
    };
    rafIdRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafIdRef.current);
  }, [flushBuffers]);

  useWebSocket(
    `ws://${typeof window !== "undefined" ? window.location.hostname : "localhost"}:8080/ws`,
    paused, pushEvent, pushAlert, setStatsCb, setConnected
  );

  const togglePause = useCallback(() => {
    setPaused((p) => !p);
  }, []);

  const toggleOpcodeFilter = useCallback((opcode: string) => {
    setFilterOpcodes((prev) => {
      const next = new Set(prev);
      if (next.has(opcode)) {
        next.delete(opcode);
      } else {
        next.add(opcode);
      }
      return next;
    });
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
    setAlerts([]);
  }, []);

  const value: FuseVizState = {
    connected,
    backend,
    events,
    alerts,
    stats,
    paused,
    selectedEvent,
    selectedAlert,
    filterOpcodes,
    searchQuery,
    togglePause,
    selectEvent: setSelectedEvent,
    selectAlert: setSelectedAlert,
    toggleOpcodeFilter,
    setSearchQuery,
    clearEvents,
  };

  return (
    <FuseVizContext.Provider value={value}>{children}</FuseVizContext.Provider>
  );
}
