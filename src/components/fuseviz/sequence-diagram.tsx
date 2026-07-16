"use client";

import { useFuseViz } from "@/lib/fuse-context";
import { OPCODE_COLORS, DEFAULT_OPCODE_COLOR } from "@/lib/fuse-types";
import type { FUSEEvent } from "@/lib/fuse-types";
import { ScrollArea } from "@/components/ui/scroll-area";

// ── Sequence diagram actors ──
const ACTORS = ["Kernel", "FuseViz", "VFS"];
const ACTOR_X = [40, 140, 240];
const SVG_W = 280;
const ROW_H = 22;
const HEADER_H = 32;

function eventDirection(evt: FUSEEvent): [number, number] {
  // Use the actual direction from the event data
  if (evt.dir === "exit") return [1, 0]; // FuseViz → Kernel
  return [0, 1]; // Kernel → FuseViz (default: enter/request)
}

interface SequenceDiagramProps {
  events: FUSEEvent[];
  maxRows?: number;
}

export function SequenceDiagram({ events, maxRows = 50 }: SequenceDiagramProps) {
  const recentEvents = events.slice(-maxRows);

  const svgH = HEADER_H + recentEvents.length * ROW_H + 20;

  return (
    <ScrollArea className="h-full fuse-scroll">
      <svg
        width="100%"
        viewBox={`0 0 ${SVG_W} ${Math.max(svgH, 60)}`}
        className="font-mono"
        style={{ minHeight: "100%" }}
      >
        {/* Lifelines */}
        {ACTORS.map((name, i) => (
          <g key={name}>
            <line
              x1={ACTOR_X[i]}
              y1={HEADER_H}
              x2={ACTOR_X[i]}
              y2={svgH - 10}
              stroke="currentColor"
              className="text-border"
              strokeWidth={1}
            />
            <rect
              x={ACTOR_X[i] - 30}
              y={6}
              width={60}
              height={18}
              rx={3}
              className="fill-card stroke-border"
              strokeWidth={0.5}
            />
            <text
              x={ACTOR_X[i]}
              y={18}
              textAnchor="middle"
              fontSize={8}
              className="fill-muted-foreground"
              fontWeight={600}
            >
              {name}
            </text>
          </g>
        ))}

        {/* Events */}
        {recentEvents.length === 0 && (
          <text
            x={SVG_W / 2}
            y={50}
            textAnchor="middle"
            fontSize={10}
            className="fill-muted-foreground"
          >
            No events yet
          </text>
        )}

        {recentEvents.map((evt, i) => {
          const color = OPCODE_COLORS[evt.op_name] || DEFAULT_OPCODE_COLOR;
          const [si, di] = eventDirection(evt);
          const x1 = ACTOR_X[si];
          const x2 = ACTOR_X[di];
          const dir = x2 > x1 ? 1 : -1;
          const y = HEADER_H + i * ROW_H + ROW_H / 2;

          const label = evt.op_name.replace("FUSE_", "");

          return (
            <g key={`${evt.unique}-${i}`}>
              {/* Arrow line */}
              <line
                x1={x1 + dir * 4}
                y1={y}
                x2={x2 - dir * 8}
                y2={y}
                stroke={color}
                strokeWidth={1}
                opacity={0.7}
              />
              {/* Arrowhead */}
              <polygon
                points={`${x2 - dir * 8},${y - 3} ${x2 - dir * 2},${y} ${
                  x2 - dir * 8
                },${y + 3}`}
                fill={color}
                opacity={0.7}
              />
              {/* Label */}
              <text
                x={(x1 + x2) / 2}
                y={y - 3}
                textAnchor="middle"
                fontSize={7}
                fill={color}
                opacity={0.9}
              >
                {label}
              </text>
            </g>
          );
        })}
      </svg>
    </ScrollArea>
  );
}
