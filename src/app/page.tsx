"use client";

import { FuseVizProvider, useFuseViz } from "@/lib/fuse-context";
import { TopBar } from "@/components/fuseviz/top-bar";
import { EventLogPanel } from "@/components/fuseviz/event-log-panel";
import { SequenceDiagram } from "@/components/fuseviz/sequence-diagram";
import {
  ThroughputChart,
  LatencySparklines,
  OpcodeBarChart,
} from "@/components/fuseviz/metrics-charts";
import { RightPanel } from "@/components/fuseviz/right-panel";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";

function Dashboard() {
  const { events, stats } = useFuseViz();

  return (
    <div className="h-screen w-screen flex flex-col bg-background text-foreground overflow-hidden">
      {/* Top Bar */}
      <TopBar />

      {/* Main content area */}
      <div className="flex-1 flex min-h-0">
        {/* Left: Event log + sidebar */}
        <div className="flex-1 flex min-w-0">
          <EventLogPanel />
        </div>

        {/* Right panel: Tabs with Sequence, Metrics, Threats */}
        <div className="w-80 shrink-0 flex flex-col">
          <Tabs defaultValue="sequence" className="flex flex-col h-full">
            <TabsList className="w-full rounded-none border-b border-border bg-card/50 h-9 p-0">
              <TabsTrigger
                value="sequence"
                className="flex-1 text-[9px] uppercase tracking-widest h-full rounded-none data-[state=active]:bg-background data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none"
              >
                Sequence
              </TabsTrigger>
              <TabsTrigger
                value="metrics"
                className="flex-1 text-[9px] uppercase tracking-widest h-full rounded-none data-[state=active]:bg-background data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none"
              >
                Metrics
              </TabsTrigger>
              <TabsTrigger
                value="detail"
                className="flex-1 text-[9px] uppercase tracking-widest h-full rounded-none data-[state=active]:bg-background data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none"
              >
                Detail
              </TabsTrigger>
            </TabsList>

            <TabsContent
              value="sequence"
              className="flex-1 m-0 overflow-hidden"
            >
              <SequenceDiagram events={events} />
            </TabsContent>

            <TabsContent
              value="metrics"
              className="flex-1 m-0 overflow-y-auto fuse-scroll"
            >
              <div className="p-2 space-y-2">
                <ThroughputChart />
                <LatencySparklines />
                <OpcodeBarChart />
              </div>
            </TabsContent>

            <TabsContent value="detail" className="flex-1 m-0 overflow-hidden">
              <RightPanel />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  return (
    <FuseVizProvider>
      <Dashboard />
    </FuseVizProvider>
  );
}
