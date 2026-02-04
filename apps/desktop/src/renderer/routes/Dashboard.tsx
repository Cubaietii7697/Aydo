import { Button, Skeleton } from "@nextui-org/react";
import { motion } from "framer-motion";
import {
  BellRing,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Cpu,
  Database,
  Radar,
  Sigma,
  Cloud,
  Activity,
  Layers
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import ActivityChart from "../components/ActivityChart";
import DonutChart from "../components/DonutChart";
import EventsTable from "../components/EventsTable";
import KpiCard from "../components/KpiCard";
import Shell from "../components/Shell";
import { antivirusService, useAntivirus } from "../services/antivirusService";

const Dashboard = () => {
  const antivirus = useAntivirus();
  const [severityFilter, setSeverityFilter] = useState<"all" | "high" | "medium" | "low">("all");

  const handleManualScan = async () => {
    const result = await antivirusService.requestScan(antivirus.settings.scanDepth);
    if (!result.ok && result.message !== "No file selected") {
      toast.message(result.message);
    }
  };

  useEffect(() => {
    const unsubscribe = antivirusService.onEvent(({ event }) => {
      if (event.type === "threat_detected") {
        toast.error(event.message, { description: "Immediate remediation applied." });
      }
      if (event.type === "scan_complete") {
        toast.success("Scan completed", { description: "No action required." });
      }
      if (event.type === "status" && event.severity !== "low") {
        toast.message(event.message);
      }
    });

    return () => unsubscribe();
  }, []);

  const lastScanMinutes = antivirus.stats.lastScanAt
    ? Math.max(1, Math.round((Date.now() - new Date(antivirus.stats.lastScanAt).getTime()) / 60000))
    : 0;
  const lastScanLabel = antivirus.stats.lastScanAt ? `${lastScanMinutes} min ago` : "No scan yet";

  const filteredEvents = useMemo(() => {
    if (severityFilter === "all") {
      return antivirus.recentEvents;
    }
    return antivirus.recentEvents.filter((event) => event.severity === severityFilter);
  }, [antivirus.recentEvents, severityFilter]);

  const hasEvent = (matcher: (message: string) => boolean) =>
    antivirus.recentEvents.some((event) => matcher(event.message));

  const capabilityState = (matcher: (message: string) => boolean) => {
    if (antivirus.connectionState !== "connected") {
      return "standby" as const;
    }
    return hasEvent(matcher) ? "online" : "unknown";
  };

  const capabilities = [
    {
      key: "driver",
      label: "Driver",
      icon: Cpu,
      state: capabilityState((message) => {
        const lower = message.toLowerCase();
        return lower.includes("driver connected") || lower.includes("connected to driver");
      })
    },
    {
      key: "hashdb",
      label: "Hash DB",
      icon: Database,
      state: capabilityState((message) => message.toLowerCase().includes("hashes database"))
    },
    {
      key: "yara",
      label: "YARA",
      icon: Radar,
      state: capabilityState((message) => message.toLowerCase().includes("yara scanning engine"))
    },
    {
      key: "entropy",
      label: "Entropy",
      icon: Sigma,
      state: capabilityState((message) => message.toLowerCase().includes("[entropy]"))
    },
    {
      key: "cloud",
      label: "Cloud",
      icon: Cloud,
      state: capabilityState((message) => message.toLowerCase().includes("[server]") || message.toLowerCase().includes("connecting to server"))
    }
  ];

  const capabilityStyle = (state: "online" | "standby" | "unknown") => {
    switch (state) {
      case "online":
        return "border border-accent/40 bg-accent/15 text-accent";
      case "standby":
        return "border border-white/10 bg-white/5 text-muted";
      default:
        return "border border-white/10 bg-white/5 text-slate-500 dark:text-white/50";
    }
  };

  return (
    <Shell title="Dashboard" subtitle="Realtime engine telemetry and incident stream.">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex flex-col gap-6"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-sm text-muted">Ops Overview</p>
            <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">Command Status</h2>
          </div>
          <div className="text-xs text-muted">
            {antivirus.engineType === "client" ? "Client engine active" : "Simulator session"}
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="glass-panel rounded-2xl p-5 shadow-soft">
            <div className="flex items-center justify-between text-xs text-muted">
              <span>Connection</span>
              <Activity size={16} className="text-accent" />
            </div>
            <p className="mt-3 font-display text-lg font-semibold text-slate-900 dark:text-white">
              {antivirus.connectionState}
            </p>
            <p className="mt-2 text-xs text-muted">{antivirus.statusMessage}</p>
          </div>
          <div className="glass-panel rounded-2xl p-5 shadow-soft">
            <div className="flex items-center justify-between text-xs text-muted">
              <span>Engine</span>
              <ShieldCheck size={16} className="text-accent" />
            </div>
            <p className="mt-3 font-display text-lg font-semibold text-slate-900 dark:text-white">
              {antivirus.engineType === "client" ? "Client Engine" : "Simulator"}
            </p>
            <p className="mt-2 text-xs text-muted">{antivirus.engineType === "client" ? "Local runtime active" : "Telemetry demo mode"}</p>
          </div>
          <div className="glass-panel rounded-2xl p-5 shadow-soft">
            <div className="flex items-center justify-between text-xs text-muted">
              <span>Last Scan</span>
              <ShieldAlert size={16} className="text-accent" />
            </div>
            <p className="mt-3 font-display text-lg font-semibold text-slate-900 dark:text-white">
              {lastScanLabel}
            </p>
            <p className="mt-2 text-xs text-muted">
              {antivirus.scan.target ? `Target: ${antivirus.scan.target}` : "No active target"}
            </p>
          </div>
          <div className="glass-panel rounded-2xl p-5 shadow-soft">
            <div className="flex items-center justify-between text-xs text-muted">
              <span>Scan Queue</span>
              <Layers size={16} className="text-accent" />
            </div>
            <p className="mt-3 font-display text-lg font-semibold text-slate-900 dark:text-white">
              {antivirus.scan.inProgress ? "Active" : "Idle"}
            </p>
            <p className="mt-2 text-xs text-muted">
              {antivirus.scan.inProgress ? `Scanning ${antivirus.scan.target ?? "file"}` : "0 queued"}
            </p>
          </div>
        </div>

        <div className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-muted">Capabilities</p>
              <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">Client Signals</h2>
            </div>
            <p className="text-xs text-muted">Live indicators inferred from engine logs</p>
          </div>
          <div className="mt-5 flex flex-wrap gap-3">
            {capabilities.map((capability) => {
              const Icon = capability.icon;
              return (
                <div
                  key={capability.key}
                  className={`flex items-center gap-2 rounded-full px-3 py-2 text-xs font-semibold ${capabilityStyle(capability.state)}`}
                >
                  <Icon size={14} />
                  {capability.label}
                  <span className="text-[10px] uppercase tracking-[0.2em]">
                    {capability.state === "online" ? "Online" : capability.state === "standby" ? "Standby" : "Unknown"}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {antivirus.loading ? (
            Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-32 rounded-2xl" />
            ))
          ) : (
            <>
              <KpiCard
                title="Daily Activity"
                value={antivirus.stats.dailyActivity}
                helper="Events ingested today"
                icon={<BellRing size={18} />}
              />
              <KpiCard
                title="Detections"
                value={antivirus.stats.detections}
                helper="Suspicious files blocked"
                icon={<ShieldAlert size={18} />}
              />
              <KpiCard
                title="Quarantined"
                value={antivirus.stats.quarantined}
                helper="Isolated threats"
                icon={<ShieldX size={18} />}
              />
              <KpiCard
                title="Last Scan"
                value={lastScanMinutes}
                helper={antivirus.stats.lastScanAt ? "Minutes since last scan" : "No scan yet"}
                icon={<ShieldCheck size={18} />}
              />
            </>
          )}
        </div>

        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <div className="glass-panel rounded-2xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted">Activity Stream</p>
                <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">Protection Pulse</h2>
              </div>
              <Button
                size="sm"
                variant="flat"
                className="border border-white/10 bg-white/5 text-slate-900 dark:text-white"
                onClick={handleManualScan}
              >
                {antivirus.engineType === "client"
                  ? "Scan File"
                  : `Run ${antivirus.settings.scanDepth} scan`}
              </Button>
            </div>
            <div className="mt-6">
              <ActivityChart data={antivirus.activity} />
            </div>
            {antivirus.engineType === "client" ? (
              <p className="mt-4 text-xs text-muted">
                Choose a file to scan. The client engine will also monitor new processes automatically.
              </p>
            ) : null}
          </div>

          <div className="glass-panel rounded-2xl p-6">
            <p className="text-sm text-muted">Result Distribution</p>
            <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">Threat Breakdown</h2>
            <div className="mt-6">
              <DonutChart data={antivirus.breakdown} />
            </div>
            <div className="mt-4 grid gap-2 text-xs text-muted">
              {antivirus.breakdown.map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <span>{item.label}</span>
                  <span className="text-slate-900 dark:text-white">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-muted">Live Feed</p>
              <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">Engine Logs</h2>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <span>{filteredEvents.length} events</span>
              <div className="flex items-center gap-2">
                {(["all", "high", "medium", "low"] as const).map((level) => (
                  <button
                    key={level}
                    type="button"
                    onClick={() => setSeverityFilter(level)}
                    className={`rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] transition ${
                      severityFilter === level
                        ? "bg-accent text-white"
                        : "border border-white/10 bg-white/5 text-muted"
                    }`}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-5">
            <EventsTable events={filteredEvents} />
          </div>
        </div>
      </motion.div>
    </Shell>
  );
};

export default Dashboard;
