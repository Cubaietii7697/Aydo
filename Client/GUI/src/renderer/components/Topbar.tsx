import { Button, Avatar } from "@nextui-org/react";
import { Moon, Sun, Play, Clock } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useTheme } from "next-themes";
import { useAuth } from "../services/authService";
import { antivirusService, useAntivirus } from "../services/antivirusService";
import StatusPill from "./StatusPill";

const Topbar = ({ title, subtitle }: { title: string; subtitle?: string }) => {
  const { user } = useAuth();
  const { theme, setTheme } = useTheme();
  const antivirus = useAntivirus();

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  const handleScan = async () => {
    await antivirusService.requestScan(antivirus.settings.scanDepth);
  };

  const handleConnection = async () => {
    if (antivirus.connectionState === "connected") {
      await antivirusService.disconnect();
    } else {
      await antivirusService.connect();
    }
  };

  const lastScanLabel = antivirus.stats.lastScanAt
    ? formatDistanceToNow(new Date(antivirus.stats.lastScanAt), { addSuffix: true })
    : "No scan yet";

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200/70 bg-slate-50/90 px-8 py-6 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/40">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-muted">Aydo Command</p>
        <h1 className="font-display text-2xl font-semibold text-slate-900 dark:text-white">{title}</h1>
        {subtitle ? <p className="text-sm text-muted">{subtitle}</p> : null}
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex flex-wrap items-center gap-2 rounded-full border border-slate-200/60 bg-white/70 px-2 py-1 text-xs text-muted dark:border-white/10 dark:bg-white/5">
          <StatusPill state={antivirus.connectionState} message={antivirus.statusMessage} />
          <div className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-muted">
            Engine: {antivirus.engineType === "client" ? "Client" : "Simulator"}
          </div>
          <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-muted">
            <Clock size={12} />
            Last scan: {lastScanLabel}
          </div>
          {antivirus.scan.inProgress ? (
            <div className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-muted">
              Scan running · {antivirus.scan.progress}%
            </div>
          ) : null}
        </div>
        <Button
          size="sm"
          variant="flat"
          className="border border-white/10 bg-white/5 text-slate-900 dark:text-white"
          onClick={handleConnection}
        >
          {antivirus.connectionState === "connected" ? "Disconnect" : "Connect"}
        </Button>
        <Button
          size="sm"
          className="bg-accent text-white font-semibold"
          startContent={<Play size={14} />}
          onClick={handleScan}
          isDisabled={antivirus.connectionState !== "connected"}
        >
          {antivirus.engineType === "client" ? "Scan File" : "Start Scan"}
        </Button>
        <button
          onClick={toggleTheme}
          className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/5 text-slate-700 transition hover:text-slate-900 dark:text-white/70 dark:hover:text-white"
        >
          {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        <div className="flex items-center gap-3">
          <Avatar
            size="sm"
            name={user?.name ?? "Analyst"}
            src={user?.avatarUrl ?? undefined}
            className="bg-accent/20 text-accent"
          />
          <div className="text-xs">
            <p className="font-semibold text-slate-900 dark:text-white">{user?.name ?? "Analyst"}</p>
            <p className="text-muted">{user?.role ?? "Security"}</p>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Topbar;
