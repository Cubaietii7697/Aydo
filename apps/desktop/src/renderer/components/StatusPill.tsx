import type { AvConnectionState } from "@shared/antivirus";

const statusMap: Record<AvConnectionState, { label: string; className: string }> = {
  connected: { label: "Connected", className: "bg-success/15 text-success" },
  connecting: { label: "Connecting", className: "bg-warning/15 text-warning" },
  reconnecting: { label: "Reconnecting", className: "bg-warning/15 text-warning" },
  disconnected: { label: "Disconnected", className: "bg-danger/15 text-danger" }
};

const StatusPill = ({ state, message }: { state: AvConnectionState; message?: string }) => {
  const { label, className } = statusMap[state];
  return (
    <div className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${className}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      <span>{label}</span>
      {message ? <span className="hidden text-[10px] font-normal text-muted md:inline">{message}</span> : null}
    </div>
  );
};

export default StatusPill;
