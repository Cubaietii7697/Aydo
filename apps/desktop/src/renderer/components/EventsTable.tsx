import { Chip, Table, TableBody, TableCell, TableColumn, TableHeader, TableRow } from "@nextui-org/react";
import type { AvEvent } from "@shared/antivirus";
import { formatDistanceToNow } from "date-fns";

const severityColor = (severity: AvEvent["severity"]) => {
  switch (severity) {
    case "high":
      return "danger";
    case "medium":
      return "warning";
    default:
      return "success";
  }
};

const EventsTable = ({ events }: { events: AvEvent[] }) => {
  if (!events.length) {
    return (
      <div className="flex h-48 items-center justify-center rounded-2xl border border-slate-200/60 bg-white/70 text-sm text-muted dark:border-white/10 dark:bg-white/5">
        No logs yet. The engine will stream scans, server calls, and alerts here.
      </div>
    );
  }

  return (
    <Table
      aria-label="Recent events"
      removeWrapper
    classNames={{
        base: "rounded-2xl border border-slate-200/60 bg-white/70 dark:border-white/10 dark:bg-white/5",
        th: "bg-transparent text-xs text-muted",
        td: "text-sm text-slate-700 dark:text-white/80"
      }}
    >
      <TableHeader>
        <TableColumn>Time</TableColumn>
        <TableColumn>Type</TableColumn>
        <TableColumn>Severity</TableColumn>
        <TableColumn>Message</TableColumn>
      </TableHeader>
      <TableBody>
        {events.map((event) => (
          <TableRow key={event.id}>
            <TableCell className="text-muted">
              {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
            </TableCell>
            <TableCell className="capitalize">{event.type.replace("_", " ")}</TableCell>
            <TableCell>
              <Chip size="sm" color={severityColor(event.severity)} variant="flat">
                {event.severity}
              </Chip>
            </TableCell>
            <TableCell>{event.message}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};

export default EventsTable;
