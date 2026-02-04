import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip } from "recharts";
import type { AvActivityPoint } from "@shared/antivirus";

const ActivityChart = ({ data }: { data: AvActivityPoint[] }) => {
  if (!data.length) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-muted">
        No activity yet. The engine will stream data once scanning starts.
      </div>
    );
  }

  const accent = "rgb(var(--color-accent))";
  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart data={data} margin={{ top: 10, right: 16, left: -10, bottom: 0 }}>
        <XAxis dataKey="time" stroke="rgba(139,153,173,0.6)" fontSize={11} />
        <YAxis stroke="rgba(139,153,173,0.6)" fontSize={11} width={32} />
        <Tooltip
          contentStyle={{
            background: "rgba(10,15,23,0.9)",
            border: `1px solid ${accent}`,
            borderRadius: 12,
            color: "#e7edf5"
          }}
          cursor={{ stroke: "rgba(90,130,255,0.35)" }}
        />
        <Line
          type="monotone"
          dataKey="value"
          stroke={accent}
          strokeWidth={3}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
};

export default ActivityChart;
