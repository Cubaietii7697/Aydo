import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { AvBreakdownItem } from "@shared/antivirus";

const COLORS = ["#3c6cff", "#f4b740", "#f0677c", "#7b8fb3"];

const DonutChart = ({ data }: { data: AvBreakdownItem[] }) => {
  if (!data.length) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-muted">
        Waiting for scan results.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={data}
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
          dataKey="value"
        >
          {data.map((_, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "rgba(10,15,23,0.9)",
            border: "1px solid rgba(90,130,255,0.5)",
            borderRadius: 12,
            color: "#e7edf5"
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
};

export default DonutChart;
