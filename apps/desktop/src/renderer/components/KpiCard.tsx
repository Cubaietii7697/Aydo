import { ReactNode } from "react";
import AnimatedNumber from "./AnimatedNumber";

const KpiCard = ({
  title,
  value,
  helper,
  icon
}: {
  title: string;
  value: number;
  helper: string;
  icon: ReactNode;
}) => {
  return (
    <div className="glass-panel rounded-2xl p-5 shadow-soft">
      <div className="flex items-center justify-between text-sm text-muted">
        <span>{title}</span>
        <span className="text-accent">{icon}</span>
      </div>
      <div className="mt-4">
        <AnimatedNumber value={value} />
      </div>
      <p className="mt-2 text-xs text-muted">{helper}</p>
    </div>
  );
};

export default KpiCard;
