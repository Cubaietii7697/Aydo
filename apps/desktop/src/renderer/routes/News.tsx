import { motion } from "framer-motion";
import { ExternalLink, ShieldAlert, Radar, Sparkles } from "lucide-react";
import Shell from "../components/Shell";

const newsItems = [
  {
    id: "1",
    title: "Zero-trust rollouts hit enterprise readiness milestone",
    source: "Aydo Labs",
    time: "2 hours ago",
    summary:
      "Endpoint enforcement and adaptive isolation are now enabled across 48 regions with automatic rollback safeguards.",
    icon: ShieldAlert
  },
  {
    id: "2",
    title: "Behavioral model update reduces false positives by 18%",
    source: "Threat Research",
    time: "Yesterday",
    summary:
      "Telemetry weighting now prioritizes process lineage and signed module validation for higher precision.",
    icon: Radar
  },
  {
    id: "3",
    title: "New containment playbook for ransomware escalation",
    source: "Incident Response",
    time: "2 days ago",
    summary:
      "Playbook adds automated snapshotting, registry diffing, and rapid rollback for high-risk incidents.",
    icon: Sparkles
  }
];

const News = () => {
  return (
    <Shell title="News" subtitle="Product updates, threat research, and incident playbooks.">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="grid gap-4"
      >
        {newsItems.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.id} className="glass-panel rounded-2xl p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-accent/15 text-accent shadow-glow">
                    <Icon size={18} />
                  </div>
                  <div>
                    <h2 className="font-display text-lg font-semibold text-slate-900 dark:text-white">
                      {item.title}
                    </h2>
                    <p className="text-xs text-muted">{item.source} · {item.time}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-accent">
                  Advisory
                  <ExternalLink size={14} />
                </div>
              </div>
              <p className="mt-4 text-sm text-muted">{item.summary}</p>
            </div>
          );
        })}
      </motion.div>
    </Shell>
  );
};

export default News;
