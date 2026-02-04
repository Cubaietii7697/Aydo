import { Sliders, Activity, Newspaper } from "lucide-react";
import { NavLink, useNavigate } from "react-router-dom";
import { authService } from "../services/authService";
import logoUrl from "../assets/logo.png";
import BrandMark from "./BrandMark";

const linkBase = "flex items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium transition";

const Sidebar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    authService.logout();
    navigate("/login");
  };

  return (
    <aside className="flex w-64 flex-col gap-8 border-r border-slate-200/70 bg-slate-50/90 px-6 py-8 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/40">
      <div className="flex items-center gap-3">
        <BrandMark className="h-10 w-10" />
        <div className="flex flex-col">
          <img src={logoUrl} alt="Aydo Security" className="h-6 w-auto object-contain" />
          <span className="text-[10px] uppercase tracking-[0.3em] text-muted">Security Console</span>
        </div>
      </div>

      <nav className="flex flex-col gap-2">
        <NavLink
          to="/dashboard"
          className={({ isActive }) =>
            `${linkBase} ${
              isActive
                ? "bg-accent/15 text-accent shadow-glow"
                : "text-slate-700 hover:bg-slate-200/40 dark:text-white/80 dark:hover:bg-white/5"
            }`
          }
        >
          <Activity size={18} />
          Dashboard
        </NavLink>
        <NavLink
          to="/news"
          className={({ isActive }) =>
            `${linkBase} ${
              isActive
                ? "bg-accent/15 text-accent shadow-glow"
                : "text-slate-700 hover:bg-slate-200/40 dark:text-white/80 dark:hover:bg-white/5"
            }`
          }
        >
          <Newspaper size={18} />
          News
        </NavLink>
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            `${linkBase} ${
              isActive
                ? "bg-accent/15 text-accent shadow-glow"
                : "text-slate-700 hover:bg-slate-200/40 dark:text-white/80 dark:hover:bg-white/5"
            }`
          }
        >
          <Sliders size={18} />
          Settings
        </NavLink>
      </nav>

      <div className="mt-auto rounded-2xl border border-slate-200/70 bg-white/80 p-4 dark:border-white/10 dark:bg-white/5">
        <p className="text-xs uppercase tracking-[0.3em] text-muted">Quick Actions</p>
        <button
          onClick={handleLogout}
          className="mt-3 w-full rounded-xl border border-slate-200/70 py-2 text-sm text-slate-700 transition hover:border-slate-300 hover:text-slate-900 dark:border-white/10 dark:text-white/80 dark:hover:text-white"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
