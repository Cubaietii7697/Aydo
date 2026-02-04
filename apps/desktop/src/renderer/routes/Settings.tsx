import { Avatar, Button, Input } from "@nextui-org/react";
import { motion } from "framer-motion";
import { Camera, Download, RefreshCcw, Save } from "lucide-react";
import { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import Shell from "../components/Shell";
import { antivirusService, useAntivirus } from "../services/antivirusService";
import type { AvSettings, ScanDepth, Sensitivity } from "@shared/antivirus";
import { authService, useAuth } from "../services/authService";

const profilePresets: Record<
  Sensitivity,
  { label: string; desc: string; killThreshold: number; entropyThreshold: number }
> = {
  low: {
    label: "Low",
    desc: "Lower sensitivity, fewer false positives. Best for trusted endpoints.",
    killThreshold: 200,
    entropyThreshold: 7.2
  },
  balanced: {
    label: "Balanced",
    desc: "Recommended default. Balanced detection and noise.",
    killThreshold: 150,
    entropyThreshold: 6.0
  },
  aggressive: {
    label: "Aggressive",
    desc: "Higher sensitivity and stricter blocking at the cost of more alerts.",
    killThreshold: 110,
    entropyThreshold: 5.2
  }
};

const runtimePresets = [30, 60, 120];

const deriveSensitivity = (killThreshold: number): Sensitivity => {
  if (killThreshold <= 120) {
    return "aggressive";
  }
  if (killThreshold >= 190) {
    return "low";
  }
  return "balanced";
};

const deriveScanDepth = (runtime: number): ScanDepth => {
  if (runtime <= 35) {
    return "quick";
  }
  if (runtime >= 100) {
    return "deep";
  }
  return "standard";
};

const normalizeSettings = (settings: AvSettings): AvSettings => {
  const killThreshold = Number.isFinite(settings.killThreshold) ? settings.killThreshold : 150;
  const entropyThreshold = Number.isFinite(settings.entropyThreshold) ? settings.entropyThreshold : 6.0;
  const runtime = Number.isFinite(settings.runtime) ? settings.runtime : 60;
  return {
    ...settings,
    serverUrl: settings.serverUrl?.trim() || "http://192.168.56.1",
    accessToken: settings.accessToken ?? "",
    refreshToken: settings.refreshToken ?? "",
    killThreshold,
    entropyThreshold,
    runtime,
    sensitivity: deriveSensitivity(killThreshold),
    scanDepth: deriveScanDepth(runtime)
  };
};

const Settings = () => {
  const antivirus = useAntivirus();
  const { user } = useAuth();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [draft, setDraft] = useState<AvSettings>(antivirus.settings);

  useEffect(() => {
    setDraft({ ...antivirus.settings });
  }, [antivirus.settings]);

  const normalizedDraft = useMemo(() => normalizeSettings(draft), [draft]);
  const isDirty = useMemo(
    () => JSON.stringify(normalizedDraft) !== JSON.stringify(antivirus.settings),
    [normalizedDraft, antivirus.settings]
  );

  const applySettings = () => {
    antivirusService.updateSettings(normalizedDraft);
    toast.success("Settings saved", {
      description: "Client configuration updated on disk."
    });
  };

  const resetSettings = () => {
    setDraft({ ...antivirus.settings });
  };

  const handleAvatarUpload = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : null;
      authService.setAvatar(result);
    };
    reader.readAsDataURL(file);
  };

  const handleNumberChange = (key: keyof AvSettings) => (value: string) => {
    const next = Number(value);
    if (!Number.isFinite(next)) {
      return;
    }
    setDraft((prev) => ({ ...prev, [key]: next }));
  };

  const applyPreset = (preset: Sensitivity) => {
    const profile = profilePresets[preset];
    setDraft((prev) => ({
      ...prev,
      killThreshold: profile.killThreshold,
      entropyThreshold: profile.entropyThreshold
    }));
  };

  const activePreset = deriveSensitivity(draft.killThreshold);

  return (
    <Shell title="Settings" subtitle="Configure the client engine and operational thresholds.">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex flex-col gap-6"
      >
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button
            variant="flat"
            className="border border-white/10 bg-white/5 text-slate-900 dark:text-white"
            startContent={<RefreshCcw size={14} />}
            onClick={resetSettings}
            isDisabled={!isDirty}
          >
            Reset
          </Button>
          <Button
            className="bg-accent text-white font-semibold"
            startContent={<Save size={16} />}
            onClick={applySettings}
            isDisabled={!isDirty}
          >
            Save changes
          </Button>
        </div>

        <div className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-muted">Profile</p>
              <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">
                Operator Identity
              </h2>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleAvatarUpload}
            />
            <div className="flex items-center gap-3">
              <Button
                variant="flat"
                className="border border-white/10 bg-white/5 text-slate-900 dark:text-white"
                startContent={<Camera size={16} />}
                onClick={() => fileInputRef.current?.click()}
              >
                Change Photo
              </Button>
              {user?.avatarUrl ? (
                <Button
                  variant="flat"
                  className="border border-white/10 bg-white/5 text-slate-900 dark:text-white"
                  onClick={() => authService.setAvatar(null)}
                >
                  Remove
                </Button>
              ) : null}
            </div>
          </div>
          <div className="mt-5 flex items-center gap-4">
            <Avatar
              size="lg"
              name={user?.name ?? "Analyst"}
              src={user?.avatarUrl ?? undefined}
              className="bg-accent/20 text-accent"
            />
            <div>
              <p className="text-sm text-muted">Signed in as</p>
              <p className="font-display text-lg font-semibold text-slate-900 dark:text-white">
                {user?.name ?? "Security Analyst"}
              </p>
              <p className="text-xs text-muted">{user?.email ?? "analyst@aydo.local"}</p>
            </div>
          </div>
        </div>

        <div className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-muted">Detection</p>
              <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">
                Threat Thresholds
              </h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.keys(profilePresets).map((key) => {
                const preset = key as Sensitivity;
                const active = activePreset === preset;
                return (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => applyPreset(preset)}
                    aria-pressed={active}
                    className={`rounded-full px-4 py-2 text-xs font-semibold transition ${
                      active
                        ? "bg-accent text-white"
                        : "border border-white/10 text-slate-700 hover:border-white/30 dark:text-white/70"
                    }`}
                  >
                    {profilePresets[preset].label}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-[1.4fr_1fr]">
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-muted">Active Profile</p>
              <p className="mt-2 font-display text-lg font-semibold text-slate-900 dark:text-white">
                {profilePresets[activePreset].label}
              </p>
              <p className="mt-2 text-sm text-muted">{profilePresets[activePreset].desc}</p>
            </div>
            <div className="grid gap-4">
              <Input
                type="number"
                label="Kill Threshold"
                value={String(draft.killThreshold)}
                onValueChange={handleNumberChange("killThreshold")}
                classNames={{ inputWrapper: "border-white/10 bg-white/5", label: "text-muted" }}
                min={50}
                max={400}
              />
              <Input
                type="number"
                label="Entropy Threshold"
                value={String(draft.entropyThreshold)}
                onValueChange={handleNumberChange("entropyThreshold")}
                classNames={{ inputWrapper: "border-white/10 bg-white/5", label: "text-muted" }}
                step={0.1}
                min={3}
                max={10}
              />
            </div>
          </div>
          <p className="mt-4 text-sm text-muted">
            Kill threshold defines when the client terminates a process. Entropy threshold triggers cloud analysis when
            file entropy is suspicious.
          </p>
        </div>

        <div className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-muted">Sandbox</p>
              <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">
                Server & Runtime
              </h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {runtimePresets.map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setDraft((prev) => ({ ...prev, runtime: preset }))}
                  className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                    draft.runtime === preset
                      ? "bg-accent text-white"
                      : "border border-white/10 text-slate-700 hover:border-white/30 dark:text-white/70"
                  }`}
                >
                  {preset}s
                </button>
              ))}
            </div>
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-muted">Server Endpoint</p>
              <p className="mt-2 text-sm text-muted">Managed by policy</p>
              <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">
                {normalizedDraft.serverUrl || "Not configured"}
              </p>
            </div>
            <Input
              type="number"
              label="Sandbox Runtime (seconds)"
              value={String(draft.runtime)}
              onValueChange={handleNumberChange("runtime")}
              classNames={{ inputWrapper: "border-white/10 bg-white/5", label: "text-muted" }}
              min={10}
              max={600}
            />
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Input
              type="password"
              label="Access Token"
              value={draft.accessToken}
              onValueChange={(value) => setDraft((prev) => ({ ...prev, accessToken: value }))}
              classNames={{ inputWrapper: "border-white/10 bg-white/5", label: "text-muted" }}
            />
            <Input
              type="password"
              label="Refresh Token"
              value={draft.refreshToken}
              onValueChange={(value) => setDraft((prev) => ({ ...prev, refreshToken: value }))}
              classNames={{ inputWrapper: "border-white/10 bg-white/5", label: "text-muted" }}
            />
          </div>

          <p className="mt-4 text-sm text-muted">
            Runtime controls sandbox detonation time. Tokens are required when the client runs unattended.
          </p>
        </div>

        <div className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-muted">Reporting</p>
              <h2 className="font-display text-xl font-semibold text-slate-900 dark:text-white">Session Summary</h2>
            </div>
            <Button
              variant="flat"
              className="border border-white/10 bg-white/5 text-slate-900 dark:text-white"
              startContent={<Download size={16} />}
              onClick={() =>
                toast.message("Export pending", {
                  description: "Report export will be enabled once backend storage is connected."
                })
              }
            >
              Export (Coming soon)
            </Button>
          </div>
          <p className="mt-3 text-sm text-muted">
            Reporting requires backend storage. Connect a server to unlock full audit exports.
          </p>
        </div>
      </motion.div>
    </Shell>
  );
};

export default Settings;
