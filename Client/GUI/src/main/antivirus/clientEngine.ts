import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline";
import fs from "node:fs";
import path from "node:path";
import type {
  AvEvent,
  AvSettings,
  HandshakeRequest,
  HandshakeResponse,
  ScanRequest,
  ScanDepth,
  Sensitivity
} from "@shared/antivirus";
import { AV_PROTOCOL_VERSION } from "@shared/antivirus";
import type { AntivirusEngine } from "./engine";

const defaultSettings: AvSettings = {
  sensitivity: "balanced",
  realtime: true,
  startupScan: true,
  scanDepth: "standard",
  telemetry: true,
  serverUrl: "http://192.168.56.1",
  accessToken: "",
  refreshToken: "",
  killThreshold: 150,
  entropyThreshold: 6.0,
  runtime: 60
};

const HEARTBEAT_INTERVAL_MS = 5000;

export type ClientEngineOptions = {
  binaryPath?: string;
  workingDir?: string;
  env?: NodeJS.ProcessEnv;
};

export class ClientEngine extends EventEmitter implements AntivirusEngine {
  private binaryPath: string | null;
  private workingDir: string;
  private env: NodeJS.ProcessEnv;
  private child: ReturnType<typeof spawn> | null = null;
  private connected = false;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private scanTimer: NodeJS.Timeout | null = null;
  private manualScanStartedAt: number | null = null;
  private manualScanTarget: string | null = null;
  private settings: AvSettings;

  constructor(options: ClientEngineOptions = {}) {
    super();
    this.binaryPath = resolveBinaryPath(options.binaryPath);
    this.workingDir = resolveWorkingDir(this.binaryPath, options.workingDir);
    this.env = { ...process.env, ...options.env };
    const config = readConfig(this.workingDir);
    const killThreshold = config.killThreshold ?? defaultSettings.killThreshold;
    const runtime = config.runtime ?? defaultSettings.runtime;
    this.settings = normalizeSettings({
      ...defaultSettings,
      ...config,
      sensitivity: deriveSensitivity(killThreshold),
      scanDepth: deriveScanDepth(runtime)
    });
  }

  isAvailable(): boolean {
    return !!this.binaryPath && fs.existsSync(this.binaryPath);
  }

  async handshake(request: HandshakeRequest): Promise<HandshakeResponse> {
    if (request.protocolVersion !== AV_PROTOCOL_VERSION) {
      return {
        ok: false,
        engineVersion: "client-unknown",
        serverTime: new Date().toISOString(),
        message: "Protocol mismatch"
      };
    }

    if (!this.binaryPath || !fs.existsSync(this.binaryPath)) {
      return {
        ok: false,
        engineVersion: "client-unknown",
        serverTime: new Date().toISOString(),
        message: "Client engine binary not found"
      };
    }

    return {
      ok: true,
      engineVersion: "client-1.0.0",
      serverTime: new Date().toISOString()
    };
  }

  async connect(): Promise<void> {
    if (this.connected || this.child) {
      return;
    }

    if (!this.binaryPath || !fs.existsSync(this.binaryPath)) {
      throw new Error("Client engine binary not found");
    }

    if (!this.settings.accessToken && !this.settings.refreshToken) {
      this.emitEvent(
        "status",
        "medium",
        "Server tokens missing. Offline scanning enabled; cloud sync disabled.",
        { state: "connecting" }
      );
    }

    ensureConfig(this.workingDir, this.settings);

    this.child = spawn(this.binaryPath, [], {
      cwd: this.workingDir,
      env: this.env,
      windowsHide: true
    });

    this.connected = true;
    this.emitEvent("status", "low", "Client engine starting", { state: "connecting" });

    const stdout = createInterface({ input: this.child.stdout });
    stdout.on("line", (line) => this.handleLine(line));

    const stderr = createInterface({ input: this.child.stderr });
    stderr.on("line", (line) => this.handleLine(line, true));

    this.child.on("error", (error) => {
      this.connected = false;
      this.emitEvent("status", "high", `Client engine failed to start: ${error.message}`, {
        state: "disconnected",
        fatal: true
      });
      this.cleanup();
    });

    this.child.on("exit", (code) => {
      this.connected = false;
      this.emitEvent(
        "status",
        "medium",
        `Client engine stopped${typeof code === "number" ? ` (code ${code})` : ""}`,
        { state: "disconnected" }
      );
      this.cleanup();
    });

    this.startHeartbeat();
  }

  async disconnect(): Promise<void> {
    if (!this.child) {
      this.connected = false;
      return;
    }

    this.child.kill();
    this.connected = false;
    this.emitEvent("status", "medium", "Client engine disconnected", { state: "disconnected" });
    this.cleanup();
  }

  async startScan(request: ScanRequest): Promise<void> {
    if (!this.connected || !this.child) {
      throw new Error("Engine not connected");
    }

    const target = request.paths?.[0];
    if (!target) {
      throw new Error("Scan target required");
    }

    if (!this.child.stdin) {
      throw new Error("Engine stdin unavailable");
    }

    if (this.manualScanStartedAt) {
      return;
    }

    this.manualScanStartedAt = Date.now();
    this.manualScanTarget = target;

    this.emitEvent("scan_progress", "low", "Manual scan started", {
      progress: 0,
      target
    });

    const escaped = target.replace(/\"/g, "\\\"");
    this.child.stdin.write(`scan \"${escaped}\"\n`);
  }

  setSettings(settings: AvSettings): void {
    const normalized = normalizeSettings(settings);
    this.settings = { ...normalized };
    ensureConfig(this.workingDir, this.settings);
    this.emitEvent("info", "low", "Client engine settings updated", { settings: this.settings });

    if (this.child) {
      this.emitEvent("status", "medium", "Client engine restarting", { state: "reconnecting" });
      this.child.kill();
      this.connected = false;
      this.cleanup();
      this.connect().catch((error) => {
        const message = error instanceof Error ? error.message : "Restart failed";
        this.emitEvent("status", "high", message, { state: "disconnected", fatal: true });
      });
    }
  }

  getSettings(): AvSettings {
    return { ...this.settings };
  }

  getType(): "client" {
    return "client";
  }

  onEvent(listener: (event: AvEvent) => void): () => void {
    this.on("event", listener);
    return () => this.off("event", listener);
  }

  isConnected(): boolean {
    return this.connected;
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(() => {
      if (!this.connected) {
        return;
      }
      this.emitEvent("heartbeat", "low", "Client heartbeat", {
        engineVersion: "client-1.0.0",
        pingMs: 10 + Math.round(Math.random() * 12)
      });
    }, HEARTBEAT_INTERVAL_MS);
  }

  private handleLine(line: string, isError = false): void {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }

    const lower = trimmed.toLowerCase();
    const logSeverity: AvEvent["severity"] =
      isError || lower.includes("fatal") ? "high" : lower.includes("error") || lower.includes("failed") ? "medium" : "low";

    if (trimmed.includes("Process monitoring started") || trimmed.includes("Monitoring active")) {
      this.emitEvent("status", "low", "Client engine online", { state: "connected" });
      return;
    }

    if (trimmed.includes("Process monitoring stopped")) {
      this.emitEvent("status", "medium", "Client engine stopped", { state: "disconnected" });
      return;
    }

    if (trimmed.includes("Failed to open driver device")) {
      this.emitEvent("status", "high", "Driver unavailable", { state: "disconnected", fatal: true });
      return;
    }

    if (trimmed.includes("Successfully connected to driver")) {
      this.emitEvent("status", "low", "Driver connected", { driver: "connected" });
      return;
    }

    if (trimmed.includes("FATAL ERROR")) {
      this.emitEvent("status", "high", trimmed, { state: "disconnected", fatal: true });
      return;
    }

    if (trimmed.startsWith("[SCAN]")) {
      const target = extractAfterColon(trimmed) ?? this.manualScanTarget ?? "Manual scan";
      this.emitEvent("scan_progress", "low", trimmed, { progress: 10, target });
      return;
    }

    if (trimmed.startsWith("[SCAN RESULT]")) {
      const target = extractAfterColon(trimmed) ?? this.manualScanTarget ?? "Manual scan";
      const isThreat = trimmed.includes("THREAT");
      const durationSec = this.manualScanStartedAt
        ? Math.max(1, Math.round((Date.now() - this.manualScanStartedAt) / 1000))
        : null;

      this.emitEvent("scan_complete", isThreat ? "high" : "low", trimmed, {
        target,
        durationSec,
        threatsFound: isThreat ? 1 : 0
      });

      if (isThreat) {
        this.emitEvent("threat_detected", "high", trimmed, { target });
      }

      this.manualScanStartedAt = null;
      this.manualScanTarget = null;
      return;
    }

    if (trimmed.startsWith("[SCAN ERROR]")) {
      const target = extractAfterColon(trimmed) ?? this.manualScanTarget ?? "Manual scan";
      const durationSec = this.manualScanStartedAt
        ? Math.max(1, Math.round((Date.now() - this.manualScanStartedAt) / 1000))
        : null;
      this.emitEvent("scan_complete", "medium", trimmed, {
        target,
        durationSec,
        threatsFound: 0,
        failed: true
      });
      this.manualScanStartedAt = null;
      this.manualScanTarget = null;
      return;
    }

    if (trimmed.includes("[ALERT]") || trimmed.includes("Threat detected")) {
      this.emitEvent("threat_detected", "high", trimmed);
      return;
    }

    if (trimmed.includes("[SUCCESS] Process terminated")) {
      this.emitEvent("quarantine", "medium", trimmed);
      return;
    }

    if (trimmed.includes("[SERVER]")) {
      this.emitEvent("info", logSeverity, trimmed.replace(/^->\s*/, ""));
      return;
    }

    if (
      trimmed.includes("[NEW PROCESS]") ||
      trimmed.includes("Scanning:") ||
      trimmed.includes("[CACHED]") ||
      trimmed.includes("[SIGNED]") ||
      trimmed.includes("[HASH]") ||
      trimmed.includes("[YARA]") ||
      trimmed.includes("[ENTROPY]") ||
      trimmed.includes("[CLEAN]")
    ) {
      this.emitEvent("info", logSeverity, trimmed.replace(/^->\s*/, ""));
      return;
    }

    if (trimmed.includes("[ERROR]") || isError) {
      this.emitEvent("info", logSeverity, trimmed);
      return;
    }

    if (
      trimmed.includes("Connecting to server") ||
      trimmed.includes("Initializing scanning engines") ||
      trimmed.includes("Initialized YARA scanning engine") ||
      trimmed.includes("Loaded hashes database") ||
      trimmed.includes("All scanning engines initialized")
    ) {
      this.emitEvent("info", "low", trimmed);
      return;
    }

    this.emitEvent("info", logSeverity, trimmed);
  }

  private emitEvent(
    type: AvEvent["type"],
    severity: AvEvent["severity"],
    message: string,
    data?: Record<string, unknown>
  ): void {
    const event: AvEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      severity,
      message,
      data
    };

    this.emit("event", event);
  }

  private cleanup(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }

    this.manualScanStartedAt = null;
    this.manualScanTarget = null;

    if (this.child) {
      this.child.removeAllListeners();
      this.child = null;
    }
  }
}

const resolveBinaryPath = (explicitPath?: string): string | null => {
  const envPath = explicitPath ?? process.env.AYDO_ENGINE_PATH;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  const repoRoot = path.resolve(process.cwd(), "..", "..");
  const candidates = [
    path.join(repoRoot, "x64", "Release", "Service.exe"),
    path.join(repoRoot, "x64", "Debug", "Service.exe"),
    path.join(repoRoot, "x64", "Release", "ProcessMonitor.exe"),
    path.join(repoRoot, "x64", "Debug", "ProcessMonitor.exe")
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
};

const resolveWorkingDir = (binaryPath: string | null, explicitDir?: string): string => {
  const envDir = explicitDir ?? process.env.AYDO_ENGINE_CWD;
  if (envDir) {
    return envDir;
  }

  if (binaryPath) {
    return path.resolve(path.dirname(binaryPath), "..", "..");
  }

  return process.cwd();
};

const readConfig = (workingDir: string): Partial<AvSettings> => {
  try {
    const configPath = path.join(workingDir, "config.json");
    if (!fs.existsSync(configPath)) {
      return {};
    }
    const raw = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    return {
      serverUrl: typeof raw.serverUrl === "string" ? raw.serverUrl : undefined,
      accessToken: typeof raw.accessToken === "string" ? raw.accessToken : undefined,
      refreshToken: typeof raw.refreshToken === "string" ? raw.refreshToken : undefined,
      killThreshold: Number.isFinite(raw.killThreshold) ? raw.killThreshold : undefined,
      entropyThreshold: Number.isFinite(raw.entropyThreshold) ? raw.entropyThreshold : undefined,
      runtime: Number.isFinite(raw.runtime) ? raw.runtime : undefined
    };
  } catch {
    return {};
  }
};

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
  const killThreshold = Number.isFinite(settings.killThreshold)
    ? settings.killThreshold
    : defaultSettings.killThreshold;
  const entropyThreshold = Number.isFinite(settings.entropyThreshold)
    ? settings.entropyThreshold
    : defaultSettings.entropyThreshold;
  const runtime = Number.isFinite(settings.runtime) ? settings.runtime : defaultSettings.runtime;
  return {
    ...defaultSettings,
    ...settings,
    serverUrl: settings.serverUrl?.trim() || defaultSettings.serverUrl,
    accessToken: settings.accessToken ?? "",
    refreshToken: settings.refreshToken ?? "",
    killThreshold,
    entropyThreshold,
    runtime,
    sensitivity: deriveSensitivity(killThreshold),
    scanDepth: deriveScanDepth(runtime)
  };
};

const ensureConfig = (workingDir: string, settings: AvSettings): void => {
  try {
    const normalized = normalizeSettings(settings);
    fs.mkdirSync(workingDir, { recursive: true });
    const configPath = path.join(workingDir, "config.json");
    const current = fs.existsSync(configPath)
      ? JSON.parse(fs.readFileSync(configPath, "utf-8"))
      : {};

    const next = {
      ...current,
      serverUrl: normalized.serverUrl,
      accessToken: normalized.accessToken,
      refreshToken: normalized.refreshToken,
      killThreshold: normalized.killThreshold,
      entropyThreshold: normalized.entropyThreshold,
      runtime: normalized.runtime
    };

    fs.writeFileSync(configPath, JSON.stringify(next, null, 2));
  } catch (error) {
    // Ignore config errors; engine will use defaults.
  }
};

const extractAfterColon = (value: string): string | null => {
  const index = value.indexOf(":");
  if (index === -1) {
    return null;
  }
  const target = value.slice(index + 1).trim();
  return target.length > 0 ? target : null;
};
