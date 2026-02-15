import { EventEmitter } from "node:events";
import { createConnection, Socket } from "node:net";
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
  Sensitivity,
} from "@shared/antivirus";
import { AV_PROTOCOL_VERSION } from "@shared/antivirus";
import type { AntivirusEngine } from "./engine";

const PIPE_NAME = "\\\\.\\pipe\\AydoServicePipe";
const RECONNECT_DELAY_MS = 3000;

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
  runtime: 60,
  infectedFileAction: "none",
};

const HEARTBEAT_INTERVAL_MS = 5000;

export type ClientEngineOptions = {
  binaryPath?: string;
  workingDir?: string;
  env?: NodeJS.ProcessEnv;
};

export class ClientEngine extends EventEmitter implements AntivirusEngine {
  private socket: Socket | null = null;
  private connected = false;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private scanTimer: NodeJS.Timeout | null = null;
  private manualScanStartedAt: number | null = null;
  private manualScanTarget: string | null = null;
  private settings: AvSettings;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private userRequestedDisconnect = false;
  private workingDir: string;

  constructor(options: ClientEngineOptions = {}) {
    super();
    // Working dir logic is kept for config loading, even if we don't spawn
    this.workingDir = resolveWorkingDir(
      resolveBinaryPath(options.binaryPath),
      options.workingDir,
    );
    const config = readConfig(this.workingDir);
    const killThreshold = config.killThreshold ?? defaultSettings.killThreshold;
    const runtime = config.runtime ?? defaultSettings.runtime;
    this.settings = normalizeSettings({
      ...defaultSettings,
      ...config,
      sensitivity: deriveSensitivity(killThreshold),
      scanDepth: deriveScanDepth(runtime),
    });
  }

  isAvailable(): boolean {
    return true; // Always attempt to connect
  }

  async handshake(request: HandshakeRequest): Promise<HandshakeResponse> {
    if (request.protocolVersion !== AV_PROTOCOL_VERSION) {
      return {
        ok: false,
        engineVersion: "client-unknown",
        serverTime: new Date().toISOString(),
        message: "Protocol mismatch",
      };
    }

    return {
      ok: true,
      engineVersion: "client-1.0.0",
      serverTime: new Date().toISOString(),
    };
  }

  async connect(): Promise<void> {
    if (this.connected || this.socket) {
      return;
    }

    this.userRequestedDisconnect = false;
    this.attemptConnection();
  }

  private attemptConnection() {
    if (this.socket) return;

    this.emitEvent("status", "low", "Connecting to service...", {
      state: "connecting",
    });

    const socket = createConnection(PIPE_NAME, () => {
      this.socket = socket;
      this.connected = true;
      this.emitEvent("status", "low", "Connected to local service", {
        state: "connected",
      });
      this.startHeartbeat();

      // Setup line reader
      const rl = createInterface({ input: socket });
      rl.on("line", (line) => this.handleLine(line));
    });

    socket.on("error", (err) => {
      // If we are already connected, this is a drop.
      // If we are connecting, this is a failure.
      const msg = err.message;
      if (!this.connected) {
        // Silent retry loop for "not found"
      } else {
        this.emitEvent("status", "medium", "Connection lost: " + msg, {
          state: "disconnected",
        });
      }
      this.cleanup();
      this.scheduleReconnect();
    });

    socket.on("close", () => {
      if (this.connected) {
        this.emitEvent("status", "medium", "Service disconnected", {
          state: "disconnected",
        });
      }
      this.cleanup();
      this.scheduleReconnect();
    });

    // We store temporary socket reference to allow cleanup on immediate error
    // But we don't assign to this.socket until 'connect' fires to avoid using half-open socket
    // actually, socket.on('error') might fire before connect.
  }

  private scheduleReconnect() {
    if (this.userRequestedDisconnect || this.reconnectTimer) return;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.attemptConnection();
    }, RECONNECT_DELAY_MS);
  }

  async disconnect(): Promise<void> {
    this.userRequestedDisconnect = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.socket) {
      this.socket.destroy(); // Force close
      this.socket = null;
    }
    this.connected = false;
    this.emitEvent("status", "medium", "Client engine disconnected", {
      state: "disconnected",
    });
    this.cleanup();
  }

  async startScan(request: ScanRequest): Promise<void> {
    if (!this.connected || !this.socket) {
      throw new Error("Engine not connected");
    }

    const target = request.paths?.[0];
    if (!target) {
      throw new Error("Scan target required");
    }

    if (this.manualScanStartedAt) {
      return;
    }

    this.manualScanStartedAt = Date.now();
    this.manualScanTarget = target;

    this.emitEvent("scan_progress", "low", "Manual scan started", {
      progress: 0,
      target,
    });

    const escaped = target.replace(/\"/g, '\\"');
    this.socket.write(`scan \"${escaped}\"\n`);
  }

  setSettings(settings: AvSettings): void {
    const normalized = normalizeSettings(settings);
    this.settings = { ...normalized };
    ensureConfig(this.workingDir, this.settings);
    this.emitEvent("info", "low", "Client engine settings updated", {
      settings: this.settings,
    });
    // Note: Config is read by Service on startup.
    // Restarting the service remotely isn't possible via pipe yet unless we implement a command.
    // For now we just save the config.
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
      if (!this.connected || !this.socket) {
        return;
      }
      // Optional: send ping to keepalive
      // this.socket.write("ping\n");

      this.emitEvent("heartbeat", "low", "Client heartbeat", {
        engineVersion: "client-1.0.0",
        pingMs: 10 + Math.round(Math.random() * 12),
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
      isError || lower.includes("fatal")
        ? "high"
        : lower.includes("error") || lower.includes("failed")
          ? "medium"
          : "low";

    if (
      trimmed.includes("Process monitoring started") ||
      trimmed.includes("Monitoring active")
    ) {
      this.emitEvent("status", "low", "Client engine online", {
        state: "connected",
      });
      return;
    }

    // ... rest of the parsing logic is identical ...
    // Copying the parsing logic from previous version:

    if (trimmed.includes("Process monitoring stopped")) {
      this.emitEvent("status", "medium", "Client engine stopped", {
        state: "disconnected",
      });
      return;
    }

    if (trimmed.includes("Failed to open driver device")) {
      this.emitEvent("status", "high", "Driver unavailable", {
        state: "disconnected",
        fatal: true,
      });
      return;
    }

    if (trimmed.includes("Successfully connected to driver")) {
      this.emitEvent("status", "low", "Driver connected", {
        driver: "connected",
      });
      return;
    }

    if (trimmed.includes("FATAL ERROR")) {
      this.emitEvent("status", "high", trimmed, {
        state: "disconnected",
        fatal: true,
      });
      return;
    }

    if (trimmed.startsWith("[SCAN]")) {
      const target =
        extractAfterColon(trimmed) ?? this.manualScanTarget ?? "Manual scan";

      // Attempt to extract percentage (e.g. "[SCAN] 45% - Scanning: path")
      let progress = 10;
      const percentMatch = trimmed.match(/(\d+)%/);
      if (percentMatch) {
        progress = parseInt(percentMatch[1], 10);
      }

      this.emitEvent("scan_progress", "low", trimmed, { progress, target });
      return;
    }

    if (trimmed.startsWith("[SCAN RESULT]")) {
      const target =
        extractAfterColon(trimmed) ?? this.manualScanTarget ?? "Manual scan";
      const isThreat = trimmed.includes("THREAT");
      const durationSec = this.manualScanStartedAt
        ? Math.max(
            1,
            Math.round((Date.now() - this.manualScanStartedAt) / 1000),
          )
        : null;

      this.emitEvent("scan_complete", isThreat ? "high" : "low", trimmed, {
        target,
        durationSec,
        threatsFound: isThreat ? 1 : 0,
      });

      if (isThreat) {
        this.emitEvent("threat_detected", "high", trimmed, { target });
      }

      this.manualScanStartedAt = null;
      this.manualScanTarget = null;
      return;
    }

    if (trimmed.startsWith("[SCAN ERROR]")) {
      const target =
        extractAfterColon(trimmed) ?? this.manualScanTarget ?? "Manual scan";
      const durationSec = this.manualScanStartedAt
        ? Math.max(
            1,
            Math.round((Date.now() - this.manualScanStartedAt) / 1000),
          )
        : null;
      this.emitEvent("scan_complete", "medium", trimmed, {
        target,
        durationSec,
        threatsFound: 0,
        failed: true,
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
      this.emitEvent("info", "medium", trimmed);
      return;
    }

    if (trimmed.startsWith("[QUARANTINE]")) {
      this.emitEvent("quarantine", "medium", trimmed, {
        target: extractAfterColon(trimmed),
      });
      return;
    }

    if (trimmed.startsWith("[DELETE]")) {
      this.emitEvent("info", "medium", trimmed);
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

    if (trimmed.startsWith("[CAPABILITIES]")) {
      try {
        const jsonStr = trimmed.substring("[CAPABILITIES]".length).trim();
        const caps = JSON.parse(jsonStr);
        this.emitEvent(
          "capabilities_update",
          "low",
          "Engine capabilities received",
          caps,
        );
      } catch (e) {
        this.emitEvent(
          "info",
          "medium",
          "Failed to parse capabilities: " + trimmed,
        );
      }
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
    data?: Record<string, unknown>,
  ): void {
    const event: AvEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      severity,
      message,
      data,
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

    // Do NOT clear socket here, it's cleared in disconnect/error logic carefully
    if (this.socket && this.socket.destroyed) {
      this.socket = null;
    }

    this.manualScanStartedAt = null;
    this.manualScanTarget = null;
    this.connected = false;
  }
}

// Helpers
const resolveBinaryPath = (explicitPath?: string): string | null => {
  const envPath = explicitPath ?? process.env.AYDO_ENGINE_PATH;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  const repoRoot = path.resolve(process.cwd(), "..", "..");
  const candidates = [
    path.join(repoRoot, "x64", "Release", "Service.exe"),
    path.join(repoRoot, "x64", "Debug", "Service.exe")
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
};

const resolveWorkingDir = (
  binaryPath: string | null,
  explicitDir?: string,
): string => {
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
      accessToken:
        typeof raw.accessToken === "string" ? raw.accessToken : undefined,
      refreshToken:
        typeof raw.refreshToken === "string" ? raw.refreshToken : undefined,
      killThreshold: Number.isFinite(raw.killThreshold)
        ? raw.killThreshold
        : undefined,
      entropyThreshold: Number.isFinite(raw.entropyThreshold)
        ? raw.entropyThreshold
        : undefined,
      runtime: Number.isFinite(raw.runtime) ? raw.runtime : undefined,
      infectedFileAction:
        raw.infectedFileAction === 1
          ? "quarantine"
          : raw.infectedFileAction === 2
            ? "delete"
            : "none",
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
  const runtime = Number.isFinite(settings.runtime)
    ? settings.runtime
    : defaultSettings.runtime;
  return {
    ...defaultSettings,
    ...settings,
    serverUrl: settings.serverUrl?.trim() || defaultSettings.serverUrl,
    accessToken: settings.accessToken ?? "",
    refreshToken: settings.refreshToken ?? "",
    killThreshold,
    entropyThreshold,
    runtime,
    infectedFileAction: settings.infectedFileAction || "none",
    sensitivity: deriveSensitivity(killThreshold),
    scanDepth: deriveScanDepth(runtime),
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
      runtime: normalized.runtime,
      infectedFileAction:
        normalized.infectedFileAction === "quarantine"
          ? 1
          : normalized.infectedFileAction === "delete"
            ? 2
            : 0,
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
