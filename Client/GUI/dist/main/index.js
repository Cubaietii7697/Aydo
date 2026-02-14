import { ipcMain, dialog, app, BrowserWindow, shell } from "electron";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import __cjs_mod__ from "node:module";
const __filename = import.meta.filename;
const __dirname = import.meta.dirname;
const require2 = __cjs_mod__.createRequire(import.meta.url);
const AV_PROTOCOL_VERSION = 1;
const isFastSim = process.env.AYDO_SIM_FAST === "1";
const HEARTBEAT_INTERVAL_MS$1 = isFastSim ? 1200 : 4500;
const AMBIENT_INTERVAL_MS = isFastSim ? 3200 : 11e3;
const defaultSettings$2 = {
  sensitivity: "balanced",
  realtime: true,
  startupScan: true,
  scanDepth: "standard",
  telemetry: true,
  serverUrl: "http://192.168.56.1",
  accessToken: "",
  refreshToken: "",
  killThreshold: 150,
  entropyThreshold: 6,
  runtime: 60
};
class AntivirusSimulator extends EventEmitter {
  constructor() {
    super(...arguments);
    this.connected = false;
    this.heartbeatTimer = null;
    this.ambientTimer = null;
    this.scanTimer = null;
    this.progress = 0;
    this.settings = { ...defaultSettings$2 };
  }
  async handshake(request) {
    await delay(320);
    if (request.protocolVersion !== AV_PROTOCOL_VERSION) {
      return {
        ok: false,
        engineVersion: "sim-1.0.0",
        serverTime: (/* @__PURE__ */ new Date()).toISOString(),
        message: "Protocol mismatch"
      };
    }
    if (!request.token) {
      return {
        ok: false,
        engineVersion: "sim-1.0.0",
        serverTime: (/* @__PURE__ */ new Date()).toISOString(),
        message: "Missing token"
      };
    }
    return {
      ok: true,
      engineVersion: "sim-1.0.0",
      serverTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  async connect() {
    if (this.connected) {
      return;
    }
    this.connected = true;
    this.emitEvent("status", "low", "Simulator connected", { state: "connected" });
    this.heartbeatTimer = setInterval(() => {
      this.emitEvent("heartbeat", "low", "Engine heartbeat", {
        pingMs: 18 + Math.round(Math.random() * 15),
        engineVersion: "sim-1.0.0"
      });
    }, HEARTBEAT_INTERVAL_MS$1);
    this.ambientTimer = setInterval(() => {
      if (!this.connected || this.scanTimer) {
        return;
      }
      const roll = Math.random();
      if (roll > 0.82) {
        this.emitEvent("threat_detected", "high", "Suspicious behavior blocked", {
          family: "Ransomware.Generic",
          action: "blocked"
        });
      } else if (roll > 0.55) {
        this.emitEvent("info", "low", "Realtime shield recalibrated", {
          module: "behavioral"
        });
      }
    }, AMBIENT_INTERVAL_MS);
  }
  async disconnect() {
    if (!this.connected) {
      return;
    }
    this.connected = false;
    this.progress = 0;
    this.clearTimers();
    this.emitEvent("status", "medium", "Simulator disconnected", { state: "disconnected" });
  }
  async startScan(request) {
    if (!this.connected) {
      throw new Error("Engine not connected");
    }
    if (this.scanTimer) {
      return;
    }
    this.progress = 0;
    const scanTarget = request.paths?.[0] ?? "System";
    this.emitEvent("info", "low", `Scan started (${request.depth})`, {
      target: scanTarget,
      depth: request.depth
    });
    const scanInterval = isFastSim ? 240 : 720;
    this.scanTimer = setInterval(() => {
      this.progress = Math.min(100, this.progress + 6 + Math.round(Math.random() * 10));
      if (Math.random() > this.thresholdForThreat()) {
        this.emitEvent("threat_detected", "high", "Threat neutralized", {
          file: "C:/Windows/Temp/trace.tmp",
          family: "Trojan.Injector",
          action: "quarantined"
        });
      }
      this.emitEvent("scan_progress", "low", "Scanning", {
        progress: this.progress,
        itemsScanned: 320 + Math.round(Math.random() * 180),
        target: scanTarget
      });
      if (this.progress >= 100) {
        this.finishScan(scanTarget);
      }
    }, scanInterval);
  }
  setSettings(settings) {
    this.settings = { ...settings };
    this.emitEvent("info", "low", "Settings applied", { settings: this.settings });
  }
  getSettings() {
    return { ...this.settings };
  }
  getType() {
    return "simulator";
  }
  onEvent(listener) {
    this.on("event", listener);
    return () => this.off("event", listener);
  }
  isConnected() {
    return this.connected;
  }
  finishScan(target) {
    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }
    this.emitEvent("scan_complete", "low", "Scan completed", {
      target,
      durationSec: 68 + Math.round(Math.random() * 40),
      threatsFound: Math.round(Math.random() * 3)
    });
  }
  thresholdForThreat() {
    switch (this.settings.sensitivity) {
      case "low":
        return 0.98;
      case "aggressive":
        return 0.7;
      default:
        return 0.85;
    }
  }
  emitEvent(type, severity, message, data) {
    const event = {
      id: randomUUID(),
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      type,
      severity,
      message,
      data
    };
    this.emit("event", event);
  }
  clearTimers() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.ambientTimer) {
      clearInterval(this.ambientTimer);
      this.ambientTimer = null;
    }
    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }
  }
}
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
const CONNECT_TIMEOUT_MS = 2400;
const RECONNECT_DELAY_MS = 4e3;
const HEARTBEAT_TIMEOUT_MS = 14e3;
const MAX_EVENTS = 120;
const defaultSettings$1 = {
  sensitivity: "balanced",
  realtime: true,
  startupScan: true,
  scanDepth: "standard",
  telemetry: true,
  serverUrl: "http://192.168.56.1",
  accessToken: "",
  refreshToken: "",
  killThreshold: 150,
  entropyThreshold: 6,
  runtime: 60
};
const defaultStats = {
  dailyActivity: 1240,
  detections: 3,
  quarantined: 2,
  lastScanAt: null,
  lastScanDurationSec: null
};
const defaultBreakdown = [
  { label: "Clean", value: 78 },
  { label: "Blocked", value: 14 },
  { label: "Quarantined", value: 8 }
];
class AntivirusBridge {
  constructor(sender, engine = new AntivirusSimulator()) {
    this.connectionState = "disconnected";
    this.statusMessage = "Engine offline";
    this.settings = { ...defaultSettings$1 };
    this.stats = { ...defaultStats };
    this.activity = seedActivity();
    this.breakdown = [...defaultBreakdown];
    this.recentEvents = [];
    this.scan = { inProgress: false, progress: 0, target: null };
    this.lastHeartbeatAt = null;
    this.reconnectTimer = null;
    this.watchdogTimer = null;
    this.clientId = randomUUID();
    this.userRequestedDisconnect = false;
    this.unsubscribe = null;
    this.sender = sender;
    this.engine = engine;
    this.engineType = engine.getType();
    this.settings = engine.getSettings();
  }
  init() {
    if (this.unsubscribe) {
      return;
    }
    this.unsubscribe = this.engine.onEvent((event) => this.handleEvent(event));
    this.settings = this.engine.getSettings();
    this.watchdogTimer = setInterval(() => this.monitorHeartbeat(), 6e3);
  }
  async connect() {
    if (this.connectionState === "connected" || this.connectionState === "connecting") {
      return { ok: true, message: "Already connected" };
    }
    this.userRequestedDisconnect = false;
    this.setStatus("connecting", "Negotiating secure channel");
    this.pushEvent("status", "low", "Negotiating secure channel", { state: "connecting" });
    const handshake = await withTimeout(
      this.engine.handshake({
        protocolVersion: AV_PROTOCOL_VERSION,
        clientId: this.clientId,
        token: "local-sim-token"
      }),
      CONNECT_TIMEOUT_MS
    ).catch((error) => {
      const message = error instanceof Error ? error.message : "Handshake failed";
      this.setStatus("disconnected", message);
      return { ok: false, message };
    });
    if (!handshake || !handshake.ok) {
      this.setStatus("disconnected", handshake?.message ?? "Handshake rejected");
      return { ok: false, message: handshake?.message ?? "Handshake rejected" };
    }
    const connectError = await withTimeout(this.engine.connect(), CONNECT_TIMEOUT_MS).catch((error) => error);
    if (connectError) {
      const message = connectError instanceof Error ? connectError.message : "Connection failed";
      this.setStatus("disconnected", message);
      return { ok: false, message };
    }
    if (!this.engine.isConnected()) {
      this.setStatus("disconnected", "Engine unavailable");
      return { ok: false, message: "Engine unavailable" };
    }
    this.setStatus("connected", "Live protection active");
    this.pushEvent("status", "low", "Engine connected", { engineVersion: handshake.engineVersion });
    return { ok: true, message: "Connected" };
  }
  async disconnect() {
    this.userRequestedDisconnect = true;
    await this.engine.disconnect();
    this.setStatus("disconnected", "Engine offline");
    this.pushEvent("status", "medium", "Engine disconnected", { reason: "user" });
    return { ok: true, message: "Disconnected" };
  }
  async startScan(request) {
    if (this.connectionState !== "connected") {
      return { ok: false, message: "Engine not connected" };
    }
    this.scan.inProgress = true;
    this.scan.progress = 0;
    this.scan.target = request.paths?.[0] ?? "System";
    await this.engine.startScan(request);
    return { ok: true, message: "Scan started" };
  }
  setSettings(settings) {
    this.engine.setSettings(settings);
    this.settings = this.engine.getSettings();
    this.pushEvent("info", "low", "Settings updated", { settings: this.settings });
  }
  getSnapshot() {
    return {
      engineType: this.engineType,
      connectionState: this.connectionState,
      statusMessage: this.statusMessage,
      stats: { ...this.stats },
      activity: [...this.activity],
      breakdown: [...this.breakdown],
      recentEvents: [...this.recentEvents],
      settings: { ...this.settings },
      scan: { ...this.scan }
    };
  }
  handleEvent(event) {
    if (event.type === "heartbeat") {
      this.lastHeartbeatAt = Date.now();
      this.bumpActivity(1 + Math.round(Math.random() * 2));
      this.stats.dailyActivity += 2 + Math.round(Math.random() * 3);
      this.setStatus("connected", "Live protection active");
    }
    if (event.type === "scan_progress") {
      const progress = typeof event.data?.progress === "number" ? event.data?.progress : 0;
      this.scan.inProgress = true;
      this.scan.progress = Math.min(100, progress);
      this.scan.target = typeof event.data?.target === "string" ? event.data?.target : this.scan.target;
      this.bumpActivity(2 + Math.round(Math.random() * 3));
    }
    if (event.type === "threat_detected") {
      this.stats.detections += 1;
      const action = event.data?.action === "quarantined" ? "Quarantined" : "Blocked";
      this.incrementBreakdown(action);
      if (action === "Quarantined") {
        this.stats.quarantined += 1;
      }
    }
    if (event.type === "scan_complete") {
      this.scan.inProgress = false;
      this.scan.progress = 100;
      this.stats.lastScanAt = event.timestamp;
      this.stats.lastScanDurationSec = typeof event.data?.durationSec === "number" ? event.data?.durationSec : null;
      this.bumpActivity(6 + Math.round(Math.random() * 4));
      this.stats.dailyActivity += 14 + Math.round(Math.random() * 8);
    }
    if (event.type === "status") {
      const state = event.data?.state === "connected" || event.data?.state === "disconnected" ? event.data?.state : void 0;
      const fatal = event.data?.fatal === true;
      if (state === "disconnected" && !this.userRequestedDisconnect && !fatal) {
        this.setStatus("reconnecting", "Connection lost, retrying");
        this.scheduleReconnect();
      } else if (state === "disconnected" && fatal) {
        this.setStatus("disconnected", event.message);
      }
    }
    this.statusMessage = event.message;
    this.pushEvent(event.type, event.severity, event.message, event.data);
  }
  pushEvent(type, severity, message, data) {
    const event = {
      id: randomUUID(),
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      type,
      severity,
      message,
      data
    };
    this.recentEvents = [event, ...this.recentEvents].slice(0, MAX_EVENTS);
    this.sender("av:event", { event, snapshot: this.getSnapshot() });
  }
  setStatus(state, message) {
    this.connectionState = state;
    this.statusMessage = message;
  }
  bumpActivity(value) {
    const now = /* @__PURE__ */ new Date();
    const label = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const next = this.activity.slice(1);
    next.push({ time: label, value: Math.max(4, value + Math.round(Math.random() * 6)) });
    this.activity = next;
  }
  incrementBreakdown(label) {
    this.breakdown = this.breakdown.map(
      (item) => item.label === label ? { ...item, value: item.value + 1 } : item
    );
  }
  monitorHeartbeat() {
    if (this.connectionState !== "connected") {
      return;
    }
    if (this.lastHeartbeatAt && Date.now() - this.lastHeartbeatAt > HEARTBEAT_TIMEOUT_MS) {
      this.setStatus("reconnecting", "Heartbeat lost, reconnecting");
      this.pushEvent("status", "medium", "Heartbeat lost, reconnecting", { state: "reconnecting" });
      this.scheduleReconnect();
    }
  }
  scheduleReconnect() {
    if (this.userRequestedDisconnect || this.reconnectTimer) {
      return;
    }
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      await this.connect();
    }, RECONNECT_DELAY_MS);
  }
}
function seedActivity() {
  const now = /* @__PURE__ */ new Date();
  const points = [];
  for (let i = 11; i >= 0; i -= 1) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1e3);
    points.push({
      time: time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      value: 12 + Math.round(Math.random() * 28)
    });
  }
  return points;
}
function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Operation timed out")), ms);
    promise.then((result) => {
      clearTimeout(timer);
      resolve(result);
    }).catch((error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}
const defaultSettings = {
  sensitivity: "balanced",
  realtime: true,
  startupScan: true,
  scanDepth: "standard",
  telemetry: true,
  serverUrl: "http://192.168.56.1",
  accessToken: "",
  refreshToken: "",
  killThreshold: 150,
  entropyThreshold: 6,
  runtime: 60
};
const HEARTBEAT_INTERVAL_MS = 5e3;
class ClientEngine extends EventEmitter {
  constructor(options = {}) {
    super();
    this.child = null;
    this.connected = false;
    this.heartbeatTimer = null;
    this.scanTimer = null;
    this.manualScanStartedAt = null;
    this.manualScanTarget = null;
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
  isAvailable() {
    return !!this.binaryPath && fs.existsSync(this.binaryPath);
  }
  async handshake(request) {
    if (request.protocolVersion !== AV_PROTOCOL_VERSION) {
      return {
        ok: false,
        engineVersion: "client-unknown",
        serverTime: (/* @__PURE__ */ new Date()).toISOString(),
        message: "Protocol mismatch"
      };
    }
    if (!this.binaryPath || !fs.existsSync(this.binaryPath)) {
      return {
        ok: false,
        engineVersion: "client-unknown",
        serverTime: (/* @__PURE__ */ new Date()).toISOString(),
        message: "Client engine binary not found"
      };
    }
    return {
      ok: true,
      engineVersion: "client-1.0.0",
      serverTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  async connect() {
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
  async disconnect() {
    if (!this.child) {
      this.connected = false;
      return;
    }
    this.child.kill();
    this.connected = false;
    this.emitEvent("status", "medium", "Client engine disconnected", { state: "disconnected" });
    this.cleanup();
  }
  async startScan(request) {
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
    const escaped = target.replace(/\"/g, '\\"');
    this.child.stdin.write(`scan "${escaped}"
`);
  }
  setSettings(settings) {
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
  getSettings() {
    return { ...this.settings };
  }
  getType() {
    return "client";
  }
  onEvent(listener) {
    this.on("event", listener);
    return () => this.off("event", listener);
  }
  isConnected() {
    return this.connected;
  }
  startHeartbeat() {
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
  handleLine(line, isError = false) {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }
    const lower = trimmed.toLowerCase();
    const logSeverity = isError || lower.includes("fatal") ? "high" : lower.includes("error") || lower.includes("failed") ? "medium" : "low";
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
      const durationSec = this.manualScanStartedAt ? Math.max(1, Math.round((Date.now() - this.manualScanStartedAt) / 1e3)) : null;
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
      const durationSec = this.manualScanStartedAt ? Math.max(1, Math.round((Date.now() - this.manualScanStartedAt) / 1e3)) : null;
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
    if (trimmed.includes("[NEW PROCESS]") || trimmed.includes("Scanning:") || trimmed.includes("[CACHED]") || trimmed.includes("[SIGNED]") || trimmed.includes("[HASH]") || trimmed.includes("[YARA]") || trimmed.includes("[ENTROPY]") || trimmed.includes("[CLEAN]")) {
      this.emitEvent("info", logSeverity, trimmed.replace(/^->\s*/, ""));
      return;
    }
    if (trimmed.includes("[ERROR]") || isError) {
      this.emitEvent("info", logSeverity, trimmed);
      return;
    }
    if (trimmed.includes("Connecting to server") || trimmed.includes("Initializing scanning engines") || trimmed.includes("Initialized YARA scanning engine") || trimmed.includes("Loaded hashes database") || trimmed.includes("All scanning engines initialized")) {
      this.emitEvent("info", "low", trimmed);
      return;
    }
    this.emitEvent("info", logSeverity, trimmed);
  }
  emitEvent(type, severity, message, data) {
    const event = {
      id: randomUUID(),
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      type,
      severity,
      message,
      data
    };
    this.emit("event", event);
  }
  cleanup() {
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
const resolveBinaryPath = (explicitPath) => {
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
const resolveWorkingDir = (binaryPath, explicitDir) => {
  const envDir = explicitDir ?? process.env.AYDO_ENGINE_CWD;
  if (envDir) {
    return envDir;
  }
  if (binaryPath) {
    return path.resolve(path.dirname(binaryPath), "..", "..");
  }
  return process.cwd();
};
const readConfig = (workingDir) => {
  try {
    const configPath = path.join(workingDir, "config.json");
    if (!fs.existsSync(configPath)) {
      return {};
    }
    const raw = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    return {
      serverUrl: typeof raw.serverUrl === "string" ? raw.serverUrl : void 0,
      accessToken: typeof raw.accessToken === "string" ? raw.accessToken : void 0,
      refreshToken: typeof raw.refreshToken === "string" ? raw.refreshToken : void 0,
      killThreshold: Number.isFinite(raw.killThreshold) ? raw.killThreshold : void 0,
      entropyThreshold: Number.isFinite(raw.entropyThreshold) ? raw.entropyThreshold : void 0,
      runtime: Number.isFinite(raw.runtime) ? raw.runtime : void 0
    };
  } catch {
    return {};
  }
};
const deriveSensitivity = (killThreshold) => {
  if (killThreshold <= 120) {
    return "aggressive";
  }
  if (killThreshold >= 190) {
    return "low";
  }
  return "balanced";
};
const deriveScanDepth = (runtime) => {
  if (runtime <= 35) {
    return "quick";
  }
  if (runtime >= 100) {
    return "deep";
  }
  return "standard";
};
const normalizeSettings = (settings) => {
  const killThreshold = Number.isFinite(settings.killThreshold) ? settings.killThreshold : defaultSettings.killThreshold;
  const entropyThreshold = Number.isFinite(settings.entropyThreshold) ? settings.entropyThreshold : defaultSettings.entropyThreshold;
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
const ensureConfig = (workingDir, settings) => {
  try {
    const normalized = normalizeSettings(settings);
    fs.mkdirSync(workingDir, { recursive: true });
    const configPath = path.join(workingDir, "config.json");
    const current = fs.existsSync(configPath) ? JSON.parse(fs.readFileSync(configPath, "utf-8")) : {};
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
  }
};
const extractAfterColon = (value) => {
  const index = value.indexOf(":");
  if (index === -1) {
    return null;
  }
  const target = value.slice(index + 1).trim();
  return target.length > 0 ? target : null;
};
const createAntivirusEngine = () => {
  const mode = (process.env.AYDO_ENGINE ?? "client").toLowerCase();
  if (mode === "simulator") {
    return new AntivirusSimulator();
  }
  const client = new ClientEngine();
  if (mode === "client") {
    return client;
  }
  if (client.isAvailable()) {
    return client;
  }
  return new AntivirusSimulator();
};
const sendToRenderer = (channel, payload) => {
  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send(channel, payload);
  }
};
const bridge = new AntivirusBridge(sendToRenderer, createAntivirusEngine());
bridge.init();
const normalizeServerUrl = (raw) => {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  return trimmed.replace(/\/+$/, "");
};
const performAuth = async (mode, payload) => {
  if (process.env.AYDO_AUTH_OFFLINE === "1") {
    const nickname = payload.nickname ?? payload.email.split("@")[0] ?? "Analyst";
    return {
      ok: true,
      message: "Offline auth",
      accessToken: "offline-access",
      refreshToken: "offline-refresh",
      nickname
    };
  }
  const serverUrl = normalizeServerUrl(payload.serverUrl);
  if (!serverUrl) {
    return { ok: false, message: "Server URL is required" };
  }
  const endpoint = mode === "login" ? "/api/auth/login" : "/api/auth/register";
  const body = mode === "login" ? { email: payload.email, password: payload.password } : { email: payload.email, nickname: payload.nickname ?? payload.email, password: payload.password };
  try {
    const response = await fetch(`${serverUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => null);
    if (!response.ok) {
      return { ok: false, message: data?.message ?? `Auth failed (${response.status})` };
    }
    const accessToken = data?.accessToken;
    const refreshToken = data?.refreshToken;
    let nickname = payload.nickname;
    if (accessToken) {
      try {
        const meResponse = await fetch(`${serverUrl}/api/auth/me`, {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        if (meResponse.ok) {
          const meData = await meResponse.json().catch(() => null);
          if (meData?.nickname) {
            nickname = meData.nickname;
          }
        }
      } catch {
      }
    }
    return {
      ok: true,
      message: data?.message ?? "Authenticated",
      accessToken,
      refreshToken,
      nickname
    };
  } catch (error) {
    const nickname = payload.nickname ?? payload.email.split("@")[0] ?? "Analyst";
    const message = error instanceof Error ? error.message : "Network error";
    return {
      ok: true,
      message: `Server offline. Offline session enabled. (${message})`,
      nickname,
      offline: true
    };
  }
};
const resolvePreloadPath = () => {
  const candidates = [
    path.join(__dirname, "../preload/preload.mjs"),
    path.join(process.cwd(), "dist/preload/preload.mjs"),
    path.join(process.cwd(), "out/preload/preload.mjs")
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return candidates[0];
};
const findDevServer = async () => {
  const ports = [5173, 5174, 5175, 5176];
  for (const port of ports) {
    try {
      const url = `http://localhost:${port}`;
      const response = await fetch(url, { method: "HEAD", timeout: 1e3 });
      if (response.ok || response.status === 304) {
        return url;
      }
    } catch {
    }
  }
  return void 0;
};
const createWindow = async () => {
  const preloadPath = resolvePreloadPath();
  let devServerUrl = process.env.VITE_DEV_SERVER_URL;
  if (!devServerUrl) {
    devServerUrl = await findDevServer();
  }
  const mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1080,
    minHeight: 720,
    backgroundColor: "#0c1219",
    titleBarStyle: "hiddenInset",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      preload: preloadPath
    }
  });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http")) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });
  if (devServerUrl) {
    mainWindow.loadURL(devServerUrl);
  } else {
    mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
  }
};
ipcMain.handle("av:connect", async () => bridge.connect());
ipcMain.handle("av:disconnect", async () => bridge.disconnect());
ipcMain.handle("av:snapshot", async () => bridge.getSnapshot());
ipcMain.handle("av:start-scan", async (_event, request) => bridge.startScan(request));
ipcMain.handle("av:set-settings", async (_event, settings) => bridge.setSettings(settings));
ipcMain.handle("av:pick-scan-target", async () => {
  const result = await dialog.showOpenDialog({
    title: "Select file to scan",
    properties: ["openFile"]
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0] ?? null;
});
ipcMain.handle(
  "auth:login",
  async (_event, payload) => performAuth("login", payload)
);
ipcMain.handle(
  "auth:register",
  async (_event, payload) => performAuth("register", payload)
);
app.whenReady().then(async () => {
  await createWindow();
  bridge.connect();
  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createWindow();
    }
  });
});
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
