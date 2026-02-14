import { app, BrowserWindow, ipcMain, shell, dialog } from "electron";
import fs from "node:fs";
import path from "node:path";
import { AntivirusBridge } from "./antivirus/bridge";
import { createAntivirusEngine } from "./antivirus/engineFactory";
import type { AvEventEnvelope, AvSettings, ScanRequest } from "@shared/antivirus";

const sendToRenderer = (channel: string, payload: AvEventEnvelope) => {
  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send(channel, payload);
  }
};

const bridge = new AntivirusBridge(sendToRenderer, createAntivirusEngine());
bridge.init();

type AuthResponse = {
  ok: boolean;
  message: string;
  accessToken?: string;
  refreshToken?: string;
  nickname?: string;
  offline?: boolean;
};

const normalizeServerUrl = (raw: string): string => {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  return trimmed.replace(/\/+$/, "");
};

const performAuth = async (
  mode: "login" | "register",
  payload: { email: string; password: string; nickname?: string; serverUrl: string }
): Promise<AuthResponse> => {
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
  const body =
    mode === "login"
      ? { email: payload.email, password: payload.password }
      : { email: payload.email, nickname: payload.nickname ?? payload.email, password: payload.password };

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

    const accessToken = data?.accessToken as string | undefined;
    const refreshToken = data?.refreshToken as string | undefined;
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
        // Ignore profile errors; login is still valid.
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

const resolvePreloadPath = (): string => {
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

const findDevServer = async (): Promise<string | undefined> => {
  // Try common dev server ports
  const ports = [5173, 5174, 5175, 5176];
  
  for (const port of ports) {
    try {
      const url = `http://localhost:${port}`;
      const response = await fetch(url, { method: "HEAD", timeout: 1000 });
      if (response.ok || response.status === 304) {
        return url;
      }
    } catch {
      // Port not responding, try next
    }
  }
  
  return undefined;
};

const createWindow = async (): Promise<void> => {
  const preloadPath = resolvePreloadPath();
  
  // Detect dev server URL
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
ipcMain.handle("av:start-scan", async (_event, request: ScanRequest) => bridge.startScan(request));
ipcMain.handle("av:set-settings", async (_event, settings: AvSettings) => bridge.setSettings(settings));
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

ipcMain.handle("auth:login", async (_event, payload: { email: string; password: string; serverUrl: string }) =>
  performAuth("login", payload)
);
ipcMain.handle(
  "auth:register",
  async (_event, payload: { email: string; password: string; nickname: string; serverUrl: string }) =>
    performAuth("register", payload)
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
