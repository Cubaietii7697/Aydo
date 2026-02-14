import { ipcRenderer, contextBridge } from "electron";
const preloadStatus = {
  ok: true,
  error: null,
  sandboxed: typeof process !== "undefined" ? Boolean(process.sandboxed) : false
};
try {
  const api = {
    connect: () => ipcRenderer.invoke("av:connect"),
    disconnect: () => ipcRenderer.invoke("av:disconnect"),
    getSnapshot: () => ipcRenderer.invoke("av:snapshot"),
    startScan: (request) => ipcRenderer.invoke("av:start-scan", request),
    setSettings: (settings) => ipcRenderer.invoke("av:set-settings", settings),
    pickScanTarget: () => ipcRenderer.invoke("av:pick-scan-target"),
    authLogin: (payload) => ipcRenderer.invoke("auth:login", payload),
    authRegister: (payload) => ipcRenderer.invoke("auth:register", payload),
    onEvent: (handler) => {
      const listener = (_event, payload) => handler(payload);
      ipcRenderer.on("av:event", listener);
      return () => ipcRenderer.removeListener("av:event", listener);
    }
  };
  contextBridge.exposeInMainWorld("avBridge", api);
} catch (error) {
  preloadStatus.ok = false;
  preloadStatus.error = error instanceof Error ? error.message : "Unknown preload error";
}
contextBridge.exposeInMainWorld("__preloadStatus", preloadStatus);
