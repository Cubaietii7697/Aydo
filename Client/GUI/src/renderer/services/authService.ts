import { useSyncExternalStore } from "react";
import { antivirusService } from "./antivirusService";

export type UserProfile = {
  name: string;
  email: string;
  role: string;
  avatarUrl?: string | null;
};

type AuthState = {
  user: UserProfile | null;
  loading: boolean;
  error: string | null;
};

const STORAGE_KEY = "aydo.user";
const SERVER_URL_KEY = "aydo.serverUrl";
const SERVER_DEFAULT_URL = "http://192.168.56.1";
const MIN_PASSWORD_LENGTH = 6;
const GUEST_SIM_DELAY_MS = 600;

class AuthService {
  private state: AuthState = {
    user: null,
    loading: false,
    error: null,
  };
  private listeners = new Set<() => void>();

  constructor() {
    this.hydrate();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  getState(): AuthState {
    return this.state;
  }

  getStoredServerUrl(): string {
    try {
      const stored = localStorage.getItem(SERVER_URL_KEY);
      return stored ?? SERVER_DEFAULT_URL;
    } catch {
      return SERVER_DEFAULT_URL;
    }
  }

  async login(
    email: string,
    password: string,
    serverUrl: string,
  ): Promise<{ ok: boolean; message: string }> {
    this.update({ loading: true, error: null });

    if (!email.includes("@") || password.length < MIN_PASSWORD_LENGTH) {
      this.update({
        loading: false,
        error:
          "Invalid credentials. Try a valid email and a stronger password.",
      });
      return { ok: false, message: "Invalid credentials" };
    }

    const bridge = typeof window !== "undefined" ? window.avBridge : undefined;
    if (!bridge) {
      const message =
        "Desktop bridge unavailable. Run the Electron app (bun run dev) instead of the browser URL.";
      this.update({ loading: false, error: message });
      return { ok: false, message };
    }

    const authResult = await bridge.authLogin({
      email,
      password,
      serverUrl,
    });

    if (!authResult.ok) {
      this.update({ loading: false, error: authResult.message });
      return { ok: false, message: authResult.message };
    }

    const stored = this.readStored();
    const avatarUrl = stored?.email === email ? stored.avatarUrl : null;
    const name =
      authResult.nickname ??
      email
        .split("@")[0]
        .replace(/\./g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase());
    const roleSuffix = authResult.offline ? " (Offline)" : "";

    this.update({
      loading: false,
      error: null,
      user: {
        name,
        email,
        role: `Sigma Rizzler${roleSuffix}`,
        avatarUrl,
      },
    });

    this.persist();
    this.persistServerUrl(serverUrl);

    await antivirusService.init();
    const currentSettings = antivirusService.getState().settings;
    await antivirusService.updateSettings({
      ...currentSettings,
      serverUrl,
      accessToken: authResult.accessToken ?? currentSettings.accessToken,
      refreshToken: authResult.refreshToken ?? currentSettings.refreshToken,
    });
    await antivirusService.connect();

    return { ok: true, message: authResult.message };
  }

  async register(
    name: string,
    email: string,
    password: string,
    serverUrl: string,
  ): Promise<{ ok: boolean; message: string }> {
    this.update({ loading: true, error: null });

    if (!name.trim()) {
      this.update({ loading: false, error: "Please enter your name." });
      return { ok: false, message: "Missing name" };
    }

    if (!email.includes("@") || password.length < MIN_PASSWORD_LENGTH) {
      this.update({
        loading: false,
        error: "Invalid details. Use a valid email and at least 6 characters.",
      });
      return { ok: false, message: "Invalid details" };
    }

    const bridge = typeof window !== "undefined" ? window.avBridge : undefined;
    if (!bridge) {
      const message =
        "Desktop bridge unavailable. Run the Electron app (bun run dev) instead of the browser URL.";
      this.update({ loading: false, error: message });
      return { ok: false, message };
    }

    const authResult = await bridge.authRegister({
      email,
      password,
      nickname: name,
      serverUrl,
    });

    if (!authResult.ok) {
      this.update({ loading: false, error: authResult.message });
      return { ok: false, message: authResult.message };
    }

    const roleSuffix = authResult.offline ? " (Offline)" : "";
    this.update({
      loading: false,
      error: null,
      user: {
        name: authResult.nickname ?? name,
        email,
        role: `Sigma Rizzler ${roleSuffix}`,
        avatarUrl: null,
      },
    });

    this.persist();
    this.persistServerUrl(serverUrl);

    await antivirusService.init();
    const currentSettings = antivirusService.getState().settings;
    await antivirusService.updateSettings({
      ...currentSettings,
      serverUrl,
      accessToken: authResult.accessToken ?? currentSettings.accessToken,
      refreshToken: authResult.refreshToken ?? currentSettings.refreshToken,
    });
    await antivirusService.connect();

    return { ok: true, message: authResult.message };
  }

  setAvatar(avatarUrl: string | null): void {
    if (!this.state.user) {
      return;
    }

    this.update({
      user: {
        ...this.state.user,
        avatarUrl,
      },
    });

    this.persist();
  }

  async continueAsGuest(): Promise<{ ok: boolean }> {
    this.update({ loading: true, error: null });

    // Simulate a short delay for premium feel
    await new Promise((resolve) => setTimeout(resolve, GUEST_SIM_DELAY_MS));

    this.update({
      loading: false,
      error: null,
      user: {
        name: "Smooth Operator",
        email: "guest@aydo.ontop",
        role: "SKIBIDI!!!",
        avatarUrl: null,
      },
    });

    this.persist();

    await antivirusService.init();
    await antivirusService.connect();

    return { ok: true };
  }

  logout(): void {
    this.update({ user: null, loading: false, error: null });
    this.persist();
    antivirusService.disconnect();
    antivirusService.updateSettings({
      ...antivirusService.getState().settings,
      accessToken: "",
      refreshToken: "",
    });
  }

  private update(partial: Partial<AuthState>): void {
    this.state = { ...this.state, ...partial };
    this.listeners.forEach((listener) => listener());
  }

  private hydrate(): void {
    const stored = this.readStored();
    if (stored) {
      this.state = { ...this.state, user: stored };
    }
  }

  private persist(): void {
    try {
      if (this.state.user) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(this.state.user));
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // ignore storage errors
    }
  }

  private persistServerUrl(url: string): void {
    try {
      localStorage.setItem(SERVER_URL_KEY, url);
    } catch {
      // ignore storage errors
    }
  }

  private readStored(): UserProfile | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        return null;
      }
      return JSON.parse(raw) as UserProfile;
    } catch {
      return null;
    }
  }
}

export const authService = new AuthService();

export const useAuth = (): AuthState =>
  useSyncExternalStore(
    (listener) => authService.subscribe(listener),
    () => authService.getState(),
    () => authService.getState(),
  );
