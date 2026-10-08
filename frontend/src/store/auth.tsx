import * as React from "react";
import { api, setAuthToken, USE_MOCK } from "@/api/client";
import { clearSessionQueries } from "@/api/sessionQueryStore";
import type { Principal } from "@/types";

type Status = "loading" | "authed" | "anon";

interface AuthContextValue {
  status: Status;
  user: Principal | null;
  login: (email: string, password: string) => Promise<void>;
  /** Rotate the password (required on first login for default credentials);
   * swaps in the fresh token pair the API returns. */
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = React.createContext<AuthContextValue | null>(null);
const TOKEN_KEY = "rtm.accessToken";
const REFRESH_KEY = "rtm.refreshToken";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = React.useState<Status>("loading");
  const [user, setUser] = React.useState<Principal | null>(null);

  // Restore session on load. Mock mode skips auth entirely.
  React.useEffect(() => {
    if (USE_MOCK) {
      api.auth.me().then((u) => {
        setUser(u);
        setStatus("authed");
      });
      return;
    }
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
      setStatus("anon");
      return;
    }
    setAuthToken(token);
    api.auth
      .me()
      .then((u) => {
        setUser(u);
        setStatus("authed");
      })
      .catch(() => {
        setAuthToken(null);
        clearSessionQueries("threatlocker:");
        localStorage.removeItem(TOKEN_KEY);
        setStatus("anon");
      });
  }, []);

  const login = React.useCallback(async (email: string, password: string) => {
    const res = await api.auth.login(email, password);
    setAuthToken(res.accessToken);
    localStorage.setItem(TOKEN_KEY, res.accessToken);
    localStorage.setItem(REFRESH_KEY, res.refreshToken);
    setUser(res.user);
    setStatus("authed");
  }, []);

  const changePassword = React.useCallback(
    async (currentPassword: string, newPassword: string) => {
      const res = await api.auth.changePassword(currentPassword, newPassword);
      setAuthToken(res.accessToken);
      localStorage.setItem(TOKEN_KEY, res.accessToken);
      localStorage.setItem(REFRESH_KEY, res.refreshToken);
      setUser(res.user);
    },
    [],
  );

  const logout = React.useCallback(() => {
    setAuthToken(null);
    clearSessionQueries("threatlocker:");
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    setUser(null);
    setStatus("anon");
  }, []);

  return (
    <AuthContext.Provider value={{ status, user, login, changePassword, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = React.useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

/** Backward-compatible capability check while older sessions roll forward. */
export function hasPermission(
  user: Principal | null | undefined,
  permission: string,
) {
  if (!user) return false;
  if (user.permissions) return user.permissions.includes(permission);
  return user.isAdmin;
}
