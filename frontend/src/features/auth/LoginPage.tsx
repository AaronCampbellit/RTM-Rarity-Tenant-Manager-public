import { useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { useAuth } from "@/store/auth";
import { Logo } from "@/components/layout/Logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RtmApiError } from "@/api/client";

export function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState("admin@rtm.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(
        err instanceof RtmApiError ? err.message : "Unable to sign in. Please try again.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-app px-4">
      <div className="w-full max-w-[380px]">
        <div className="mb-6 flex justify-center">
          <Logo />
        </div>
        <div className="rounded-[14px] border border-[var(--border-card)] bg-card p-6 shadow-[0_24px_70px_rgba(0,0,0,.5)]">
          <h1 className="text-[16px] font-bold text-fg-strong">Sign in</h1>
          <p className="mt-1 text-[12.5px] text-muted">
            Use your RTM operator credentials.
          </p>

          <form onSubmit={submit} className="mt-5 space-y-3.5">
            <div>
              <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
                Email
              </label>
              <Input
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
                Password
              </label>
              <Input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoFocus
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <Button type="submit" variant="accent" className="w-full" disabled={busy}>
              {busy && <Loader2 className="size-4 animate-spin" />}
              Sign in
            </Button>
          </form>
        </div>
        <p className="mt-4 text-center text-[11.5px] text-faint">
          RTM — Rarity Tenant Manager · secure MSP console
        </p>
      </div>
    </div>
  );
}
