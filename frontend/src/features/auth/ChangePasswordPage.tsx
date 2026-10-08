import { useState } from "react";
import { AlertTriangle, KeyRound, Loader2 } from "lucide-react";
import { useAuth } from "@/store/auth";
import { Logo } from "@/components/layout/Logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RtmApiError } from "@/api/client";

const MIN_LENGTH = 12;

/**
 * Forced password rotation. Rendered instead of the app whenever the signed-in
 * account still holds a default/seeded password — the API rejects everything
 * else with PASSWORD_CHANGE_REQUIRED until the rotation succeeds.
 */
export function ChangePasswordPage() {
  const { user, changePassword, logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (next.length < MIN_LENGTH) {
      setError(`The new password must be at least ${MIN_LENGTH} characters.`);
      return;
    }
    if (next === current) {
      setError("The new password must be different from the current one.");
      return;
    }
    if (next !== confirm) {
      setError("The password confirmation does not match.");
      return;
    }
    setBusy(true);
    try {
      await changePassword(current, next);
      // Success: user.mustChangePassword flips false and the app renders.
    } catch (err) {
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Unable to change the password. Please try again.",
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
          <div className="flex items-center gap-2.5">
            <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
              <KeyRound className="size-4 text-secondary" />
            </div>
            <div>
              <h1 className="text-[16px] font-bold text-fg-strong">Set a new password</h1>
              <p className="text-[12px] text-muted">{user?.email}</p>
            </div>
          </div>
          <p className="mt-3 text-[12.5px] text-muted">
            This account is using a default password. Choose a new one (at
            least {MIN_LENGTH} characters) to continue.
          </p>

          <form onSubmit={submit} className="mt-5 space-y-3.5">
            <div>
              <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
                Current password
              </label>
              <Input
                type="password"
                autoComplete="current-password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div>
              <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
                New password
              </label>
              <Input
                type="password"
                autoComplete="new-password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
                Confirm new password
              </label>
              <Input
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
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
              Change password
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={logout}
              disabled={busy}
            >
              Sign out
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
