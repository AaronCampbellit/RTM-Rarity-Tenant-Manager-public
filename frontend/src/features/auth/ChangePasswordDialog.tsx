import { useState } from "react";
import { AlertTriangle, CircleCheck, KeyRound, Loader2 } from "lucide-react";
import { RtmApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/store/auth";

const MIN_LENGTH = 12;

/** Self-service password change for a normally authenticated local account. */
export function ChangePasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, changePassword } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [complete, setComplete] = useState(false);

  function close() {
    if (busy) return;
    setCurrent("");
    setNext("");
    setConfirm("");
    setError(null);
    setComplete(false);
    onClose();
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (next.length < MIN_LENGTH) {
      setError(`The new password must be at least ${MIN_LENGTH} characters.`);
      return;
    }
    if (next === current) {
      setError("The new password must be different from the current password.");
      return;
    }
    if (next !== confirm) {
      setError("The password confirmation does not match.");
      return;
    }
    setBusy(true);
    try {
      await changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setComplete(true);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Unable to change the password. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={close} width={460}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <KeyRound className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Change password</h2>
            <p className="text-[12px] text-muted">{user?.email}</p>
          </div>
        </div>

        {complete ? (
          <div className="mt-4">
            <div className="flex gap-3 rounded-[10px] border border-[var(--border-strong)] bg-raised/40 p-4">
              <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--color-success)]" />
              <div>
                <p className="text-[12.5px] font-semibold text-fg">Password changed</p>
                <p className="mt-1 text-[12px] leading-5 text-muted">
                  Your other RTM sessions have been revoked. This session is using newly issued credentials.
                </p>
              </div>
            </div>
            <div className="mt-4 flex justify-end">
              <Button variant="accent" onClick={close}>Done</Button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} className="mt-4 space-y-3.5">
            <p className="text-[12px] leading-5 text-muted">
              Choose a password of at least {MIN_LENGTH} characters. Changing it revokes every other RTM session for this account.
            </p>
            <div>
              <label htmlFor="local-current-password" className="mb-1.5 block text-[12px] font-semibold text-secondary">Current password</label>
              <Input id="local-current-password" type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} required autoFocus />
            </div>
            <div>
              <label htmlFor="local-new-password" className="mb-1.5 block text-[12px] font-semibold text-secondary">New password</label>
              <Input id="local-new-password" type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} required />
            </div>
            <div>
              <label htmlFor="local-confirm-password" className="mb-1.5 block text-[12px] font-semibold text-secondary">Confirm new password</label>
              <Input id="local-confirm-password" type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} required />
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-[8px] border border-[var(--border-strong)] bg-[var(--bg-danger)] px-3 py-2 text-[12.5px] text-[var(--color-danger)]">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="default" onClick={close} disabled={busy}>Cancel</Button>
              <Button type="submit" variant="accent" disabled={busy}>
                {busy && <Loader2 className="size-4 animate-spin" />}
                Change password
              </Button>
            </div>
          </form>
        )}
      </div>
    </Dialog>
  );
}
