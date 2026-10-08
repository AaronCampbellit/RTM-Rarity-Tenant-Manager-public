import { useState } from "react";
import {
  AlertTriangle,
  KeyRound,
  Loader2,
  Lock,
  Pencil,
  Trash2,
  UserPlus,
} from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useAuth } from "@/store/auth";
import { useSetPageTitle } from "@/store/page";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy-button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { UnderlineTabs } from "@/components/ui/tabs";
import { Avatar } from "@/components/common/Avatar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { roleTone } from "@/components/common/status";
import type { AppSetting, Role, Technician } from "@/types";
import { DEFAULT_SESSION_TIMEOUT, SESSION_TIMEOUT_OPTIONS } from "./sessionTimeout";

const TABS = [
  { key: "technicians", label: "Technicians" },
  { key: "roles", label: "Roles" },
  { key: "settings", label: "App Settings" },
];

export function AdminSettingsPage() {
  useSetPageTitle("Admin Settings");
  const [tab, setTab] = useState("technicians");

  return (
    <div>
      <UnderlineTabs tabs={TABS} value={tab} onChange={setTab} />
      {tab === "technicians" && <Technicians />}
      {tab === "roles" && <Roles />}
      {tab === "settings" && <AppSettings />}
    </div>
  );
}

// ---- Technicians (real accounts; full CRUD) ----

function Technicians() {
  const { user } = useAuth();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, loading, error } = useAsync(() => api.admin.technicians(), [refreshKey]);
  const roles = useAsync(() => api.admin.roles(), []);
  const [inviting, setInviting] = useState(false);
  const [editing, setEditing] = useState<Technician | null>(null);

  const refresh = () => setRefreshKey((k) => k + 1);

  const columns: Column<Technician>[] = [
    {
      key: "name",
      header: "Technician",
      cell: (t) => (
        <div className="flex items-center gap-2.5">
          <Avatar name={t.name} />
          <div>
            <p className="font-semibold text-fg">{t.name}</p>
            <p className="text-[11.5px] text-muted">{t.email}</p>
          </div>
        </div>
      ),
    },
    { key: "role", header: "Role", cell: (t) => <Badge tone={roleTone(t.role)} dot={false}>{t.role}</Badge> },
    { key: "tenants", header: "Tenants", width: "90px", cell: (t) => <span className="text-secondary">{t.tenants}</span> },
    {
      key: "status",
      header: "Status",
      width: "100px",
      cell: (t) => (
        <Badge tone={t.status === "Active" ? "success" : t.status === "Disabled" ? "neutral" : "warning"}>
          {t.status}
        </Badge>
      ),
    },
    {
      key: "credentials",
      header: "Credentials",
      width: "165px",
      cell: (t) => (
        <Badge tone={t.mustChangePassword ? "warning" : "success"}>
          {t.mustChangePassword ? "Change required" : "Current"}
        </Badge>
      ),
    },
    { key: "last", header: "Last Active", width: "120px", cell: (t) => <span className="text-secondary">{t.lastActive}</span> },
  ];

  return (
    <div>
      <div className="mb-3 flex justify-end">
        <Button variant="accent" onClick={() => setInviting(true)}>
          <UserPlus className="size-4" />
          Add Technician
        </Button>
      </div>
      <DataTable
        columns={columns}
        rows={data}
        loading={loading}
        error={error}
        getRowId={(t) => t.id}
        onRowClick={(t) => setEditing(t)}
      />
      <p className="mt-3 text-[12px] text-muted">
        Click an account to edit its role and status or issue a one-time
        password reset. Every RTM user has access to all tenants.
      </p>

      <InviteTechnicianDialog
        open={inviting}
        roles={roles.data ?? []}
        onClose={() => setInviting(false)}
        onCreated={refresh}
      />
      {editing && (
        <EditTechnicianDialog
          technician={editing}
          selfId={user?.id ?? ""}
          roles={roles.data ?? []}
          onClose={() => setEditing(null)}
          onChanged={refresh}
        />
      )}
    </div>
  );
}

function InviteTechnicianDialog({
  open,
  roles,
  onClose,
  onCreated,
}: {
  open: boolean;
  roles: Role[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"Admin" | "Technician">("Technician");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  function reset() {
    setName("");
    setEmail("");
    setRole("Technician" as const);
    setBusy(false);
    setError(null);
    setTempPassword(null);
  }

  function close() {
    if (busy) return;
    reset();
    onClose();
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.admin.createTechnician({ name, email, role });
      setBusy(false);
      setTempPassword(res.tempPassword);
      onCreated();
    } catch (err) {
      setBusy(false);
      setError(err instanceof RtmApiError ? err.message : "Unable to create the technician.");
    }
  }

  if (tempPassword) {
    return (
      <Dialog open={open} onClose={close} width={460}>
        <div className="px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
              <KeyRound className="size-4 text-secondary" />
            </div>
            <h2 className="text-[15px] font-bold text-fg-strong">Technician created</h2>
          </div>
          <p className="mt-3 text-[12.5px] leading-relaxed text-muted">
            Hand this one-time password to <span className="font-semibold text-fg">{name}</span>.
            It is shown only now, and the first login forces them to set their own.
          </p>
          <div className="mt-3 flex items-center gap-2 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 py-2.5">
            <span className="mono flex-1 text-[13px] text-fg">{tempPassword}</span>
            <CopyButton value={tempPassword} />
          </div>
          <div className="mt-4 flex justify-end">
            <Button variant="accent" onClick={close}>
              Done
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onClose={close} width={480}>
      <form onSubmit={submit} className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <UserPlus className="size-4 text-secondary" />
          </div>
          <h2 className="text-[15px] font-bold text-fg-strong">Add Technician</h2>
        </div>

        <div className="mt-4 space-y-3.5">
          <div>
            <label className="mb-1.5 block text-[12px] font-semibold text-secondary">Name</label>
            <Input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
          </div>
          <div>
            <label className="mb-1.5 block text-[12px] font-semibold text-secondary">Email</label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div>
            <label className="mb-1.5 block text-[12px] font-semibold text-secondary">Role</label>
            <RoleSelect
              roles={roles}
              value={role}
              onChange={(v) => setRole(v as "Admin" | "Technician")}
            />
            <p className="mt-1.5 text-[11.5px] text-muted">
              Admins manage tenants, technicians, write actions, and settings.
              Both roles work across every tenant.
            </p>
          </div>
        </div>

        {error && <ErrorNote message={error} />}

        <div className="mt-4 flex justify-end gap-2">
          <Button type="button" variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" variant="accent" disabled={busy}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Create Technician
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function EditTechnicianDialog({
  technician,
  selfId,
  roles,
  onClose,
  onChanged,
}: {
  technician: Technician;
  selfId: string;
  roles: Role[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const isSelf = technician.id === selfId;
  const [role, setRole] = useState(technician.role);
  const [active, setActive] = useState(technician.status === "Active");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      if (!isSelf) {
        await api.admin.updateTechnician(technician.id, {
          role,
          status: active ? "Active" : "Disabled",
        });
      }
      onChanged();
      onClose();
    } catch (err) {
      setBusy(false);
      setError(err instanceof RtmApiError ? err.message : "Unable to save the changes.");
    }
  }

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await api.admin.deleteTechnician(technician.id);
      onChanged();
      onClose();
    } catch (err) {
      setBusy(false);
      setConfirmDelete(false);
      setError(err instanceof RtmApiError ? err.message : "Unable to delete the technician.");
    }
  }

  async function resetPassword() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.admin.resetTechnicianPassword(technician.id);
      setTempPassword(result.tempPassword);
      setConfirmReset(false);
      setBusy(false);
      onChanged();
    } catch (err) {
      setBusy(false);
      setConfirmReset(false);
      setError(err instanceof RtmApiError ? err.message : "Unable to reset the password.");
    }
  }

  if (tempPassword) {
    return (
      <Dialog open onClose={() => !busy && onClose()} width={460}>
        <div className="px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
              <KeyRound className="size-4 text-secondary" />
            </div>
            <h2 className="text-[15px] font-bold text-fg-strong">Password reset</h2>
          </div>
          <p className="mt-3 text-[12.5px] leading-relaxed text-muted">
            Every existing session for <span className="font-semibold text-fg">{technician.name}</span> has been revoked.
            Give them this one-time password; RTM will require a new password at sign-in.
          </p>
          <div className="mt-3 flex items-center gap-2 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 py-2.5">
            <span className="mono flex-1 text-[13px] text-fg">{tempPassword}</span>
            <CopyButton value={tempPassword} />
          </div>
          <p className="mt-2 text-[11.5px] text-muted">This password will not be shown again after you close this dialog.</p>
          <div className="mt-4 flex justify-end">
            <Button variant="accent" onClick={onClose}>Done</Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open onClose={() => !busy && onClose()} width={480}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <Avatar name={technician.name} />
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">{technician.name}</h2>
            <p className="text-[12px] text-muted">{technician.email}</p>
          </div>
        </div>

        {isSelf && (
          <p className="mt-3 rounded-[8px] border border-[var(--border-card)] bg-[#19191d] px-3 py-2 text-[12px] text-muted">
            This is your own account — role and status can only be changed by
            another admin.
          </p>
        )}

        <div className="mt-4 space-y-3.5">
          {!isSelf && (
            <>
              <div>
                <label className="mb-1.5 block text-[12px] font-semibold text-secondary">Role</label>
                <RoleSelect roles={roles} value={role} onChange={setRole} />
              </div>
              <label className="flex items-center justify-between gap-2 text-[13px] text-body">
                <span>Account enabled (can sign in)</span>
                <Switch checked={active} onChange={() => setActive((v) => !v)} />
              </label>
            </>
          )}
          <p className="text-[12px] text-muted">
            Every RTM account has access to all tenants; the role controls
            platform administration and write actions.
          </p>
          {technician.mustChangePassword && (
            <p className="rounded-[8px] border border-[var(--border-card)] bg-raised/40 px-3 py-2 text-[12px] text-muted">
              This account must change its password before it can use RTM.
            </p>
          )}
          {!isSelf && confirmReset && (
            <div className="rounded-[8px] border border-[var(--border-strong)] bg-raised/40 px-3 py-2.5">
              <p className="text-[12.5px] font-semibold text-fg">Reset this account's password?</p>
              <p className="mt-1 text-[11.5px] leading-5 text-muted">
                This immediately revokes every session and replaces the current password with a one-time temporary password.
              </p>
              <div className="mt-2.5 flex gap-2">
                <Button size="sm" variant="accent" onClick={resetPassword} disabled={busy}>
                  {busy && <Loader2 className="size-3.5 animate-spin" />}
                  Confirm reset
                </Button>
                <Button size="sm" variant="default" onClick={() => setConfirmReset(false)} disabled={busy}>Keep password</Button>
              </div>
            </div>
          )}
        </div>

        {error && <ErrorNote message={error} />}

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          {!isSelf ? (
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={() => { setConfirmDelete(false); setConfirmReset(true); }} disabled={busy || confirmReset}>
                <KeyRound className="size-4" />
                Reset password
              </Button>
              {confirmDelete ? (
                <Button variant="accent" onClick={remove} disabled={busy}>
                  {busy && <Loader2 className="size-4 animate-spin" />}
                  Confirm delete
                </Button>
              ) : (
                <Button variant="outline" onClick={() => { setConfirmReset(false); setConfirmDelete(true); }} disabled={busy}>
                  <Trash2 className="size-4" />
                  Delete
                </Button>
              )}
            </div>
          ) : (
            <span />
          )}
          <div className="flex justify-end gap-2">
            <Button variant="default" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button variant="accent" onClick={save} disabled={busy}>
              {busy && <Loader2 className="size-4 animate-spin" />}
              Save
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
}

function RoleSelect({
  roles,
  value,
  onChange,
}: {
  roles: Role[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]"
    >
      {roles.map((r) => (
        <option key={r.name} value={r.name}>
          {r.name}
        </option>
      ))}
    </select>
  );
}

function ErrorNote({ message }: { message: string }) {
  return (
    <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <span>{message}</span>
    </div>
  );
}

// ---- Roles (persisted, capability-backed policies) ----

const ROLE_PERMISSIONS = [
  { key: "tenants.manage", label: "Manage tenants", description: "Connect, edit, and remove managed Microsoft 365 tenants." },
  { key: "technicians.manage", label: "Manage technicians", description: "Invite, edit, reset passwords, disable, and remove RTM operator accounts." },
  { key: "roles.manage", label: "Manage roles", description: "Edit role descriptions and elevated capability assignments." },
  { key: "settings.manage", label: "Manage settings", description: "Change application and global connector settings." },
  { key: "changes.execute", label: "Execute changes", description: "Preview, execute, and revert tenant write actions." },
  { key: "security.manage", label: "Manage detections", description: "Create, tune, and restore Security Operations detection rules." },
  { key: "threatlocker.manage", label: "Manage ThreatLocker", description: "Perform ThreatLocker policy, application, and cleanup actions." },
] as const;

function Roles() {
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, loading, error } = useAsync(() => api.admin.roles(), [refreshKey]);
  const [editing, setEditing] = useState<Role | null>(null);

  if (loading) {
    return <div className="h-44 animate-pulse rounded-[12px] border border-[var(--border-card)] bg-card" />;
  }
  if (error) return <ErrorNote message="Unable to load roles." />;

  return (
    <div>
      <p className="mb-3 text-[12px] text-muted">
        Click a role to edit its description and elevated capabilities. Read access across all managed tenants is included in every role.
      </p>
      <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
        {data?.map((role) => (
          <button
            key={role.name}
            type="button"
            onClick={() => setEditing(role)}
            className="group rounded-[12px] text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ac)]"
          >
            <Card className="h-full p-4 transition-colors group-hover:border-[var(--border-strong)] group-hover:bg-[#202025]">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <h3 className="text-[14px] font-bold text-fg-strong">{role.name}</h3>
                  <Pencil className="size-3.5 text-faint transition-colors group-hover:text-secondary" />
                </div>
                <Badge tone={role.levelTone} dot={false}>{role.level}</Badge>
              </div>
              <p className="mt-1.5 text-[12.5px] leading-relaxed text-secondary">{role.description}</p>
              <div className="mt-3 flex items-center justify-between border-t border-[var(--border-card)] pt-3">
                <span className="text-[12px] text-muted">{role.permissions}</span>
                <span className="text-[12px] font-medium text-secondary">{role.assigned} assigned</span>
              </div>
            </Card>
          </button>
        ))}
      </div>
      {editing && (
        <EditRoleDialog
          role={editing}
          onClose={() => setEditing(null)}
          onSaved={() => setRefreshKey((key) => key + 1)}
        />
      )}
    </div>
  );
}

function EditRoleDialog({
  role,
  onClose,
  onSaved,
}: {
  role: Role;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [description, setDescription] = useState(role.description);
  const [permissionKeys, setPermissionKeys] = useState(() => new Set(role.permissionKeys));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const locked = new Set(role.lockedPermissionKeys ?? []);

  function toggle(permission: string) {
    if (locked.has(permission)) return;
    setPermissionKeys((current) => {
      const next = new Set(current);
      if (next.has(permission)) next.delete(permission);
      else next.add(permission);
      return next;
    });
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.admin.updateRole(role.name, {
        description: description.trim(),
        permissionKeys: ROLE_PERMISSIONS
          .map((permission) => permission.key)
          .filter((permission) => permissionKeys.has(permission)),
      });
      onSaved();
      onClose();
    } catch (err) {
      setBusy(false);
      setError(err instanceof RtmApiError ? err.message : "Unable to save the role.");
    }
  }

  return (
    <Dialog open onClose={() => !busy && onClose()} width={620}>
      <form onSubmit={save} className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Pencil className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Edit {role.name} role</h2>
            <p className="text-[11.5px] text-muted">Changes apply to assigned accounts on their next API request.</p>
          </div>
        </div>

        <label className="mt-4 block text-[12px] font-semibold text-secondary" htmlFor="role-description">
          Description
        </label>
        <textarea
          id="role-description"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          minLength={10}
          maxLength={500}
          required
          rows={3}
          className="mt-1.5 w-full resize-y rounded-[8px] border border-[var(--border-strong)] bg-control px-3 py-2 text-[13px] leading-5 text-fg outline-none focus:border-[var(--ac)]"
        />

        <p className="mt-4 text-[12px] font-semibold text-secondary">Elevated capabilities</p>
        <div className="mt-1.5 overflow-hidden rounded-[9px] border border-[var(--border-card)]">
          {ROLE_PERMISSIONS.map((permission) => {
            const isLocked = locked.has(permission.key);
            return (
              <div
                key={permission.key}
                className="flex items-center justify-between gap-4 border-b border-[var(--border-card)] px-3.5 py-3 last:border-0"
              >
                <span className="min-w-0">
                  <span className="flex items-center gap-1.5 text-[12.5px] font-semibold text-fg">
                    {permission.label}
                    {isLocked && <Lock className="size-3 text-faint" aria-label="Required capability" />}
                  </span>
                  <span className="mt-0.5 block text-[11.5px] leading-4 text-muted">{permission.description}</span>
                </span>
                <Switch
                  ariaLabel={permission.label}
                  checked={permissionKeys.has(permission.key)}
                  disabled={isLocked || busy}
                  onChange={() => toggle(permission.key)}
                />
              </div>
            );
          })}
        </div>
        {role.name === "Admin" && (
          <p className="mt-2 text-[11.5px] text-muted">
            Admin capabilities are locked so platform access and recovery cannot be disabled.
          </p>
        )}
        {error && <ErrorNote message={error} />}
        <div className="mt-4 flex justify-end gap-2">
          <Button type="button" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="accent" disabled={busy || description.trim().length < 10}>
            {busy && <Loader2 className="animate-spin" />}
            Save role
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

// ---- App settings (persisted toggles) ----

function AppSettings() {
  const [refreshKey, setRefreshKey] = useState(0);
  const { data } = useAsync(() => api.admin.settings(), [refreshKey]);
  const [error, setError] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);

  async function toggle(s: AppSetting) {
    if (s.locked || savingKey) return;
    setSavingKey(s.key);
    setError(null);
    try {
      await api.admin.updateSetting(s.key, !s.enabled);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Unable to save the setting.");
    } finally {
      setSavingKey(null);
    }
  }

  async function setValue(s: AppSetting, value: string) {
    if (s.locked || savingKey) return;
    setSavingKey(s.key);
    setError(null);
    try {
      await api.admin.updateSettingValue(s.key, value);
      setRefreshKey((key) => key + 1);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Unable to save the setting.");
    } finally {
      setSavingKey(null);
    }
  }

  return (
    <div>
      {error && <ErrorNote message={error} />}
      <ThreatLockerGlobalSettings />
      <Card className="mt-2">
        {data?.map((s: AppSetting, i) => (
          <div
            key={s.key}
            className="flex items-center justify-between gap-4 border-b border-[var(--border-card)] px-4 py-3.5 last:border-0"
            style={{ animationDelay: `${i * 20}ms` }}
          >
            <div className="min-w-0">
              <p className="flex items-center gap-2 text-[13px] font-semibold text-fg">
                {s.label}
                {s.locked && (
                  <span className="inline-flex items-center gap-1 rounded-[5px] bg-[var(--bg-neutral)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-secondary">
                    <Lock className="size-3" />
                    Enforced
                  </span>
                )}
              </p>
              <p className="mt-0.5 text-[12px] text-muted">{s.description}</p>
            </div>
            {s.key === "session_timeout" ? (
              <div className="flex items-center gap-2">
                {savingKey === s.key && <Loader2 aria-label="Saving session timeout" className="size-4 animate-spin text-muted" />}
                <select
                  key={`${s.key}:${s.value}`}
                  aria-label="Session timeout"
                  defaultValue={s.value || DEFAULT_SESSION_TIMEOUT}
                  disabled={s.locked || savingKey === s.key}
                  onChange={(event) => void setValue(s, event.target.value)}
                  className="h-9 min-w-[150px] rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[12.5px] font-medium text-fg outline-none transition-colors focus:border-[var(--ac)] disabled:cursor-not-allowed disabled:opacity-70"
                >
                  {SESSION_TIMEOUT_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </div>
            ) : (
              <Switch
                checked={s.enabled}
                disabled={s.locked || savingKey === s.key}
                onChange={() => toggle(s)}
              />
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}

function ThreatLockerGlobalSettings() {
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, loading } = useAsync(() => api.admin.threatLocker(), [refreshKey]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const instance = String(form.get("instance") ?? "").trim();
    const token = String(form.get("token") ?? "");
    const parentOrganizationId = String(form.get("parentOrganizationId") ?? "").trim();
    if (!instance || (!token && !data?.tokenConfigured) || !parentOrganizationId) {
      setError("Portal instance, API token, and MSP parent organization ID are required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await api.admin.updateThreatLocker({ instance, token, parentOrganizationId });
      formElement.reset();
      setRefreshKey((key) => key + 1);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Unable to save ThreatLocker settings.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card className="mb-4 p-4">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="text-[13px] font-semibold text-fg">Global ThreatLocker workspace</p>
          <p className="mt-0.5 text-[12px] text-muted">MSP parent credentials for the ThreatLocker workspace and parent-owned app cleanup.</p>
        </div>
        <Badge tone={data?.configured ? "success" : "warning"} dot={false}>
          {loading ? "Checking…" : data?.configured ? "Configured" : "Not configured"}
        </Badge>
      </div>
      {error && <ErrorNote message={error} />}
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={save}>
        <label className="text-[12px] font-semibold text-secondary">
          Portal instance
          <Input name="instance" defaultValue={data?.instance} placeholder="g" className="mt-1.5" disabled={saving} />
        </label>
        <label className="text-[12px] font-semibold text-secondary">
          MSP parent organization ID
          <Input name="parentOrganizationId" defaultValue={data?.parentOrganizationId} placeholder="Organization GUID" className="mt-1.5" disabled={saving} />
        </label>
        <label className="text-[12px] font-semibold text-secondary sm:col-span-2">
          API token
          <Input name="token" type="password" placeholder={data?.tokenConfigured ? "Enter a replacement token to change it" : "ThreatLocker API User token"} className="mt-1.5" disabled={saving} />
          <span className="mt-1 block text-[11px] font-normal text-muted">The token is encrypted and write-only. Leave it blank to keep the current token.</span>
        </label>
        <div className="sm:col-span-2 flex justify-end">
          <Button type="submit" variant="accent" disabled={saving}>{saving && <Loader2 className="size-4 animate-spin" />} Save global connection</Button>
        </div>
      </form>
    </Card>
  );
}
