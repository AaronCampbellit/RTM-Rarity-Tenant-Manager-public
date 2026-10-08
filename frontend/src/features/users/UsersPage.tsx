import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Check, CheckCircle2, Columns3, Download, Layers, Play, RotateCcw, X } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useTenant } from "@/store/tenant";
import { useModals } from "@/store/modals";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, SearchInput } from "@/components/ui/input";
import { Dropdown, DropdownItem } from "@/components/ui/dropdown";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { Avatar } from "@/components/common/Avatar";
import { HybridNotice } from "@/components/common/HybridNotice";
import { mfaTone, userTone, sourceLabel, sourceTone } from "@/components/common/status";
import { downloadAuditedCsv } from "@/lib/csv";
import { RunWhatIfDialog } from "./RunWhatIfDialog";
import { UserRawModal } from "./UserRawModal";
import {
  DEFAULT_USER_COLUMNS,
  filterAndSortUsers,
  lastSignInText,
  normalizeVisibleUserColumns,
  USER_COLUMN_DEFINITIONS,
  userColumnText,
  type UserColumnId,
  type UserDirectorySort,
} from "./userDirectory";
import type { User } from "@/types";

const USER_COLUMNS_STORAGE_KEY = "rtm.users.columns.v1";

export function UsersPage() {
  useSetPageTitle("Users");
  const { activeTenant, setActiveTenant, loading: tenantLoading } = useTenant();
  const { version: syncVersion } = useSync();
  const { openWorkingSet } = useModals();
  const { data, loading, error } = useAsync(
    () => api.users.list(activeTenant?.id ?? ""),
    [activeTenant?.id, syncVersion],
    { enabled: Boolean(activeTenant?.id) },
  );

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState<Partial<Record<UserColumnId, string>>>({});
  const [sort, setSort] = useState<UserDirectorySort>({ column: "name", direction: "asc" });
  const [visibleColumns, setVisibleColumns] = useState<UserColumnId[]>(() => {
    try {
      return normalizeVisibleUserColumns(JSON.parse(localStorage.getItem(USER_COLUMNS_STORAGE_KEY) ?? "null"));
    } catch {
      return DEFAULT_USER_COLUMNS;
    }
  });
  const [whatIfOpen, setWhatIfOpen] = useState(false);
  const [rawUser, setRawUser] = useState<User | null>(null);
  const [loadedWorkingSet, setLoadedWorkingSet] = useState<{ id: string; name: string } | null>(null);
  const [workingSetError, setWorkingSetError] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
  const workingSetId = searchParams.get("workingSet");

  // Seed the filter from the header search box (?q=) when arriving via /users?q=…
  useEffect(() => {
    const urlQ = searchParams.get("q");
    if (urlQ) setQ(urlQ);
  }, [searchParams]);

  useEffect(() => {
    if (!workingSetId) return;
    let cancelled = false;
    api.workingSets.get(workingSetId).then((workingSet) => {
      if (cancelled) return;
      if (activeTenant?.id !== workingSet.tenantId) {
        setActiveTenant(workingSet.tenantId);
        return;
      }
      setSelected(new Set(workingSet.userIds));
      setLoadedWorkingSet({ id: workingSet.id, name: workingSet.name });
      setWorkingSetError(null);
    }).catch((err) => {
      if (!cancelled) setWorkingSetError(err instanceof RtmApiError ? err.message : "The Working Set could not be loaded.");
    });
    return () => { cancelled = true; };
  }, [activeTenant?.id, setActiveTenant, workingSetId]);

  useEffect(() => {
    localStorage.setItem(USER_COLUMNS_STORAGE_KEY, JSON.stringify(visibleColumns));
  }, [visibleColumns]);

  const rows = useMemo(
    () => filterAndSortUsers(data ?? [], q, filters, sort),
    [data, filters, q, sort],
  );

  const exportCsv = () =>
    void downloadAuditedCsv(
      {
        kind: "users",
        filename: "users.csv",
        rowCount: rows.length,
        tenantId: activeTenant?.id,
        headers: visibleColumns.map((column) => USER_COLUMN_DEFINITIONS.find(({ id }) => id === column)?.label ?? column),
        rows: rows.map((user) => visibleColumns.map((column) => userColumnText(user, column))),
      },
      api.exports.generate,
    );

  const allChecked = rows.length > 0 && rows.every((u) => selected.has(u.id));
  const someChecked = rows.some((u) => selected.has(u.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const toggleAll = () =>
    setSelected(allChecked ? new Set() : new Set(rows.map((u) => u.id)));

  const toggleSort = (column: UserColumnId) => setSort((current) => ({
    column,
    direction: current.column === column && current.direction === "asc" ? "desc" : "asc",
  }));

  const toggleColumn = (column: UserColumnId) => {
    if (column === "name") return;
    setVisibleColumns((current) => current.includes(column)
      ? current.filter((candidate) => candidate !== column)
      : USER_COLUMN_DEFINITIONS.filter(({ id }) => [...current, column].includes(id)).map(({ id }) => id));
  };

  const renderCell = (column: UserColumnId, user: User) => {
    if (column === "name") {
      return (
        <button className="flex items-center gap-2.5 text-left" title="View user details" onClick={() => setRawUser(user)}>
          <Avatar name={user.name} />
          <span className="font-semibold text-fg hover:underline">{user.name}</span>
        </button>
      );
    }
    if (column === "mfa") return <Badge tone={mfaTone(user.mfa)}>{user.mfa}</Badge>;
    if (column === "source") return <Badge tone={sourceTone(user.sourceOfAuthority)} dot={false}>{sourceLabel(user.sourceOfAuthority)}</Badge>;
    if (column === "status") return <Badge tone={userTone(user.status)}>{user.status}</Badge>;
    if (column === "lastSignIn") {
      const value = lastSignInText(user);
      return <span className={user.lastSignInAvailable ? "text-secondary" : "text-warning"} title={user.lastSignIn || value}>{value}</span>;
    }
    const value = userColumnText(user, column);
    return <span className="text-secondary" title={value || undefined}>{value || "—"}</span>;
  };

  const columns: Column<User>[] = [
    {
      key: "sel",
      header: (
        <Checkbox
          checked={allChecked}
          indeterminate={!allChecked && someChecked}
          onChange={toggleAll}
          aria-label="Select all"
        />
      ),
      width: "44px",
      cell: (u) => (
        <Checkbox checked={selected.has(u.id)} onChange={() => toggle(u.id)} aria-label={`Select ${u.name}`} />
      ),
    },
    ...visibleColumns.map((column): Column<User> => {
      const definition = USER_COLUMN_DEFINITIONS.find(({ id }) => id === column)!;
      return {
        key: column,
        header: definition.label,
        width: definition.width,
        className: "min-w-[110px]",
        sortDirection: sort.column === column ? sort.direction : undefined,
        onSort: () => toggleSort(column),
        filter: (
          <Input
            aria-label={`Filter ${definition.label}`}
            placeholder="Filter…"
            value={filters[column] ?? ""}
            onChange={(event) => setFilters((current) => ({ ...current, [column]: event.target.value }))}
            className="h-7 min-w-[94px] rounded-[6px] px-2 text-[11px] font-normal normal-case tracking-normal"
          />
        ),
        cell: (user) => renderCell(column, user),
      };
    }),
  ];

  const hasSynced = (data ?? []).some((u) => u.sourceOfAuthority === "on_prem");

  return (
    <div className="pb-16">
      <PageToolbar count={`${data?.length ?? 0} users`}>
        <SearchInput
          placeholder="Search users…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {Object.values(filters).some((value) => value?.trim()) ? (
          <Button variant="ghost" onClick={() => setFilters({})}>
            <RotateCcw className="size-4" />
            Clear filters
          </Button>
        ) : null}
        <Dropdown
          align="end"
          menuClassName="max-h-[min(520px,70vh)] w-[280px] overflow-y-auto p-2"
          trigger={({ toggle }) => (
            <Button variant="default" onClick={toggle} aria-label="Choose user table columns">
              <Columns3 className="size-4" />
              Columns
              <span className="text-[11px] text-muted">{visibleColumns.length}</span>
            </Button>
          )}
        >
          {() => (
            <>
              <div className="flex items-center justify-between px-2 pb-2 pt-1">
                <span className="text-[11px] font-semibold uppercase tracking-[.5px] text-faint">Show columns</span>
                <button type="button" className="text-[11px] text-accent hover:underline" onClick={() => setVisibleColumns(DEFAULT_USER_COLUMNS)}>Reset</button>
              </div>
              {USER_COLUMN_DEFINITIONS.map((definition) => {
                const checked = visibleColumns.includes(definition.id);
                return (
                  <DropdownItem
                    key={definition.id}
                    role="menuitemcheckbox"
                    aria-checked={checked}
                    disabled={definition.id === "name"}
                    onClick={() => toggleColumn(definition.id)}
                    className="justify-between disabled:cursor-default disabled:opacity-70"
                  >
                    <span>{definition.label}</span>
                    {checked ? <Check aria-hidden="true" className="size-4 text-accent" /> : <span className="size-4" />}
                  </DropdownItem>
                );
              })}
            </>
          )}
        </Dropdown>
        <Button variant="default" onClick={exportCsv} disabled={loading || rows.length === 0}>
          <Download className="size-4" />
          Export CSV
        </Button>
      </PageToolbar>

      {hasSynced && (
        <div className="mb-3">
          <HybridNotice mode="mixed" compact />
        </div>
      )}

      {loadedWorkingSet && (
        <div className="mb-3 flex items-center gap-2 rounded-[9px] border border-info/30 bg-info/10 px-3 py-2 text-[12px] text-secondary">
          <CheckCircle2 className="size-4 shrink-0 text-info" />
          <span className="min-w-0 flex-1 truncate">
            Loaded Working Set <strong className="text-fg">{loadedWorkingSet.name}</strong> — {selected.size} users selected.
          </span>
          <Button variant="ghost" size="sm" onClick={() => { setSelected(new Set()); setLoadedWorkingSet(null); }}>Clear</Button>
        </div>
      )}
      {workingSetError && (
        <div role="alert" className="mb-3 rounded-[9px] border border-danger/30 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          {workingSetError}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={rows}
      loading={tenantLoading || loading}
        error={error}
        getRowId={(u) => u.id}
        isRowActive={(u) => selected.has(u.id)}
        emptyTitle="No users match"
      />

      {!loading && !error && (
        <div className="mt-3 flex items-center justify-between text-[12px] text-muted">
          <span>
            Showing {rows.length} of {data?.length ?? 0}
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" disabled>
              Prev
            </Button>
            <Button variant="ghost" size="sm" disabled>
              Next
            </Button>
          </div>
        </div>
      )}

      {/* Floating action bar — appears when ≥1 user selected */}
      {selected.size > 0 && (
        <div className="fixed bottom-6 left-[calc(250px+50%-125px)] z-30 -translate-x-1/2 animate-pop">
          <div className="flex items-center gap-2 rounded-[12px] border border-[var(--border-strong)] bg-raised px-3 py-2 shadow-[0_14px_40px_rgba(0,0,0,.55)]">
            <span className="px-1.5 text-[13px] font-semibold text-fg">
              {selected.size} selected
            </span>
            <span className="h-5 w-px bg-white/10" />
            <Button
              variant="default"
              size="sm"
              onClick={() => openWorkingSet({
                tenantId: activeTenant?.id ?? "",
                tenant: activeTenant?.name ?? "",
                userIds: Array.from(selected),
                onSaved: () => setSelected(new Set()),
              })}
            >
              <Layers className="size-3.5" />
              Save as Working Set
            </Button>
            <Button variant="accent" size="sm" onClick={() => setWhatIfOpen(true)}>
              <Play className="size-3.5" />
              Run What If
            </Button>
            <Button variant="ghost" size="icon" aria-label="Clear" onClick={() => setSelected(new Set())}>
              <X className="size-4" />
            </Button>
          </div>
        </div>
      )}

      <RunWhatIfDialog
        open={whatIfOpen}
        tenantId={activeTenant?.id ?? ""}
        userIds={Array.from(selected)}
        onClose={() => setWhatIfOpen(false)}
      />

      <UserRawModal
        open={rawUser !== null}
        tenantId={activeTenant?.id ?? ""}
        user={rawUser}
        onClose={() => setRawUser(null)}
      />
    </div>
  );
}
