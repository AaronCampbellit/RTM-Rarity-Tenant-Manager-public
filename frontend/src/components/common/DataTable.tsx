import * as React from "react";
import { AlertTriangle, ArrowDown, ArrowUp, ArrowUpDown, Inbox, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { RtmApiError } from "@/api/client";

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  align?: "left" | "right";
  sortDirection?: "asc" | "desc";
  onSort?: () => void;
  /** Optional second header-row control for per-column filtering. */
  filter?: React.ReactNode;
  /** Fixed column width, e.g. "120px" or "30%". */
  width?: string;
  className?: string;
  cell: (row: T, index: number) => React.ReactNode;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[] | undefined;
  density?: "default" | "compact";
  fixedLayout?: boolean;
  loading?: boolean;
  error?: Error | RtmApiError;
  emptyTitle?: string;
  emptyHint?: string;
  getRowId: (row: T) => string;
  onRowClick?: (row: T) => void;
  isRowActive?: (row: T) => boolean;
}

const COL_HEADER =
  "px-4 text-left text-[10.5px] font-bold uppercase tracking-[.5px] text-faint";

export function DataTable<T>({
  columns,
  rows,
  density = "default",
  fixedLayout = false,
  loading,
  error,
  emptyTitle = "Nothing to show",
  emptyHint,
  getRowId,
  onRowClick,
  isRowActive,
}: DataTableProps<T>) {
  return (
    <div className="overflow-hidden rounded-[12px] border border-[var(--border-card)] bg-card">
      <div className="overflow-x-auto">
        <table className={cn("w-full border-collapse text-left", fixedLayout && "table-fixed")}>
          <thead>
            <tr className="border-b border-[var(--border-card)] bg-th">
              {columns.map((c) => (
                <th
                  key={c.key}
                  aria-sort={c.onSort ? c.sortDirection === "asc" ? "ascending" : c.sortDirection === "desc" ? "descending" : "none" : undefined}
                  className={cn(
                    COL_HEADER,
                    "h-9 select-none",
                    density === "compact" && "px-2.5",
                    c.align === "right" && "text-right",
                    c.className,
                  )}
                  style={c.width ? { width: c.width } : undefined}
                >
                  {c.onSort ? (
                    <button
                      type="button"
                      onClick={c.onSort}
                      className={cn(
                        "inline-flex w-full items-center gap-1.5 rounded-sm py-1 text-inherit transition-colors hover:text-body focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ac)]/50",
                        c.align === "right" && "justify-end",
                      )}
                    >
                      <span>{c.header}</span>
                      {c.sortDirection === "asc" ? <ArrowUp aria-hidden="true" className="size-3" /> : c.sortDirection === "desc" ? <ArrowDown aria-hidden="true" className="size-3" /> : <ArrowUpDown aria-hidden="true" className="size-3 opacity-60" />}
                    </button>
                  ) : c.header}
                </th>
              ))}
            </tr>
            {columns.some((column) => column.filter != null) ? (
              <tr className="border-b border-[var(--border-card)] bg-th">
                {columns.map((column) => (
                  <th
                    key={column.key}
                    className={cn("px-2 pb-2", column.align === "right" && "text-right", column.className)}
                  >
                    {column.filter}
                  </th>
                ))}
              </tr>
            ) : null}
          </thead>
          <tbody>
            {loading && <StateRow span={columns.length} kind="loading" />}
            {!loading && error && (
              <StateRow span={columns.length} kind="error" error={error} />
            )}
            {!loading && !error && rows && rows.length === 0 && (
              <StateRow
                span={columns.length}
                kind="empty"
                title={emptyTitle}
                hint={emptyHint}
              />
            )}
            {!loading &&
              !error &&
              rows?.map((row, i) => (
                <tr
                  key={getRowId(row)}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    "border-b border-[var(--border-card)] last:border-0 transition-colors",
                    onRowClick && "cursor-pointer",
                    "hover:bg-[var(--row-hover)]",
                    isRowActive?.(row) && "bg-[var(--acb)]",
                  )}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={cn(
                        "px-4 align-middle text-[12.5px] text-body",
                        density === "compact" && "px-2.5",
                        c.align === "right" && "text-right tabular",
                        c.className,
                      )}
                      style={{ paddingTop: "var(--rp)", paddingBottom: "var(--rp)" }}
                    >
                      {c.cell(row, i)}
                    </td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StateRow({
  span,
  kind,
  error,
  title,
  hint,
}: {
  span: number;
  kind: "loading" | "empty" | "error";
  error?: Error | RtmApiError;
  title?: string;
  hint?: string;
}) {
  return (
    <tr>
      <td colSpan={span} className="px-4 py-16">
        <div className="sticky left-0 flex w-[calc(100vw-6rem)] flex-col items-center justify-center gap-2 text-center md:static md:w-auto">
          {kind === "loading" && (
            <>
              <Loader2 className="size-5 animate-spin text-muted" />
              <p className="text-[13px] text-muted">Loading…</p>
            </>
          )}
          {kind === "empty" && (
            <>
              <Inbox className="size-6 text-faint" />
              <p className="text-[13px] font-medium text-secondary">{title}</p>
              {hint && <p className="text-[12px] text-muted">{hint}</p>}
            </>
          )}
          {kind === "error" && (
            <>
              <AlertTriangle className="size-6 text-[#f7868a]" />
              <p className="text-[13px] font-medium text-[#f7868a]">
                {error?.message ?? "Something went wrong."}
              </p>
              {error instanceof RtmApiError && (
                <p className="mono text-[11px] text-muted">
                  {error.code} · {error.correlationId}
                </p>
              )}
            </>
          )}
        </div>
      </td>
    </tr>
  );
}
