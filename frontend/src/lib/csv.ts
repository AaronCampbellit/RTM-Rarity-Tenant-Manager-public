/** Quote a CSV field if it contains a comma, quote, or newline. */
function escapeCsvField(field: string | number): string {
  const value = String(field);
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export type ExportKind =
  | "users"
  | "group-members"
  | "mailboxes"
  | "change-history"
  | "global-report"
  | "share-detective"
  | "threatlocker-applications"
  | "threatlocker-devices";

export interface ExportGenerateRequest {
  kind: ExportKind;
  filename: string;
  rowCount: number;
  tenantId?: string;
}

export interface CsvExportRequest extends ExportGenerateRequest {
  headers: string[];
  rows: (string | number)[][];
}

export type AuditExport = (
  request: ExportGenerateRequest,
) => Promise<{ status: "recorded" }>;

export interface CsvDownloadDependencies {
  download: typeof downloadCsv;
  notify: (message: string) => void;
}

const exportFailureMessage =
  "The CSV could not be audited, so RTM did not start the download. Please try again.";

/** Build CSV text from headers + rows and trigger a browser download. */
export function downloadCsv(
  filename: string,
  headers: string[],
  rows: (string | number)[][],
): void {
  const lines = [headers, ...rows].map((row) => row.map(escapeCsvField).join(","));
  const csv = lines.join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/** Audit an export on the server before creating any browser download. */
export async function downloadAuditedCsv(
  request: CsvExportRequest,
  audit: AuditExport,
  dependencies: CsvDownloadDependencies = {
    download: downloadCsv,
    notify: (message) => window.alert(message),
  },
): Promise<boolean> {
  const { headers, rows, ...metadata } = request;
  try {
    const acknowledgement = await audit(metadata);
    if (acknowledgement.status !== "recorded") {
      dependencies.notify(exportFailureMessage);
      return false;
    }
    dependencies.download(request.filename, headers, rows);
    return true;
  } catch {
    dependencies.notify(exportFailureMessage);
    return false;
  }
}
