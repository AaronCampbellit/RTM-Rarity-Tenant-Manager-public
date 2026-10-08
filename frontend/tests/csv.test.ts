import assert from "node:assert/strict";
import test from "node:test";
import {
  downloadAuditedCsv,
  type CsvDownloadDependencies,
  type CsvExportRequest,
  type ExportGenerateRequest,
} from "../src/lib/csv.ts";

const request: CsvExportRequest = {
  kind: "users",
  filename: "users.csv",
  rowCount: 2,
  tenantId: "ten_1",
  headers: ["Name"],
  rows: [["Ada"], ["Grace"]],
};

test("audits metadata before starting the CSV download", async () => {
  const events: string[] = [];
  let sent: ExportGenerateRequest | undefined;
  const dependencies: CsvDownloadDependencies = {
    download: (filename, headers, rows) => {
      events.push("download");
      assert.equal(filename, "users.csv");
      assert.deepEqual(headers, ["Name"]);
      assert.deepEqual(rows, [["Ada"], ["Grace"]]);
    },
    notify: () => events.push("notify"),
  };

  const ok = await downloadAuditedCsv(
    request,
    async (metadata) => {
      events.push("audit");
      sent = metadata;
      return { status: "recorded" };
    },
    dependencies,
  );

  assert.equal(ok, true);
  assert.deepEqual(events, ["audit", "download"]);
  assert.deepEqual(sent, {
    kind: "users",
    filename: "users.csv",
    rowCount: 2,
    tenantId: "ten_1",
  });
});

test("blocks the CSV download when audit acknowledgement fails", async () => {
  const events: string[] = [];
  const dependencies: CsvDownloadDependencies = {
    download: () => events.push("download"),
    notify: (message) => {
      events.push("notify");
      assert.match(message, /could not be audited/i);
    },
  };

  const ok = await downloadAuditedCsv(
    request,
    async () => {
      throw new Error("offline");
    },
    dependencies,
  );

  assert.equal(ok, false);
  assert.deepEqual(events, ["notify"]);
});

test("blocks the CSV download when the server does not acknowledge the audit", async () => {
  const events: string[] = [];
  const ok = await downloadAuditedCsv(
    request,
    async () => ({ status: "unexpected" as "recorded" }),
    {
      download: () => events.push("download"),
      notify: () => events.push("notify"),
    },
  );

  assert.equal(ok, false);
  assert.deepEqual(events, ["notify"]);
});
