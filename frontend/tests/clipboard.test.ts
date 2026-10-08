import assert from "node:assert/strict";
import test from "node:test";
import { copyText, type CopyTextDependencies } from "../src/lib/clipboard.ts";

type FakeTextarea = HTMLTextAreaElement & {
  removed: boolean;
  selected: boolean;
};

function fallbackHarness(copyAccepted = true) {
  const calls: string[] = [];
  const textarea = {
    value: "",
    style: {},
    removed: false,
    selected: false,
    setAttribute: () => undefined,
    focus: () => calls.push("textarea.focus"),
    select() {
      this.selected = true;
      calls.push("select");
    },
    setSelectionRange: (start: number, end: number) => calls.push(`range:${start}:${end}`),
    remove() {
      this.removed = true;
      calls.push("remove");
    },
  } as unknown as FakeTextarea;
  const dependencies: CopyTextDependencies = {
    clipboard: null,
    document: {
      activeElement: { focus: () => calls.push("restore.focus") } as unknown as Element,
      body: { appendChild: () => calls.push("append") } as unknown as HTMLElement,
      createElement: () => textarea,
      execCommand: (command: string) => {
        calls.push(command);
        return copyAccepted;
      },
    },
  };
  return { calls, dependencies, textarea };
}

test("uses the modern clipboard API when it succeeds", async () => {
  let copied = "";
  await copyText("one-time-password", {
    clipboard: { writeText: async (value) => { copied = value; } },
    document: null,
  });
  assert.equal(copied, "one-time-password");
});

test("falls back to a temporary textarea when the clipboard API is unavailable", async () => {
  const harness = fallbackHarness();
  await copyText("Rtm-copy-me", harness.dependencies);
  assert.equal(harness.textarea.value, "Rtm-copy-me");
  assert.equal(harness.textarea.selected, true);
  assert.equal(harness.textarea.removed, true);
  assert.deepEqual(harness.calls, ["append", "textarea.focus", "select", "range:0:11", "copy", "remove", "restore.focus"]);
});

test("falls back when the modern clipboard API rejects the write", async () => {
  const harness = fallbackHarness();
  harness.dependencies.clipboard = { writeText: async () => { throw new Error("insecure context"); } };
  await copyText("fallback", harness.dependencies);
  assert.ok(harness.calls.includes("copy"));
});

test("reports failure and removes the temporary value when copying is rejected", async () => {
  const harness = fallbackHarness(false);
  await assert.rejects(copyText("sensitive-value", harness.dependencies), /rejected/i);
  assert.equal(harness.textarea.removed, true);
  assert.equal(harness.textarea.value, "sensitive-value");
});
