import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const headerPath = new URL("../src/components/layout/Header.tsx", import.meta.url);

test("tenant header shows context without redundant Graph test status", async () => {
  const source = await readFile(headerPath, "utf8");
  assert.match(source, /\{activeTenant\.name\}/);
  assert.doesNotMatch(source, /Graph OK|tested \$\{activeTenant/);
});
