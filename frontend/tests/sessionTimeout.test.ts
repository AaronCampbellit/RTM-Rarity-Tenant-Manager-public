import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_SESSION_TIMEOUT,
  SESSION_TIMEOUT_OPTIONS,
} from "../src/features/admin/sessionTimeout.ts";

test("offers only the approved session timeout choices", () => {
  assert.deepEqual(SESSION_TIMEOUT_OPTIONS, [
    { value: "30", label: "30 minutes" },
    { value: "60", label: "1 hour" },
    { value: "240", label: "4 hours" },
    { value: "480", label: "8 hours" },
    { value: "720", label: "12 hours" },
    { value: "1440", label: "24 hours" },
  ]);
  assert.equal(DEFAULT_SESSION_TIMEOUT, "30");
});
