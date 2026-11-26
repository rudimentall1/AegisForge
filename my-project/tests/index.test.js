import test from "node:test";
import assert from "node:assert/strict";

import { projectMetadata } from "../src/index.js";

test("exports the expected scaffold metadata", () => {
  assert.deepEqual(projectMetadata, {
    name: "@aegisforge/my-project",
    scaffoldVersion: "0.1.0",
  });
});
