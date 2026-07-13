/**
 * test_no_math_random.js
 *
 * Node.js built-in test runner check: verifies that none of the
 * dashboard JS source files use Math.random().
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DASHBOARD_DIR = join(__dirname, "..", "..", "src", "dashboard");

function collectJsFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectJsFiles(full));
    } else if (entry.name.endsWith(".js")) {
      results.push(full);
    }
  }
  return results;
}

const jsFiles = collectJsFiles(DASHBOARD_DIR);

assert.ok(jsFiles.length > 0, "No JS files found in dashboard directory");

for (const filePath of jsFiles) {
  test(`No Math.random() in ${filePath.replace(DASHBOARD_DIR, "dashboard")}`, () => {
    const content = readFileSync(filePath, "utf8");
    assert.ok(
      !content.includes("Math.random"),
      `${filePath} uses Math.random() — use crypto.getRandomValues() instead`
    );
  });
}
