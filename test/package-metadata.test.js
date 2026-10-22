import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("npm metadata stays search-friendly", () => {
  assert.ok(pkg.description.length <= 120, "description fits npm search results");
  assert.ok(pkg.keywords.length >= 8 && pkg.keywords.length <= 12, "8-12 keywords");
  assert.match(pkg.repository.url, /github\.com\/Krrishkumar125\//);
  assert.ok(pkg.homepage && pkg.bugs);
});

test("pre-commit hook runs the published bin with known scanners", () => {
  const hook = readFileSync(new URL("../.pre-commit-hooks.yaml", import.meta.url), "utf8");
  assert.match(hook, /id: secret-blast-radius/);
  assert.match(hook, /language: node/);
  const entry = hook.match(/entry: (\S+)(.*)/);
  assert.ok(entry && pkg.bin[entry[1]], "entry is a package bin");
  assert.match(entry[2], /--fail-on high/);
});
