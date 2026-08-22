import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

test("trusted-publisher setup uses npm's filename-only workflow field", () => {
  assert.match(readme, /workflow filename `publish-npm\.yml`/);
  assert.doesNotMatch(
    readme,
    /restricted to[\s\S]{0,100}`\.github\/workflows\/publish-npm\.yml`/,
  );
});

test("operator docs describe bounded retention and complete owner archival", () => {
  assert.match(
    readme,
    /retains the signed receipt, transition evidence,[\s\S]*promotion binding[\s\S]*verification result for 90 days/,
  );
  assert.match(
    readme,
    /deletable and expiring; they are not an immutable archive/,
  );
  assert.match(
    readme,
    /copy the whole bundle into the owner-controlled release archive/,
  );
});

test("operator docs disclose the provider no-CAS residual and the short final window", () => {
  assert.match(readme, /does not provide compare-and-swap/);
  assert.match(
    readme,
    /cannot make a concurrent direct npm owner honor a repository lock/,
  );
  assert.match(readme, /authorization lifetime is at most 15 minutes/);
  assert.match(readme, /do not merge into release\s+`main`/);
});

test("operator docs provide offline signing and rejected-next reconciliation commands", () => {
  assert.match(readme, /authorize-npm-latest-promotion\.mjs/);
  assert.match(readme, /--private-key \/secure\/offline\/owner-ed25519\.pem/);
  assert.match(readme, /reconcile-rejected-next\.mjs status/);
  assert.match(readme, /RESET-REJECTED-NEXT-TO-LATEST/);
});
