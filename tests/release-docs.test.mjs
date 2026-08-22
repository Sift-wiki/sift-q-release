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
    /retains the signed receipt, transition evidence,[\s\S]*public trust policy[\s\S]*run and artifact[\s\S]*verification result for 90 days/,
  );
  assert.match(
    readme,
    /deletable and expiring; they are not an immutable archive/,
  );
  assert.match(
    readme,
    /copy the whole bundle into the owner-controlled release archive/,
  );
  for (const file of [
    "npm-latest-promotion-trust-policy.json",
    "npm-latest-verification-provenance.json",
    "transition-run-metadata.json",
    "transition-artifacts-metadata.json",
    "transition-artifact-selection.json",
    "npm-registry-package.tgz",
  ]) {
    assert.match(readme, new RegExp(file.replaceAll(".", "\\.")));
  }
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

test("activation handover records the live blockers and owner-only recovery order", () => {
  assert.match(readme, /Activation preconditions and owner-only sequence/);
  assert.match(
    readme,
    /Nicholas: GitHub `Unobtainiumrock`; npm `unobtainiumrock`/,
  );
  assert.match(
    readme,
    /Charles: GitHub `orange-juice-1024`; npm `jxiao1024`/,
  );
  assert.match(
    readme,
    /unobtainiumrock_three`, `goodnight00`,\s+`unobtainiumrock`, and `jxiao1024`/,
  );
  assert.match(readme, /no `candidate-selection` environment/);
  assert.match(readme, /`production` contained `SIFT_Q_READ_TOKEN`/);
  assert.match(
    readme,
    /no successful `deploy-development-exact-candidate` run among the\s+most recent 100 workflow runs/,
  );
  assert.match(
    readme,
    /workflow ID\s+`339350411`/,
  );
  assert.match(readme, /must reconcile the live maintainer\s+set to exactly `unobtainiumrock` and `jxiao1024`/);
  assert.match(readme, /must remove `SIFT_Q_READ_TOKEN` from `production`/);
  assert.match(readme, /A skipped run, a personal-account candidate, or a candidate\s+from another workflow cannot substitute/);
  assert.match(readme, /It does not run `npm owner`/);
});
