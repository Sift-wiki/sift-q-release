import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL(
    "../.github/workflows/verify-npm-latest-promotion.yml",
    import.meta.url,
  ),
  "utf8",
);
const cfg = workflow
  .split("\n")
  .filter((line) => !/^\s*#/.test(line))
  .join("\n");
const verifyJob = cfg.slice(cfg.indexOf("\n  verify:"));

test("latest verification is manual, serialized, main-only, and read-only", () => {
  const trigger = cfg.slice(
    cfg.indexOf("\non:"),
    cfg.indexOf("\npermissions:"),
  );
  assert.match(trigger, /workflow_dispatch:/);
  assert.doesNotMatch(
    trigger,
    /\n\s{2}(push|pull_request|schedule|workflow_run|repository_dispatch):/,
  );
  assert.match(cfg, /\npermissions: \{\}\n/);
  assert.match(cfg, /group: npm-publish\n\s+cancel-in-progress: false/);
  assert.match(verifyJob, /github\.ref == 'refs\/heads\/main'/);
  assert.match(verifyJob, /environment: production/);
  assert.match(verifyJob, /permissions:\n\s+actions: read\n\s+contents: read/);
  assert.doesNotMatch(
    verifyJob,
    /id-token: write|npm publish|npm dist-tag|npm stage|NODE_AUTH_TOKEN|NPM_TOKEN/,
  );
});

test("only Nicholas and Charles can dispatch runtime verification", () => {
  assert.match(verifyJob, /Unobtainiumrock\|orange-juice-1024/);
  assert.match(verifyJob, /GITHUB_TRIGGERING_ACTOR/);
  assert.match(verifyJob, /is not a production\/npm owner/);
  assert.doesNotMatch(verifyJob, /goodnight000\)/);
});

test("the environment kill switch is first and precedes checkout or secrets", () => {
  const firstStep = verifyJob
    .slice(verifyJob.indexOf("    steps:"))
    .split("\n      - ")[1];
  assert.match(firstStep, /NPM_LATEST_PROMOTION_VERIFIER_LANE/);
  assert.match(firstStep, /signed-next-to-latest-v1/);
  assert.match(firstStep, /Unobtainiumrock\|orange-juice-1024/);
  assert.match(firstStep, /GITHUB_TRIGGERING_ACTOR/);
  assert.doesNotMatch(firstStep, /actions\/checkout|secrets\./);
});

test("transition selection binds the exact current release main and exact artifact", () => {
  assert.match(verifyJob, /run\.name === "publish-npm"/);
  assert.match(
    verifyJob,
    /run\.path === "\.github\/workflows\/publish-npm\.yml"/,
  );
  assert.match(
    verifyJob,
    /run\.head_branch === "main" && run\.head_sha === expectedSha/,
  );
  assert.match(
    verifyJob,
    /run\.repository\?\.full_name === expectedRepository/,
  );
  assert.match(verifyJob, /matches\.length === 1/);
  assert.match(verifyJob, /npm-next-transition\.json/);
  assert.match(verifyJob, /npm-latest-promotion-binding\.json/);
  assert.match(verifyJob, /transition evidence digest differs/);
});

test("signed authorization, tag state, registry bytes, and replay marker are all verified", () => {
  assert.match(verifyJob, /NPM_LATEST_PROMOTION_TRUST_POLICY_JSON/);
  assert.match(verifyJob, /verify-promotion-result/);
  assert.match(verifyJob, /--triggering-actor "\$GITHUB_TRIGGERING_ACTOR"/);
  assert.match(verifyJob, /dist-tags\.next/);
  assert.match(verifyJob, /dist-tags\.latest/);
  assert.match(verifyJob, /npm view "\$PACKAGE" maintainers --json/);
  assert.match(verifyJob, /npm-provider-state\.mjs maintainers/);
  assert.match(verifyJob, /registry-package\.tgz/);
  assert.match(
    verifyJob,
    /signed promotion authorization was already consumed/,
  );
  assert.match(verifyJob, /npm-latest-verification-\$AUTHORIZATION_ID/);
  assert.match(verifyJob, /signed-npm-latest-promotion\.json/);
  assert.match(
    verifyJob,
    /cp "\$BOUNDARY\/transition\/npm-next-transition\.json"[\s\S]*?latest-verification\/npm-next-transition\.json/,
  );
  assert.match(
    verifyJob,
    /cp "\$BOUNDARY\/transition\/npm-latest-promotion-binding\.json"[\s\S]*?latest-verification\/npm-latest-promotion-binding\.json/,
  );
  assert.match(verifyJob, /retention-days: 90/);
});

test("no production server identity is coupled into npm promotion", () => {
  assert.doesNotMatch(
    cfg,
    /q\.sift\.wiki|dev\.q\.sift\.wiki|backendArtifact|releaseIdentity|server.{0,20}sha/i,
  );
});

test("the superseded stage-direct-latest lane is absent", () => {
  for (const relative of [
    "../.github/workflows/stage-npm-latest.yml",
    "../.github/workflows/verify-npm-stage-approval.yml",
    "../scripts/stage-npm-latest.mjs",
  ]) {
    assert.equal(existsSync(new URL(relative, import.meta.url)), false);
  }
});
