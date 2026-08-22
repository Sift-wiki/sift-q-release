import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const stage = readFileSync(
  new URL("../.github/workflows/stage-npm-latest.yml", import.meta.url),
  "utf8",
);
const approval = readFileSync(
  new URL(
    "../.github/workflows/verify-npm-stage-approval.yml",
    import.meta.url,
  ),
  "utf8",
);
const uncommented = (value) =>
  value
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
const stageCfg = uncommented(stage);
const approvalCfg = uncommented(approval);
const jobs = stageCfg.slice(stageCfg.indexOf("\njobs:"));
const selectJob = jobs.slice(
  jobs.indexOf("\n  select:"),
  jobs.indexOf("\n  authorize:"),
);
const authorizeJob = jobs.slice(
  jobs.indexOf("\n  authorize:"),
  jobs.indexOf("\n  stage:"),
);
const stageJob = jobs.slice(jobs.indexOf("\n  stage:"));
const approvalJob = approvalCfg.slice(approvalCfg.indexOf("\n  verify:"));
const docs = readFileSync(
  new URL("../docs/npm-staged-release.md", import.meta.url),
  "utf8",
);
const verifier = readFileSync(
  new URL("../scripts/stage-npm-latest.mjs", import.meta.url),
  "utf8",
);

test("both release workflows are manual-only and share one non-cancelling write lock", () => {
  for (const cfg of [stageCfg, approvalCfg]) {
    const trigger = cfg.slice(
      cfg.indexOf("\non:"),
      cfg.indexOf("\npermissions:"),
    );
    assert.match(trigger, /workflow_dispatch:/);
    assert.doesNotMatch(
      trigger,
      /\n\s{2}(push|pull_request|schedule|workflow_run|repository_dispatch):/,
    );
    assert.match(cfg, /group: npm-publish\n\s+cancel-in-progress: false/);
    assert.match(cfg, /\npermissions: \{\}\n/);
  }
});

test("stage input pins candidate, version, receipt, and signed authorization", () => {
  for (const input of [
    "candidate_run_id",
    "candidate_receipt_digest",
    "expected_version",
    "signed_authorization_base64",
  ]) {
    assert.match(stageCfg, new RegExp(`${input}:[\\s\\S]*?required: true`));
  }
});

test("OIDC exists only in the stage job and no long-lived npm token exists", () => {
  assert.equal((stageCfg.match(/id-token: write/g) ?? []).length, 1);
  assert.doesNotMatch(selectJob, /id-token/);
  assert.doesNotMatch(authorizeJob, /id-token/);
  assert.match(
    stageJob,
    /permissions:\n\s+actions: read\n\s+contents: read\n\s+id-token: write/,
  );
  assert.doesNotMatch(
    stageCfg,
    /NODE_AUTH_TOKEN|NPM_TOKEN|_authToken|registry-url/,
  );
  assert.match(stageJob, /NPM_CONFIG_PROVENANCE: ["']false["']/);
  assert.doesNotMatch(
    approvalCfg,
    /id-token|NODE_AUTH_TOKEN|NPM_TOKEN|_authToken|registry-url/,
  );
});

test("every public inter-job artifact containing unpublished bytes is ciphertext-only", () => {
  assert.match(selectJob, /seal-stage-transfer\.mjs seal/);
  assert.match(
    selectJob,
    /path: \$\{\{ steps\.candidate\.outputs\.ciphertext \}\}/,
  );
  assert.match(selectJob, /stage-candidate\.envelope\.json/);
  assert.doesNotMatch(selectJob, /path: .*handoff/);
  assert.match(authorizeJob, /NPM_STAGE_TRANSFER_PRIVATE_KEY_PEM/);
  assert.match(authorizeJob, /stage-candidate\.envelope\.json/);
  assert.match(authorizeJob, /seal-stage-transfer\.mjs seal/);
  assert.match(
    authorizeJob,
    /path: \$\{\{ steps\.freeze\.outputs\.command_ciphertext \}\}/,
  );
  assert.match(authorizeJob, /stage-command\.envelope\.json/);
  assert.doesNotMatch(authorizeJob, /path: .*command_directory/);
  assert.match(stageJob, /NPM_STAGE_TRANSFER_PRIVATE_KEY_PEM/);
  assert.match(stageJob, /sealed command file set differs/);
});

test("the signed RSA SPKI is verified before both seals and both opens", () => {
  const selectionVerification = selectJob.indexOf("verify-transfer-recipient");
  const selectionSeal = selectJob.indexOf("seal-stage-transfer.mjs seal");
  assert.ok(selectionVerification > 0 && selectionSeal > selectionVerification);

  const firstAuthorizeVerification = authorizeJob.indexOf(
    "verify-transfer-recipient",
  );
  const firstAuthorizeOpen = authorizeJob.indexOf(
    "seal-stage-transfer.mjs open",
  );
  const secondAuthorizeVerification = authorizeJob.lastIndexOf(
    "verify-transfer-recipient",
  );
  const secondAuthorizeSeal = authorizeJob.lastIndexOf(
    "seal-stage-transfer.mjs seal",
  );
  assert.ok(
    firstAuthorizeVerification > 0 &&
      firstAuthorizeOpen > firstAuthorizeVerification &&
      secondAuthorizeVerification > firstAuthorizeOpen &&
      secondAuthorizeSeal > secondAuthorizeVerification,
  );
  assert.match(authorizeJob, /--private-key/);
  assert.match(authorizeJob, /transfer_spki_sha256/);

  const stageFingerprintCheck = stageJob.indexOf(
    "observedFingerprint !== expectedFingerprint",
  );
  const stageOpen = stageJob.indexOf("privateDecrypt({");
  assert.ok(stageFingerprintCheck > 0 && stageOpen > stageFingerprintCheck);
  assert.match(stageJob, /needs\.authorize\.outputs\.transfer_spki_sha256/);
});

test("selection verifies exact private candidate without executing it", () => {
  assert.match(selectJob, /environment: candidate-selection/);
  assert.match(selectJob, /CANDIDATE_SELECTION_LANE/);
  assert.match(selectJob, /verify-legacy-publisher/);
  assert.match(selectJob, /verify-exact-candidate\.mjs select-run/);
  assert.match(selectJob, /verify-exact-candidate\.mjs verify-candidate/);
  assert.match(selectJob, /unzip -Z1/);
  assert.match(selectJob, /signed-development-candidate\.json/);
  assert.match(selectJob, /signed-npm-runtime-canary\.json/);
  assert.doesNotMatch(
    selectJob,
    /npm (?:install|ci|publish|stage)\b|pnpm|sift-q --/,
  );
});

test("authorization freezes signed authority and exact command bytes before OIDC", () => {
  assert.match(authorizeJob, /environment: production/);
  assert.match(authorizeJob, /NPM_STAGING_LANE/);
  assert.match(authorizeJob, /NPM_OWNER_TRUST_POLICY_JSON/);
  assert.match(authorizeJob, /stage-npm-latest\.mjs prepare/);
  assert.match(authorizeJob, /create-command-manifest/);
  assert.match(
    authorizeJob,
    /cp release\/scripts\/verify-exact-candidate\.mjs/,
  );
  assert.match(
    authorizeJob,
    /cp release\/scripts\/verify-registry-transition\.mjs/,
  );
  assert.match(authorizeJob, /npm-stage-authorization-\$AUTHORIZATION_ID/);
  assert.match(authorizeJob, /actions\/artifacts\?per_page=100/);
  assert.match(authorizeJob, /stage authorization was already consumed/);
  assert.doesNotMatch(authorizeJob, /npm (?:publish|stage|dist-tag)\b/);
});

test("OIDC job has no checkout or private authority and stages exactly once to latest", () => {
  assert.match(stageJob, /environment: production/);
  assert.doesNotMatch(
    stageJob,
    /actions\/checkout|SIFT_Q_READ_TOKEN|DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON|sift-q-refactor/,
  );
  assert.match(stageJob, /verify-command-manifest/);
  assert.match(stageJob, /check-authority/);
  assert.match(stageJob, /git\/ref\/heads\/main/);
  assert.equal((stageJob.match(/npm stage publish/g) ?? []).length, 1);
  assert.match(
    stageJob,
    /npm stage publish "\$COMMAND\/npm-package\.tgz" --tag latest --ignore-scripts --access public --json/,
  );
  assert.doesNotMatch(
    stageJob,
    /^\s*(?:npm publish|npm dist-tag|npm stage (?:approve|list|view|download))\b/m,
  );
  assert.match(stageJob, /record-stage/);
  assert.match(stageJob, /npm stage approve \$STAGE_ID/);
});

test("staging records and uploads its receipt before registry postconditions", () => {
  const publishAt = stageJob.indexOf(
    'npm stage publish "$COMMAND/npm-package.tgz"',
  );
  const recordAt = stageJob.indexOf("record-stage");
  const uploadAt = stageJob.indexOf("uses: actions/upload-artifact", recordAt);
  const latestAfterAt = stageJob.indexOf(
    'LATEST_AFTER=$(npm view "$PACKAGE" dist-tags.latest)',
  );
  assert.ok(
    publishAt > 0 &&
      recordAt > publishAt &&
      uploadAt > recordAt &&
      latestAfterAt > uploadAt,
  );
  assert.match(stageJob, /staged version became public before approval/);
});

test("approval verification is owner-only, read-only, and exact-current-main", () => {
  assert.match(approvalJob, /environment: production/);
  assert.match(approvalJob, /github\.ref == 'refs\/heads\/main'/);
  assert.match(approvalJob, /Unobtainiumrock.*goodnight000/);
  assert.match(approvalJob, /NPM_APPROVAL_VERIFICATION_LANE/);
  assert.match(
    approvalJob,
    /run\.head_branch === "main" && run\.head_sha === expectedSha/,
  );
  assert.match(approvalJob, /run\.conclusion === "success"/);
  assert.match(approvalJob, /expected exactly one stage result artifact/);
  assert.doesNotMatch(
    approvalJob,
    /npm (?:publish|dist-tag)|npm stage (?:publish|approve|list|view|download)/,
  );
});

test("approval verifier checks signed receipt, canonical registry bytes, and writes separate result", () => {
  assert.match(approvalJob, /NPM_OWNER_TRUST_POLICY_JSON/);
  assert.match(approvalJob, /stage-npm-latest\.mjs verify-approval/);
  assert.match(approvalJob, /hostname !== "registry\.npmjs\.org"/);
  assert.match(approvalJob, /--max-redirs 0/);
  assert.match(approvalJob, /npm-approval-result\.json/);
  assert.match(approvalJob, /npm-stage-approval-\$APPROVAL_ID/);
  assert.match(approvalJob, /signed approval attestation was already consumed/);
  assert.match(approvalJob, /owner attestation: \$APPROVED_BY/);
  assert.match(
    approvalJob,
    /npm remains authoritative for the actual approver identity/,
  );
  assert.match(approvalJob, /approved stage verified/);
});

test("documentation and code use exact schemas and a single stage-only trusted publisher", () => {
  for (const schema of [
    "sift-q-npm-stage-binding/v1",
    "sift-q-npm-signed-stage-authorization/v1",
    "sift-q-npm-owner-trust/v1",
    "sift-q-npm-stage-plan/v1",
    "sift-q-npm-stage-result/v1",
    "sift-q-npm-signed-stage-approval/v1",
    "sift-q-npm-approval-result/v1",
    "sift-q-npm-stage-command-manifest/v1",
  ]) {
    assert.match(verifier, new RegExp(schema));
    assert.match(docs, new RegExp(schema));
  }
  assert.match(docs, /sift-q-sealed-stage-transfer\/v1/);
  assert.match(docs, /one npm trusted-publisher relationship/i);
  assert.match(docs, /stage-npm-latest\.yml/);
  assert.match(docs, /production/);
  assert.match(docs, /staged publishing only/i);
  assert.match(docs, /Nicholas and Charles only/i);
  assert.match(docs, /2FA/);
  assert.match(docs, /disallow[\s\S]*npm tokens/i);
  assert.match(docs, /historical.*mutation.*disabled/i);
});

test("all external actions are immutable SHA pinned", () => {
  for (const cfg of [stageCfg, approvalCfg]) {
    const uses = [...cfg.matchAll(/uses: ([^\s@]+)@(\S+)/g)];
    assert.ok(uses.length >= 2);
    for (const [, action, ref] of uses) {
      assert.match(ref, /^[0-9a-f]{40}$/, `${action} is not commit-SHA pinned`);
    }
  }
});
