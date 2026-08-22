import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const wf = readFileSync(
  new URL("../.github/workflows/publish-npm.yml", import.meta.url),
  "utf8",
);
const cfg = wf
  .split("\n")
  .filter((line) => !/^\s*#/.test(line))
  .join("\n");
const jobs = cfg.slice(cfg.indexOf("\njobs:"));
const selectJob = jobs.slice(
  jobs.indexOf("\n  select:"),
  jobs.indexOf("\n  publish:"),
);
const publishJob = jobs.slice(
  jobs.indexOf("\n  publish:"),
  jobs.indexOf("\n  verify-registry:"),
);
const verifyRegistryJob = jobs.slice(
  jobs.indexOf("\n  verify-registry:"),
  jobs.indexOf("\n  lint-run-logs:"),
);
const lintJob = jobs.slice(jobs.indexOf("\n  lint-run-logs:"));

test("dispatch-only trigger requires exact candidate run and receipt identity", () => {
  const on = cfg.slice(cfg.indexOf("\non:"), cfg.indexOf("\npermissions:"));
  assert.match(on, /workflow_dispatch:/);
  assert.doesNotMatch(
    on,
    /\n\s{2}(push|pull_request|schedule|workflow_run|repository_dispatch):/,
  );
  assert.match(on, /candidate_run_id:[\s\S]*?required: true/);
  assert.match(on, /candidate_receipt_digest:[\s\S]*?required: true/);
});

test("workflow permissions are empty and concurrency never cancels a possible write", () => {
  assert.match(cfg, /\npermissions: \{\}\n/);
  assert.match(cfg, /group: npm-publish\n\s+cancel-in-progress: false/);
});

test("select, registry verification, and lint cannot mint OIDC; publish is the only id-token job", () => {
  assert.deepEqual(
    [...jobs.matchAll(/\n  ([a-z-]+):\n/g)].map((match) => match[1]),
    ["select", "publish", "verify-registry", "lint-run-logs"],
  );
  assert.doesNotMatch(selectJob, /id-token/);
  assert.doesNotMatch(verifyRegistryJob, /id-token|secrets\.|environment:/);
  assert.doesNotMatch(lintJob, /id-token|secrets\./);
  assert.match(
    publishJob,
    /permissions:\n\s+contents: read\n\s+id-token: write/,
  );
  assert.equal((cfg.match(/id-token: write/g) ?? []).length, 1);
});

test("all jobs are GitHub-hosted; selection and publishing use separate protected environments", () => {
  for (const job of [selectJob, publishJob, verifyRegistryJob, lintJob]) {
    assert.match(job, /runs-on: ubuntu-latest/);
    assert.doesNotMatch(job, /blacksmith|self-hosted/);
  }
  assert.match(selectJob, /environment: candidate-selection/);
  assert.match(publishJob, /environment: production/);
  assert.doesNotMatch(lintJob, /environment:/);
  assert.match(selectJob, /github\.ref == 'refs\/heads\/main'/);
  assert.match(selectJob, /Unobtainiumrock\|orange-juice-1024/);
  assert.match(selectJob, /GITHUB_TRIGGERING_ACTOR/);
  assert.match(selectJob, /is not a production\/npm owner/);
  assert.doesNotMatch(selectJob, /goodnight000\)/);
  assert.match(publishJob, /needs: select/);
  assert.match(publishJob, /if: \$\{\{ !inputs\.dry_run \}\}/);
});

test("the environment kill switch is the first select step", () => {
  const firstStep = selectJob
    .slice(selectJob.indexOf("    steps:"))
    .split("\n      - ")[1];
  assert.match(
    firstStep,
    /CANDIDATE_SELECTION_LANE: \$\{\{ vars\.CANDIDATE_SELECTION_LANE \}\}/,
  );
  assert.match(firstStep, /Unobtainiumrock\|orange-juice-1024/);
  assert.match(firstStep, /GITHUB_TRIGGERING_ACTOR/);
  assert.match(firstStep, /is not a production\/npm owner/);
  assert.match(firstStep, /!= "exact-development-candidate"/);
  assert.doesNotMatch(firstStep, /actions\/checkout|SIFT_Q_READ_TOKEN/);
});

test("the OIDC job has a separate production kill switch and no selection authority", () => {
  const firstStep = publishJob
    .slice(publishJob.indexOf("    steps:"))
    .split("\n      - ")[1];
  assert.match(
    firstStep,
    /NPM_PUBLISHER_LANE: \$\{\{ vars\.NPM_PUBLISHER_LANE \}\}/,
  );
  assert.match(firstStep, /Unobtainiumrock\|orange-juice-1024/);
  assert.match(firstStep, /GITHUB_TRIGGERING_ACTOR/);
  assert.match(firstStep, /is not a production\/npm owner/);
  assert.doesNotMatch(firstStep, /goodnight000\)/);
  assert.match(firstStep, /!= "github-actions-oidc"/);
  assert.doesNotMatch(
    publishJob,
    /candidate-selection|CANDIDATE_SELECTION_LANE|SIFT_Q_READ_TOKEN|DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON/,
  );
});

test("every action is pinned to a 40-hex commit SHA", () => {
  const uses = [...cfg.matchAll(/uses: ([^\s@]+)@(\S+)/g)];
  assert.ok(
    uses.length >= 4,
    `expected at least four uses:, got ${uses.length}`,
  );
  for (const [, action, ref] of uses) {
    assert.match(ref, /^[0-9a-f]{40}$/, `${action} is not commit-SHA pinned`);
  }
});

test("select, publish, and registry verification pin Node 22 with the same SHA-pinned setup action", () => {
  for (const job of [selectJob, publishJob, verifyRegistryJob]) {
    assert.match(job, /uses: actions\/setup-node@[0-9a-f]{40}/);
    assert.match(job, /node-version: 22/);
    assert.doesNotMatch(job, /node-version: (?:latest|current|\*)/);
  }
});

test("repo-only credential exists only in select and persisted checkout credentials are disabled", () => {
  assert.match(selectJob, /GH_TOKEN: \$\{\{ secrets\.SIFT_Q_READ_TOKEN \}\}/);
  assert.match(selectJob, /token: \$\{\{ secrets\.SIFT_Q_READ_TOKEN \}\}/);
  assert.equal((selectJob.match(/SIFT_Q_READ_TOKEN/g) ?? []).length, 3);
  assert.doesNotMatch(publishJob, /SIFT_Q_READ_TOKEN|sift-q-refactor/);
  assert.doesNotMatch(
    publishJob,
    /uses: actions\/checkout|verify-registry-transition|sift-q --/,
  );
  assert.match(
    verifyRegistryJob,
    /path: relay[\s\S]*?persist-credentials: false[\s\S]*?ref: \$\{\{ github\.sha \}\}/,
  );
  assert.doesNotMatch(
    verifyRegistryJob,
    /SIFT_Q_READ_TOKEN|DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON/,
  );
  assert.doesNotMatch(lintJob, /SIFT_Q_READ_TOKEN|sift-q-refactor/);
  assert.equal(
    (selectJob.match(/persist-credentials: false/g) ?? []).length,
    2,
  );
});

test("selection fails closed unless the exact private publisher is disabled", () => {
  const guardAt = selectJob.indexOf(
    "name: require the legacy private publisher to be disabled",
  );
  const candidateFetchAt = selectJob.indexOf(
    'gh api "repos/$SOURCE_REPO/actions/runs/$CANDIDATE_RUN_ID"',
  );
  const guardStep = selectJob.slice(
    guardAt,
    selectJob.indexOf(
      "\n      - name: verify the private run and fetch its one exact artifact",
    ),
  );
  assert.ok(guardAt > 0 && candidateFetchAt > guardAt);
  assert.match(guardStep, /gh api "repos\/\$SOURCE_REPO"/);
  assert.match(guardStep, /actions\/workflows\/publish-npm\.yml/);
  assert.match(
    guardStep,
    /verify-exact-candidate\.mjs verify-legacy-publisher/,
  );
  assert.match(guardStep, /GH_TOKEN: \$\{\{ secrets\.SIFT_Q_READ_TOKEN \}\}/);
  assert.doesNotMatch(guardStep, /\|\| true|continue-on-error/);
});

test("candidate selection pins private run, repository, workflow, lineage, artifact ID and exact file set", () => {
  assert.match(selectJob, /actions\/runs\/\$CANDIDATE_RUN_ID/);
  assert.match(selectJob, /commits\/\$CANDIDATE_SHA/);
  assert.match(selectJob, /git\/ref\/heads\/main/);
  assert.match(selectJob, /compare\/\$CANDIDATE_SHA\.\.\.main/);
  assert.match(selectJob, /verify-exact-candidate\.mjs select-run/);
  assert.match(selectJob, /actions\/artifacts\/\$ARTIFACT_ID\/zip/);
  assert.match(selectJob, /unzip -Z1/);
  for (const name of [
    "npm-package.tgz",
    "signed-development-candidate.json",
    "signed-npm-runtime-canary.json",
  ]) {
    assert.match(selectJob, new RegExp(name.replace(".", "\\.")));
  }
});

test("signed candidate verification is required before tarball upload", () => {
  assert.match(selectJob, /DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON/);
  assert.match(selectJob, /verify-exact-candidate\.mjs verify-candidate/);
  assert.match(selectJob, /--receipt-digest "\$CANDIDATE_RECEIPT_DIGEST"/);
  assert.match(selectJob, /--expected-version "\$EXPECTED_VERSION"/);
  const verifyAt = selectJob.indexOf(
    "verify-exact-candidate.mjs verify-candidate",
  );
  const uploadAt = selectJob.indexOf("uses: actions/upload-artifact");
  assert.ok(
    verifyAt > 0 && uploadAt > verifyAt,
    "verification precedes relay upload",
  );
  assert.match(selectJob, /name: exact-candidate-tarball/);
  assert.match(selectJob, /compression-level: 0/);
});

test("dry runs never upload unpublished candidate bytes", () => {
  const uploadStep = selectJob.slice(
    selectJob.lastIndexOf("\n      - uses: actions/upload-artifact"),
    selectJob.indexOf("\n      - name: candidate summary"),
  );
  assert.match(uploadStep, /if: \$\{\{ !inputs\.dry_run \}\}/);
  assert.equal(
    (selectJob.match(/uses: actions\/upload-artifact/g) ?? []).length,
    1,
  );
});

test("select never installs dependencies, builds, packs, or runs candidate code", () => {
  assert.doesNotMatch(
    selectJob,
    /pnpm (?:install|build|pack)|npm (?:install|ci)\b|build\.mjs|prepack|node_modules\/\.bin/,
  );
  assert.doesNotMatch(selectJob, /action-setup/);
});

test("publish receives only one digest-pinned tarball and publishes those exact bytes", () => {
  const uses = [...publishJob.matchAll(/uses: (\S+)/g)].map(
    (match) => match[1],
  );
  assert.deepEqual(
    uses.map((value) => value.split("@")[0]),
    ["actions/setup-node", "actions/download-artifact"],
  );
  assert.match(publishJob, /name: exact-candidate-tarball/);
  assert.match(publishJob, /test "\$ACTUAL" = "\$EXPECTED_SHA256"/);
  assert.match(
    publishJob,
    /find "\$RUNNER_TEMP\/verified-artifact"[\s\S]*?-eq 1/,
  );
  assert.match(
    publishJob,
    /npm publish "\$PUBLISH_TARBALL" --tag next --ignore-scripts --access public --loglevel verbose/,
  );
});

test("publish installs only exact npm with scripts disabled and carries no long-lived npm token", () => {
  assert.match(cfg, /NPM_VERSION: 11\.19\.0/);
  assert.match(
    publishJob,
    /npm install -g --prefix "\$npm_prefix" --ignore-scripts --no-audit --no-fund "npm@\$NPM_VERSION"/,
  );
  assert.match(publishJob, /npm_prefix="\$RUNNER_TEMP\/npm-pinned"/);
  assert.match(publishJob, /echo "\$npm_prefix\/bin" >> "\$GITHUB_PATH"/);
  assert.match(
    publishJob,
    /test "\$\("\$npm_prefix\/bin\/npm" --version\)" = "\$NPM_VERSION"/,
  );
  assert.equal(
    (publishJob.match(/\$npm_prefix\/bin\/npm\b/g) || []).length,
    1,
    "the pinned absolute npm path is used only for its immediate version check",
  );
  assert.doesNotMatch(
    publishJob,
    /pnpm|yarn|NODE_AUTH_TOKEN|NPM_TOKEN|_authToken|registry-url/,
  );
  assert.match(publishJob, /NPM_CONFIG_PROVENANCE: ["']false["']/);
});

test("candidate execution and transition evidence occur only in the no-authority verifier", () => {
  assert.doesNotMatch(
    publishJob,
    /verify-registry-transition|registry-byte install|sift-q --version|--dry-run --json/,
  );
  assert.match(verifyRegistryJob, /permissions:\n\s+contents: read/);
  assert.doesNotMatch(
    verifyRegistryJob,
    /id-token|secrets\.|environment:|NPM_PUBLISHER_LANE|npm publish/,
  );
  assert.match(verifyRegistryJob, /verify-registry-transition\.mjs canary/);
  assert.match(verifyRegistryJob, /verify-registry-transition\.mjs record/);
});

test("registry absence is checked before upload and immediately before publish", () => {
  assert.match(selectJob, /npm view "\$PACKAGE" versions --json/);
  assert.match(
    publishJob,
    /PUBLISHED=\$\(npm view "\$PACKAGE" versions --json\) \|\|/,
  );
  assert.match(
    publishJob,
    /if \(!Array\.isArray\(versions\) \|\| versions\.length === 0\) process\.exit\(2\)/,
  );
  const preflightAt = publishJob.indexOf('npm view "$PACKAGE" versions --json');
  const publishAt = publishJob.indexOf('npm publish "$PUBLISH_TARBALL"');
  assert.ok(preflightAt > 0 && publishAt > preflightAt);
});

test("the OIDC write targets next and cannot move latest", () => {
  assert.equal((publishJob.match(/npm publish /g) ?? []).length, 1);
  assert.match(publishJob, /npm publish "\$PUBLISH_TARBALL" --tag next/);
  assert.doesNotMatch(publishJob, /npm dist-tag (?:add|rm)|--tag latest/);
  assert.match(
    publishJob,
    /LATEST_BEFORE=\$\(npm view "\$PACKAGE" dist-tags\.latest\)/,
  );
  assert.doesNotMatch(publishJob, /LATEST_AFTER=/);
  assert.match(
    verifyRegistryJob,
    /LATEST_AFTER_CANARY=\$\(npm view "\$PACKAGE" dist-tags\.latest\)/,
  );
  assert.match(
    verifyRegistryJob,
    /test "\$LATEST_AFTER_CANARY" = "\$LATEST_BEFORE"/,
  );
});

test("registry-served exact bytes are fetched canonically, canaried, and emitted as strict evidence", () => {
  assert.match(
    verifyRegistryJob,
    /NPM_CONFIG_REGISTRY: https:\/\/registry\.npmjs\.org\//,
  );
  assert.match(verifyRegistryJob, /NPM_CONFIG_USERCONFIG: \/dev\/null/);
  assert.match(verifyRegistryJob, /npm view "\$PACKAGE@\$VERSION" --json/);
  assert.match(
    verifyRegistryJob,
    /npm pack "\$PACKAGE@\$VERSION" --ignore-scripts --json --pack-destination "\$REGISTRY_DIR"/,
  );
  assert.match(verifyRegistryJob, /verify-registry-transition\.mjs canary/);
  assert.match(verifyRegistryJob, /verify-registry-transition\.mjs record/);
  for (const argument of [
    "--selected-tarball",
    "--registry-tarball",
    "--candidate-receipt-digest",
    "--next-tag-version",
    "--output",
    "--promotion-binding-output",
  ]) {
    assert.match(verifyRegistryJob, new RegExp(argument));
  }
  assert.match(
    verifyRegistryJob,
    /name: npm-next-transition-\$\{\{ needs\.select\.outputs\.version \}\}/,
  );
  assert.match(verifyRegistryJob, /npm-next-transition\.json/);
  assert.match(verifyRegistryJob, /npm-latest-promotion-binding\.json/);
  assert.match(
    verifyRegistryJob,
    /transition evidence: \$TRANSITION_DIGEST \(unsigned and non-authoritative\)/,
  );
  assert.match(
    verifyRegistryJob,
    /separately governed lane must verify a trusted signed promotion receipt/,
  );
});

test("registry tags are re-read after the canary before evidence is recorded", () => {
  const canaryAt = verifyRegistryJob.indexOf(
    "verify-registry-transition.mjs canary",
  );
  const nextAt = verifyRegistryJob.indexOf("NEXT_AFTER_CANARY=$(npm view");
  const latestAt = verifyRegistryJob.indexOf("LATEST_AFTER_CANARY=$(npm view");
  const recordAt = verifyRegistryJob.indexOf(
    "verify-registry-transition.mjs record",
  );
  assert.ok(
    canaryAt > 0 &&
      nextAt > canaryAt &&
      latestAt > nextAt &&
      recordAt > latestAt,
  );
  assert.match(verifyRegistryJob, /test "\$NEXT_AFTER_CANARY" = "\$VERSION"/);
  assert.match(
    verifyRegistryJob,
    /test "\$LATEST_AFTER_CANARY" = "\$LATEST_BEFORE"/,
  );
});

test("lint job scans completed job logs and fails closed on ignored action inputs", () => {
  assert.match(lintJob, /needs: \[select, publish, verify-registry\]/);
  assert.match(lintJob, /permissions:\n\s+actions: read/);
  assert.match(lintJob, /actions\/runs\/\$RUN_ID\/jobs/);
  assert.match(lintJob, /actions\/jobs\/\$ID\/logs/);
  assert.match(lintJob, /NEEDLE='Unexpected input''\(s\)'/);
  assert.match(lintJob, /grep -nF "\$NEEDLE"/);
  assert.match(lintJob, /test "\$SCANNED" -ge 1/);
  assert.match(lintJob, /exit "\$FAIL"/);
});
