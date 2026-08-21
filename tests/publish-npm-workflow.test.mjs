// Invariants of .github/workflows/publish-npm.yml. The workflow is the trust
// root of the npm lane; a change that breaks one of these is either a bug or a
// security regression, and must be made deliberately, here, in the same PR.
// Zero dependencies: `node --test 'tests/**/*.test.mjs'` runs it in relay CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const wf = readFileSync(new URL('../.github/workflows/publish-npm.yml', import.meta.url), 'utf8');
// Comments are documentation, not configuration; test the configuration.
const cfg = wf
  .split('\n')
  .filter((l) => !/^\s*#/.test(l))
  .join('\n');
const jobs = cfg.slice(cfg.indexOf('\njobs:'));
const buildJob = jobs.slice(jobs.indexOf('\n  build:'), jobs.indexOf('\n  publish:'));
const publishJob = jobs.slice(jobs.indexOf('\n  publish:'));

test('dispatch-only trigger; nothing runs on push, PR, or schedule', () => {
  const on = cfg.slice(cfg.indexOf('\non:'), cfg.indexOf('\npermissions:'));
  assert.match(on, /workflow_dispatch:/);
  assert.doesNotMatch(on, /\n\s{2}(push|pull_request|schedule|workflow_run|repository_dispatch):/);
});

test('workflow-level permissions are empty', () => {
  assert.match(cfg, /\npermissions: \{\}\n/);
});

test('one publish at a time, never cancelled mid-write', () => {
  assert.match(cfg, /\nconcurrency:\n\s+group: npm-publish\n\s+cancel-in-progress: false\n/);
});

test('two jobs: build has no id-token; publish is the only job with id-token: write', () => {
  assert.doesNotMatch(buildJob, /id-token/);
  assert.match(buildJob, /permissions:\n\s+contents: read\n/);
  assert.match(publishJob, /permissions:\n\s+contents: read\n\s+id-token: write\n/);
  assert.equal((cfg.match(/id-token: write/g) || []).length, 1);
});

test('both jobs run on GitHub-hosted ubuntu-latest in the production environment', () => {
  for (const job of [buildJob, publishJob]) {
    assert.match(job, /runs-on: ubuntu-latest\n/);
    assert.match(job, /environment: production\n/);
    assert.doesNotMatch(job, /blacksmith|self-hosted/);
  }
});

test('build refuses off main, and publish needs build and is skipped on dry runs', () => {
  assert.match(buildJob, /if: github\.ref == 'refs\/heads\/main'\n/);
  assert.match(publishJob, /needs: build\n/);
  assert.match(publishJob, /if: \$\{\{ !inputs\.dry_run \}\}\n/);
});

test('the lane kill switch is the first build step and checks the exact value', () => {
  const firstStep = buildJob.slice(buildJob.indexOf('    steps:')).split('\n      - ')[1];
  assert.match(firstStep, /NPM_PUBLISHER_LANE: \$\{\{ vars\.NPM_PUBLISHER_LANE \}\}/);
  assert.match(firstStep, /!= "github-actions-oidc" \]; then[\s\S]*exit 1/);
  assert.ok(firstStep.indexOf('actions/checkout') === -1, 'kill switch runs before checkout');
});

test('every action is pinned to a 40-hex commit SHA', () => {
  const uses = [...cfg.matchAll(/uses: ([^\s@]+)@(\S+)/g)];
  assert.ok(uses.length >= 6, `expected several uses:, got ${uses.length}`);
  for (const [, action, ref] of uses) {
    assert.match(ref, /^[0-9a-f]{40}$/, `${action} is pinned to '${ref}', not a commit SHA`);
  }
});

test('npm is pinned to an exact version and asserted after install', () => {
  assert.match(cfg, /NPM_VERSION: 11\.\d+\.\d+\n/);
  assert.match(cfg, /npm install -g "npm@\$NPM_VERSION"/);
  assert.match(cfg, /test "\$\(npm --version\)" = "\$NPM_VERSION"/);
  assert.doesNotMatch(cfg, /npm@latest|npm@\^/);
});

test('source checkout: private repo, read token, main only, full history of that one branch', () => {
  const checkouts = [...cfg.matchAll(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n([\s\S]*?)(?=\n      - )/g)];
  assert.equal(checkouts.length, 2);
  for (const [, withBlock] of checkouts) {
    assert.match(withBlock, /repository: Sift-wiki\/sift-q-refactor/);
    assert.match(withBlock, /token: \$\{\{ secrets\.SIFT_Q_READ_TOKEN \}\}/);
    assert.match(withBlock, /ref: main/);
    assert.match(withBlock, /fetch-depth: 0/);
    assert.match(withBlock, /single-branch: true/);
  }
});

test('no npm credential, no registry-url, no corepack, provenance explicitly off', () => {
  assert.doesNotMatch(cfg, /NODE_AUTH_TOKEN|NPM_TOKEN|_authToken|registry-url|corepack/);
  assert.match(publishJob, /NPM_CONFIG_PROVENANCE: 'false'/);
  assert.doesNotMatch(cfg, /--provenance(?!=false)/);
});

test('publish job publishes the sha256-verified tarball with --ignore-scripts', () => {
  assert.match(publishJob, /test "\$ACTUAL" = "\$EXPECTED_SHA256"/);
  assert.match(publishJob, /npm publish "\$PUBLISH_TARBALL" --ignore-scripts --access public --loglevel verbose/);
  assert.match(buildJob, /tarball_sha256=\$SHA256/);
});

test('the full guard runs in the build job; the publish job re-runs it last before the write', () => {
  assert.match(buildJob, /node build\.mjs\n\s+node prepublish-guard\.mjs/);
  const guardAt = publishJob.indexOf('node "$RUNNER_TEMP/run-guard.mjs"');
  const publishAt = publishJob.indexOf('npm publish "$PUBLISH_TARBALL"');
  assert.ok(guardAt > 0 && publishAt > guardAt, 'guard precedes the publish');
  const between = publishJob.slice(guardAt, publishAt);
  assert.equal((between.match(/\n      - name:/g) || []).length, 1, 'exactly one step (the publish) follows the guard');
});

// R1 (security re-verify 2026-08-20): zero third-party code executes in the
// job that holds id-token: write. The publish job may run only the runner
// image's own toolchain, the exact pinned npm, and the guard from the fresh
// private checkout, against the sha256-pinned tarball the build job proved.
test('R1: no pnpm, no setup-node, no cache, no build in the publish job', () => {
  assert.doesNotMatch(publishJob, /pnpm/);
  assert.doesNotMatch(publishJob, /action-setup|setup-node/);
  assert.doesNotMatch(publishJob, /\bcache(?:-dependency-path)?:/);
  assert.doesNotMatch(publishJob, /build\.mjs/);
});

test('R1: the only dependency the publish job installs is the pinned npm itself', () => {
  const installs = [...publishJob.matchAll(/\b(?:npm|pnpm|yarn|corepack) (?:ci|install|add)\b[^\n]*/g)].map((m) => m[0]);
  assert.deepEqual(installs, ['npm install -g "npm@$NPM_VERSION"']);
});

test('R1: the only actions in the publish job are SHA-pinned checkout and download-artifact', () => {
  const uses = [...publishJob.matchAll(/uses: (\S+)/g)].map((m) => m[1]);
  assert.deepEqual(
    uses.map((u) => u.split('@')[0]),
    ['actions/checkout', 'actions/download-artifact'],
  );
  for (const u of uses) {
    assert.match(u.split('@')[1] ?? '', /^[0-9a-f]{40}$/, `${u} is not SHA-pinned`);
  }
});

test('R1: the publish job re-runs every guard check except the build-job-only freshness check', () => {
  // Pin the CALL SITES, not just the imported names: a runner script that
  // imports a check but never invokes it must fail here.
  assert.match(publishJob, /const sha = verifyExactMain\(runGit\);/);
  assert.match(publishJob, /verifyGreenCi\(sha, runGh\)/);
  assert.match(publishJob, /verifyGreenReleaseGates\(sha, runGh\);/);
  assert.match(publishJob, /instanceof PublishGuardError/);
  assert.doesNotMatch(publishJob, /runPublishGuard|verifyFreshBundle/);
  // The runner script goes to RUNNER_TEMP, never into the checkout, so the
  // guard's clean-tree check still passes.
  assert.match(publishJob, /cat >"\$RUNNER_TEMP\/run-guard\.mjs"/);
});

test('publish refuses if main moved since build', () => {
  assert.match(publishJob, /BUILD_SHA: \$\{\{ needs\.build\.outputs\.source_sha \}\}/);
  assert.match(publishJob, /test "\$HEAD" = "\$BUILD_SHA" && test "\$MAIN" = "\$BUILD_SHA"/);
});
