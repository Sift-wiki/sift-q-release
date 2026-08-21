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
const publishJob = jobs.slice(jobs.indexOf('\n  publish:'), jobs.indexOf('\n  lint-run-logs:'));
const lintJob = jobs.slice(jobs.indexOf('\n  lint-run-logs:'));

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

test('three jobs: build and lint-run-logs have no id-token; publish is the only job with id-token: write', () => {
  assert.deepEqual([...jobs.matchAll(/\n  ([a-z-]+):\n/g)].map((m) => m[1]), ['build', 'publish', 'lint-run-logs']);
  assert.doesNotMatch(buildJob, /id-token/);
  assert.doesNotMatch(lintJob, /id-token|secrets\./);
  assert.match(buildJob, /permissions:\n\s+contents: read\n/);
  assert.match(publishJob, /permissions:\n\s+contents: read\n\s+id-token: write\n/);
  assert.equal((cfg.match(/id-token: write/g) || []).length, 1);
});

test('all jobs run on GitHub-hosted ubuntu-latest; build and publish in the production environment', () => {
  assert.match(lintJob, /runs-on: ubuntu-latest\n/);
  assert.doesNotMatch(lintJob, /blacksmith|self-hosted|environment:/);
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

test('source checkout: private repo, read token, ref main, default depth, then an explicit unshallow of main only', () => {
  const checkouts = [...cfg.matchAll(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n([\s\S]*?)(?=\n      - )/g)];
  assert.equal(checkouts.length, 2);
  for (const [, withBlock] of checkouts) {
    assert.match(withBlock, /repository: Sift-wiki\/sift-q-refactor/);
    assert.match(withBlock, /token: \$\{\{ secrets\.SIFT_Q_READ_TOKEN \}\}/);
    assert.match(withBlock, /ref: main/);
    // `fetch-depth: 0` is "all history for all branches and tags" and printed
    // the private repo's branch list into this public log. The default depth
    // (1) fetches exactly `ref`; history comes from the explicit unshallow
    // step below, not from a checkout input. `single-branch` is not an
    // actions/checkout input at all — the runner logged "Unexpected input(s)"
    // and fetched everything, while an earlier version of this test pinned
    // it. Only keys actions/checkout@v7 actually accepts may appear here.
    assert.doesNotMatch(withBlock, /fetch-depth: 0/);
    assert.doesNotMatch(withBlock, /single-branch/);
    const KNOWN = new Set(['allow-unsafe-pr-checkout', 'repository', 'ref', 'token', 'ssh-key', 'ssh-known-hosts', 'ssh-strict', 'ssh-user',
      'persist-credentials', 'path', 'clean', 'filter', 'sparse-checkout', 'sparse-checkout-cone-mode',
      'fetch-depth', 'fetch-tags', 'show-progress', 'lfs', 'submodules', 'set-safe-directory', 'github-server-url']);
    for (const [, key] of withBlock.matchAll(/\n\s{10}([a-z-]+):/g)) {
      assert.ok(KNOWN.has(key), `'${key}' is not an actions/checkout input; the runner would ignore it`);
    }
  }
  // The unshallow step directly follows each checkout, in both jobs.
  const unshallows = [...cfg.matchAll(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n[\s\S]*?\n      - name: unshallow main only[^\n]*\n[\s\S]*?git fetch --unshallow --no-tags origin main\n/g)];
  assert.equal(unshallows.length, 2);
  for (const job of [buildJob, publishJob]) {
    assert.match(job, /git fetch --unshallow --no-tags origin main/);
    assert.match(job, /rev-parse --is-shallow-repository/);
    assert.match(job, /grep -v '\^refs\/remotes\/origin\/main\$'/);
  }
});

test('lint-run-logs fails the run on "Unexpected input(s)" in any completed job log', () => {
  assert.match(lintJob, /needs: \[build, publish\]\n/);
  assert.match(lintJob, /if: \$\{\{ always\(\)/);
  assert.match(lintJob, /permissions:\n\s+actions: read\n/);
  assert.doesNotMatch(lintJob, /uses:|SIFT_Q_READ_TOKEN|sift-q-refactor/);
  assert.match(lintJob, /actions\/runs\/\$RUN_ID\/jobs/);
  assert.match(lintJob, /actions\/jobs\/\$ID\/logs/);
  assert.match(lintJob, /grep -n 'Unexpected input\(s\)'/);
  assert.match(lintJob, /FAIL=1/);
  assert.match(lintJob, /exit \$FAIL/);
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
  assert.doesNotMatch(publishJob, /runPublishGuard/);
  // The check set is a contract with the private repo; the runner script
  // refuses if the guard exports a verify* check it neither calls nor
  // deliberately skips, so a check added there cannot be silently dropped here.
  assert.match(publishJob, /const CALLED = \["verifyExactMain", "verifyGreenCi", "verifyGreenReleaseGates"\];/);
  assert.match(publishJob, /const SKIPPED = \["verifyFreshBundle"\];/);
  assert.match(publishJob, /filter\(\(k\) => \/\^verify\[A-Z\]\/\.test\(k\) && !SKIPPED\.includes\(k\)\)/);
  assert.match(publishJob, /JSON\.stringify\(exported\) !== JSON\.stringify\(expected\)[\s\S]*?process\.exit\(1\)/);
  assert.doesNotMatch(publishJob, /verifyFreshBundle\(/, 'the freshness check is named as skipped, never called');
  // The runner script goes to RUNNER_TEMP, never into the checkout, so the
  // guard's clean-tree check still passes.
  assert.match(publishJob, /cat >"\$RUNNER_TEMP\/run-guard\.mjs"/);
});

test('publish refuses if main moved since build', () => {
  assert.match(publishJob, /BUILD_SHA: \$\{\{ needs\.build\.outputs\.source_sha \}\}/);
  assert.match(publishJob, /test "\$HEAD" = "\$BUILD_SHA" && test "\$MAIN" = "\$BUILD_SHA"/);
});
