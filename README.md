# sift-q-release

Release lane and public issue tracker for [`@sift-wiki/q`](https://www.npmjs.com/package/@sift-wiki/q),
the Sift Q installer CLI.

The product source is private (`Sift-wiki/sift-q-refactor`). This repository
contains only the public release workflow, its independent boundary verifier,
tests, and operator documentation. It lives in a public repository because npm
trusted publishing (OIDC) requires a GitHub-hosted runner, while the private
repository's GitHub-hosted jobs are unavailable.

## How a release happens

1. Accepted private `main` automatically runs `deploy-development`. That lane
   builds the package once, deploys the same source to `dev-q.sift.wiki`, runs
   the clean-HOME npm canary, and uploads exactly three files: the tarball and
   two signed receipts.
2. A maintainer records that successful run ID and the signed candidate's
   `sha256:...` receipt digest, then dispatches `publish-npm` here with those
   exact inputs and `dry_run=true`.
3. The no-OIDC selection job uses a fine-grained read-only token to verify the
   private repository ID, workflow path, accepted-main lineage, run result,
   artifact identity, exact file set, Ed25519 signatures, source/tree/receipt
   digests, runtime-canary receipt, tarball digest, and package metadata. It
   does not install, build, pack, or execute candidate code.
4. The maintainer dispatches again with the same run ID and receipt digest and
   `dry_run=false`. The OIDC job receives only the verified tarball, rechecks
   its digest and registry absence, publishes those exact bytes, and verifies
   `latest`. It has no private-repository credential or checkout.
5. Rollback is roll-forward: npm versions are immutable and the OIDC lane
   cannot move dist-tags, so a bad release is followed by a fixed patch.

The package ships **without a provenance attestation**. npm would generate
one automatically for an OIDC publish from this public repository, but it
would name a commit of this repository as the build source, and this
repository contains no source. Rather than publish a misleading attestation,
the workflow sets `NPM_CONFIG_PROVENANCE=false`; the private source commit
that was published is recorded in each run's step summary.
The tarball's `repository` metadata names this public relay, as required by the
npm trusted-publishing relationship. That is distinct from source identity,
which remains pinned to `Sift-wiki/sift-q-refactor` by the private run, signed
candidate receipts, exact commit tree, and trust policy.

## Issues

Bug reports and questions about `@sift-wiki/q` go in this repository's
issue tracker.

## Repository posture

This repository is the trust root of the npm lane, so it must be locked down harder than
the workflow it holds:

- `main` accepts changes only through a pull request with one approval from a code owner
  who is not the author; no bypass actors.
- Activation is currently fail-closed: the `candidate-selection` environment does not yet
  exist, while `production` still contains `SIFT_Q_READ_TOKEN` and the private source
  repository's legacy `.github/workflows/publish-npm.yml` is still active. Activation must
  happen in this order: (1) disable that private workflow and verify its GitHub state is
  `disabled_manually`; (2) create `candidate-selection`, require a reviewer, forbid
  self-review and admin bypass, allow only `main`, and add only
  `CANDIDATE_SELECTION_LANE=exact-development-candidate`, `SIFT_Q_READ_TOKEN`, and
  `DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON`; (3) remove `SIFT_Q_READ_TOKEN` from
  `production`; and (4) run the first reviewed dry run. `production` must retain its
  reviewer and main-only protections and only
  `NPM_PUBLISHER_LANE=github-actions-oidc`; the npm OIDC job must not receive either
  private-source secret. Every selection rechecks the exact private repository and legacy
  workflow IDs, name, path, and `disabled_manually` state before it reads candidate bytes.
- `tests/publish-npm-workflow.test.mjs` pins the workflow boundary: dispatch-only exact
  identifiers, `id-token` only on the publisher, no source credential in that job,
  SHA-pinned actions, exact npm, exact tarball transfer, provenance off, and kill switch
  first. `tests/verify-exact-candidate.test.mjs` adversarially substitutes repository,
  workflow, event, branch, conclusion, lineage, artifact authority, file set, and file type.
  Relay CI runs both suites on every pull request.
- Each authority has its own kill switch. `candidate-selection` requires
  `CANDIDATE_SELECTION_LANE=exact-development-candidate`; `production` requires
  `NPM_PUBLISHER_LANE=github-actions-oidc`. Environment admins can stop either boundary
  without a workflow edit.

## Break glass

The two-person rule (required reviewer ≠ dispatcher) has three reviewers — Unobtainiumrock,
goodnight000, orange-juice-1024 — so one person's absence never blocks a release. If _no_ second reviewer is
reachable and a release cannot wait, an admin lifts the rule for one window:

```
ops/break-glass.sh status                      # what is the rule right now
ops/break-glass.sh open "hotfix 0.9.x, <who> unreachable"   # lifts the reviewer rule; reason is recorded
#   ...dispatch and publish...
ops/break-glass.sh close                       # restores the three reviewers, no self-review, no admin bypass
```

While the glass is open, every other control still applies: `main`-only branch policy, the kill
switch, the guard, OIDC, and the SHA-pinned workflow behind reviewed pull requests. Only the second
human is removed. Both mutations are in GitHub's audit log under the caller's account and in
`~/.local/state/sift-q-release/break-glass.log`; `open` and `close` each verify the live state and
fail loudly rather than report a request as success. `close` is idempotent — run it whenever in doubt.
