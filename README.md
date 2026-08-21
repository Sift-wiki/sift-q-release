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
   its digest and registry absence, and publishes those exact bytes under the
   `next` dist-tag. It has no private-repository credential or private checkout.
5. A separate no-OIDC, no-secret, no-write job fetches that exact version back through the canonical npm
   registry, proves the registry tarball is byte-identical to the selected
   candidate, installs those registry-served bytes under a fresh temporary
   HOME, runs the bounded CLI canary, re-reads `next` and `latest`, proves
   neither moved unexpectedly, and emits
   `npm-next-transition.json` plus `npm-latest-promotion-binding.json`.
6. Those two files are strict, machine-readable evidence, but they are
   explicitly marked unsigned and non-authoritative. A separately governed
   promotion lane must verify an owner-trusted, short-lived signed authorization
   containing exactly the emitted promotion binding before it may move `next`
   to `latest`.
   No trusted promotion signer or receipt-verification policy is configured in
   this repository yet, so that final lane remains fail-closed.
7. Rollback is roll-forward: npm versions are immutable. Before promotion, a
   bad candidate can be abandoned on `next`; after promotion, it is followed by
   a fixed patch.

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
  SHA-pinned actions, exact npm, exact tarball transfer, publish-to-`next`, canonical
  registry byte equality, no direct `latest` mutation, provenance off, and kill switch
  first. `tests/verify-exact-candidate.test.mjs` adversarially substitutes repository,
  workflow, event, branch, conclusion, lineage, artifact authority, file set, and file type.
  `tests/verify-registry-transition.test.mjs` exercises the clean registry-byte canary and
  rejects changed tarballs, noncanonical registry URLs, changed `latest`, and widened
  evidence or promotion-binding schemas.
  Relay CI runs both suites on every pull request.
- Each authority has its own kill switch. `candidate-selection` requires
  `CANDIDATE_SELECTION_LANE=exact-development-candidate`; `production` requires
  `NPM_PUBLISHER_LANE=github-actions-oidc`. Environment admins can stop either boundary
  without a workflow edit.

## Latest promotion interface

`publish-npm` never invokes `npm dist-tag` and never publishes with `--tag latest`.
Its evidence artifact contains:

- `npm-next-transition.json`: exact source, candidate receipt, tarball digest,
  canonical registry metadata, unchanged `latest`, and clean canary result.
- `npm-latest-promotion-binding.json`: the exact payload a later signed
  promotion receipt must bind, including the transition-evidence digest,
  source/tree SHAs, candidate receipt digest, tarball digest, version, and
  `next` → `latest` transition, including the expected current values of both
  tags.

The binding is unsigned by design. `scripts/verify-registry-transition.mjs
verify-promotion-binding` checks that it is the exact deterministic projection
of the transition evidence; it does **not** authenticate an operator.
`verify-promotion-receipt` is the consumer interface for the future lane: it
requires an Ed25519 `sift-q-npm-latest-promotion-receipt/v1`, verifies its
entire schema, algorithm, key identity, unique authorization ID, bounded
authorization window, and exact binding against a separately supplied
`sift-q-npm-latest-promotion-trust/v1` policy, and then requires the signed
binding to equal the deterministic projection. It also refuses unless the
live `latest` and `next` values equal the signed preconditions; serialization
means the first successful promotion changes `latest` and makes replay fail.
No production trust policy,
private key, or made-up receipt is stored here. The future promotion lane must
also re-read `next`, its exact-version registry bytes, and current `latest`
under the production lock, record the authorization ID as consumed, and only
then perform the separately authorized `next` → `latest` change. Until an
owner-managed signer and trust policy exist, promotion is blocked.

## Break glass

The two-person rule (required reviewer ≠ dispatcher) has exactly two production
owners — Unobtainiumrock and goodnight000. If the other owner is unreachable
and a release cannot wait, an admin lifts the rule for one window:

```
ops/break-glass.sh status                      # what is the rule right now
ops/break-glass.sh open "hotfix 0.9.x, <who> unreachable"   # lifts the reviewer rule; reason is recorded
#   ...dispatch and publish...
ops/break-glass.sh close                       # restores both owners, no self-review, no admin bypass
```

While the glass is open, every other control still applies: `main`-only branch policy, the kill
switch, the guard, OIDC, and the SHA-pinned workflow behind reviewed pull requests. Only the second
human is removed. Both mutations are in GitHub's audit log under the caller's account and in
`~/.local/state/sift-q-release/break-glass.log`; `open` and `close` each verify the live state and
fail loudly rather than report a request as success. `close` is idempotent — run it whenever in doubt.
