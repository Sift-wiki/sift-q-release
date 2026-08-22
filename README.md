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
   `sha256:...` receipt digest, creates a short-lived signed stage
   authorization for the exact candidate, and dispatches `stage-npm-latest`
   here with those exact inputs.
3. The no-OIDC selection job uses a fine-grained read-only token to verify the
   private repository ID, workflow path, accepted-main lineage, run result,
   artifact identity, exact file set, Ed25519 signatures, source/tree/receipt
   digests, runtime-canary receipt, tarball digest, and package metadata. It
   does not install, build, pack, or execute candidate code. Its public
   handoff contains only authenticated ciphertext. Before uploading that
   ciphertext, it proves the configured RSA public key's SPKI fingerprint is
   bound into the short-lived owner-signed stage authorization.
4. Production proves the RSA private key derives that same signed SPKI before
   decrypting and validating the candidate, then repeats the proof before publishing another
   ciphertext-only command artifact. The OIDC job decrypts it in ephemeral
   storage only after independently deriving the private key's public SPKI and
   comparing it with the verified signed fingerprint; the command contains the verified tarball, signed authority,
   verifier and its complete module closure, and exact-byte manifest. It
   rechecks current `main`, authorization lifetime, replay state, registry
   absence, and every command byte, then runs exactly one mutation:
   `npm stage publish npm-package.tgz --tag latest --ignore-scripts --access public --json`.
   It has no private-repository credential or checkout and cannot approve the
   stage.
5. The workflow records the npm stage ID and exact package digests in a
   nonsecret receipt. Nicholas or Charles reviews the staged package and
   approves it interactively in npmjs.com or with `npm stage approve <stage-id>`;
   npm requires their 2FA for that action.
6. After approval, an owner supplies a separate short-lived signed approval
   attestation and dispatches `verify-npm-stage-approval`. That read-only
   workflow fetches the exact stage receipt, public metadata, and canonical
   registry tarball; proves `latest` and every published byte match; and emits
   a separate approval result receipt. See
   [`docs/npm-staged-release.md`](docs/npm-staged-release.md).
7. Rollback is roll-forward: npm versions are immutable. Before approval, a bad
   stage is rejected or allowed to expire; after approval, it is followed by a
   fixed patch.

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
  `DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON`, the public owner trust policy, plus
  the public transfer key whose DER-SPKI SHA-256 is bound into each signed stage
  authorization; (3) remove `SIFT_Q_READ_TOKEN` from
  `production`; and (4) run the first reviewed dry run. `production` must retain its
  reviewer and main-only protections and only
  `NPM_STAGING_LANE=oidc-stage-latest-v1`,
  `NPM_APPROVAL_VERIFICATION_LANE=signed-stage-approval-v1`, the owner trust policy,
  and the stage-transfer keypair;
  the npm OIDC job must not receive either private-source secret. Every selection rechecks the exact private repository and legacy
  workflow IDs, name, path, and `disabled_manually` state before it reads candidate bytes.
- `tests/publish-npm-workflow.test.mjs` pins the workflow boundary: dispatch-only exact
  identifiers, `id-token` only on the publisher, no source credential in that job,
  SHA-pinned actions, exact npm, exact tarball transfer, historical publish-to-`next`, canonical
  registry byte equality, no direct `latest` mutation, provenance off, and kill switch
  first. `tests/verify-exact-candidate.test.mjs` adversarially substitutes repository,
  workflow, event, branch, conclusion, lineage, artifact authority, file set, and file type.
  `tests/verify-registry-transition.test.mjs` exercises the clean registry-byte canary and
  rejects changed tarballs, noncanonical registry URLs, changed `latest`, and widened
  evidence or promotion-binding schemas.
  Relay CI runs both suites on every pull request.
- Each authority has its own kill switch. `candidate-selection` requires
  `CANDIDATE_SELECTION_LANE=exact-development-candidate`; `production` requires
  `NPM_STAGING_LANE=oidc-stage-latest-v1` and
  `NPM_APPROVAL_VERIFICATION_LANE=signed-stage-approval-v1`. Environment admins can stop
  either boundary without a workflow edit.

## Staged latest interface

Trusted publishing does not authenticate `npm dist-tag add`; OIDC supports
`npm publish` and `npm stage publish`. npm also shares one immutable version
index between staged and published packages, so a version already published to
`next` cannot later be staged. Future releases therefore stage the exact
development-qualified candidate directly with the intended immutable tag
`latest` and never publish that version to `next` first.

The existing `publish-npm` implementation and its transition evidence remain
available as reviewed historical work, but its live mutation path must stay
disabled. It is not the activation path for future versions. Versions already
published to `next` are outside this automated lane and require an explicit,
separately reviewed owner decision.

No production signing key or npm credential is stored here. The only npm
mutation uses GitHub OIDC; stage approval is an interactive npm 2FA act by
Nicholas or Charles. Both operations are bound together afterward by a signed
approval attestation and an independently generated registry-verification
receipt.

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
