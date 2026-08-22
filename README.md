# sift-q-release

Release lane and public issue tracker for [`@sift-wiki/q`](https://www.npmjs.com/package/@sift-wiki/q),
the Sift Q installer CLI.

The product source is private (`Sift-wiki/sift-q-refactor`). This repository
contains only the public release workflow, its independent boundary verifier,
tests, and operator documentation. It lives in a public repository because npm
trusted publishing (OIDC) requires a GitHub-hosted runner, while the private
repository's GitHub-hosted jobs are unavailable.

## How a release happens

1. Accepted private `main` runs the fixed company-AWS development producer:
   `deploy-development-exact-candidate` (workflow ID `339350411`, path
   `.github/workflows/deploy-development.yml`). That lane builds the package
   once, deploys the same source to `dev.q.sift.wiki`, runs the clean-HOME npm
   canary, and uploads exactly three files: the tarball and two signed
   receipts. The public relay checks the private repository, workflow ID, name,
   path, accepted-main lineage, and signatures. A different development run,
   a manually dispatched run, or a run not produced by the company-AWS
   development lane is not a candidate.
2. Nicholas (`Unobtainiumrock`) or Charles (`orange-juice-1024`) records that
   successful run ID and the signed candidate's `sha256:...` receipt digest,
   then dispatches `publish-npm` here with those exact inputs and `dry_run=true`.
3. The no-OIDC selection job uses a fine-grained read-only token to verify the
   private repository ID, workflow path, accepted-main lineage, run result,
   artifact identity, exact file set, Ed25519 signatures, source/tree/receipt
   digests, runtime-canary receipt, tarball digest, and package metadata. It
   does not install, build, pack, or execute candidate code.
4. One of those two production owners dispatches again with the same run ID and
   receipt digest and `dry_run=false`. The OIDC job receives only the verified
   tarball, rechecks its digest and registry absence, and refuses to write if
   `next` identifies any in-flight version distinct from `latest`. It then
   publishes those exact bytes under the `next` dist-tag. It has no
   private-repository credential or private checkout. It checks out only this
   public release repository at the dispatched SHA to run the reviewed provider
   authority verifier.
5. A separate no-OIDC, no-secret, no-write job fetches that exact version back
   through the canonical npm registry, proves the registry tarball is
   byte-identical to the selected candidate, installs those registry-served
   bytes under a fresh temporary HOME, runs the bounded CLI canary, re-reads
   `next` and `latest`, proves neither moved unexpectedly, and emits
   `npm-next-transition.json` plus `npm-latest-promotion-binding.json`.
6. Nicholas or Charles verifies the transition and a fresh owner-signed
   promotion authorization, reviews the canary evidence, and interactively runs
   `npm dist-tag add @sift-wiki/q@<version> latest` with npm 2FA. This changes
   only the tag; it never rebuilds or republishes the package bytes.
7. That same owner dispatches `verify-npm-latest-promotion` with the original
   transition run ID, exact evidence digest, and signed authorization. The
   workflow has no OIDC or registry-write credential. A different production
   owner must approve the environment. It proves the signed binding, exact
   release-main SHA, replay state, `next` and `latest`, canonical registry
   metadata, and public tarball bytes, then emits a bounded-retention GitHub
   verification bundle containing the complete transition evidence.
8. Rollback is roll-forward: npm versions are immutable. Before promotion, a
   bad candidate is reconciled through the governed rejected-`next` procedure;
   after promotion, it is followed by a fixed patch.

The package ships **without a provenance attestation**. npm would generate one
automatically for an OIDC publish from this public repository, but it would name
a commit of this repository as the build source, and this repository contains no
source. Rather than publish a misleading attestation, the workflow sets
`NPM_CONFIG_PROVENANCE=false`. The private source commit remains bound by the
private run, signed candidate receipts, exact commit tree, and trust policy.

No release step requires production to serve the package's source SHA. Runtime
qualification happens in development; production application deployment and npm
tag promotion remain separate authorities over the same immutable candidate.

## Issues

Bug reports and questions about `@sift-wiki/q` go in this repository's issue
tracker.

## Repository posture

This repository is the trust root of the npm lane:

- `main` accepts changes only through a pull request with one approval from a
  code owner who is not the author; there are no bypass actors. Tianjun
  (`goodnight000`) may review code, but production and npm runtime authority is
  restricted to Nicholas and Charles.
- Every mutation workflow is dispatch-only, main-only, and gates both the
  original dispatcher and any rerun initiator to `Unobtainiumrock` or
  `orange-juice-1024`. The production environment must
  contain only those two required reviewers, require approval by someone other
  than the dispatcher, disable administrator bypass, and allow only `main`.
- Activation remains fail-closed until the private legacy publisher is
  `disabled_manually`, `candidate-selection` exists, private-source credentials
  are removed from `production`, the public exact-candidate lane is dry-run
  qualified, and the production environment is reconciled to the two owners.
- `candidate-selection` contains only
  `CANDIDATE_SELECTION_LANE=exact-development-candidate`, the fine-grained
  read-only `SIFT_Q_READ_TOKEN`, and
  `DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON`. `production` contains only
  `NPM_PUBLISHER_LANE=github-actions-oidc` and the public
  `NPM_LATEST_PROMOTION_VERIFIER_LANE=signed-next-to-latest-v1` plus
  `NPM_LATEST_PROMOTION_TRUST_POLICY_JSON`. No npm token, private source token,
  or private signing key belongs in `production`.
- The single npm trusted publisher is restricted to this public repository,
  workflow filename `publish-npm.yml`, the `production` environment, and
  `npm publish`. OIDC is never used for `npm dist-tag`; the final tag mutation is
  an interactive Nicholas/Charles action protected by npm 2FA.
- Each authority has an independent kill switch. Until every activation item is
  proven, leave the relevant switch unset so the workflow fails before reading
  candidate bytes or requesting npm write authority.

## Activation preconditions and owner-only sequence

This release repository cannot repair provider configuration. Its checks are
deliberately fail-closed, so an absent environment, a misplaced secret, an
extra npm maintainer, or no qualified candidate stops before an npm write. Do
not dispatch `publish-npm`, enable a workflow, publish, move a tag, alter npm
owners, or change an environment while any item below is open.

The required npm maintainer set is exactly these two production authorities:

- Nicholas: GitHub `Unobtainiumrock`; npm `unobtainiumrock`.
- Charles: GitHub `orange-juice-1024`; npm `jxiao1024`.

The checked-in provider verifier accepts only `unobtainiumrock` and `jxiao1024`.
It rejects additions, removals, aliases, and a changed set before dry-run,
immediately before publication, immediately after publication, and after the
registry canary. It does not run `npm owner` and cannot reconcile the provider
for an owner.

### Read-only reconciliation snapshot — 2026-08-22

This snapshot is evidence for the activation handover, not a replacement for a
fresh owner check immediately before activation:

- npm reported four maintainers: `unobtainiumrock_three`, `goodnight00`,
  `unobtainiumrock`, and `jxiao1024`. This is not the exact Nicholas/Charles
  set, so the provider verifier refuses it.
- This repository had no `candidate-selection` environment. Therefore neither
  its lane selector nor its two required secrets existed in that environment.
- `production` contained `SIFT_Q_READ_TOKEN`. The private-source read token is
  not permitted there.
- The private `development` environment had no visible configuration names and
  there was no successful `deploy-development-exact-candidate` run among the
  most recent 100 workflow runs. There is no qualified company-AWS development
  candidate to select.

### Required owner actions, in order

1. An authorized npm owner, using npm 2FA, must reconcile the live maintainer
   set to exactly `unobtainiumrock` and `jxiao1024`. This is an external,
   irreversible authority action; no repository workflow or script may do it.
2. An authorized release-repository administrator must create the protected
   `candidate-selection` environment, then place only these configuration
   items there:
   `CANDIDATE_SELECTION_LANE=exact-development-candidate`, the fine-grained
   read-only `SIFT_Q_READ_TOKEN`, and
   `DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON`. The read token is scoped only to
   the private source repository with `Contents:read`, `Actions:read`, and
   `Metadata:read`.
3. That administrator must remove `SIFT_Q_READ_TOKEN` from `production` and
   confirm that production has no private-source token, npm token, or private
   signing key. Its required selectors remain
   `NPM_PUBLISHER_LANE=github-actions-oidc`,
   `NPM_LATEST_PROMOTION_VERIFIER_LANE=signed-next-to-latest-v1`, and
   `NPM_LATEST_PROMOTION_TRUST_POLICY_JSON`.
4. The company-AWS development owner must provision and attest the isolated
   company-AWS development producer, then obtain one fresh successful automatic
   accepted-main run of `deploy-development-exact-candidate` (workflow ID
   `339350411`). A skipped run, a personal-account candidate, or a candidate
   from another workflow cannot substitute for this gate.
5. Nicholas or Charles must independently re-read the environments, secret
   names, npm maintainers, trusted-publisher binding, disabled legacy publisher,
   and the fresh company-AWS candidate. Only then may either owner dispatch the
   same exact candidate in `dry_run=true`. A green dry run is evidence, not
   permission to skip any preceding gate.
6. After the dry run and all independent owner approvals are recorded, the
   existing controlled sequence may proceed. The publish workflow, final npm
   `latest` move, and any provider configuration change remain owner-only
   actions.

## Latest promotion interface

`publish-npm` never invokes `npm dist-tag` and never publishes with
`--tag latest`. Its evidence artifact contains:

- `npm-next-transition.json`: exact source, candidate receipt, tarball digest,
  canonical registry metadata, the pre-write `next` state, unchanged `latest`,
  and clean canary result. `next` must have been absent or equal to `latest`.
- `npm-latest-promotion-binding.json`: the exact payload a signed promotion
  authorization must bind, including the transition-evidence digest,
  source/tree SHAs, candidate receipt digest, tarball digest, version, and the
  expected `next` and pre-promotion `latest` values.

`scripts/verify-registry-transition.mjs verify-promotion-receipt` validates the
authorization before the owner runs the 2FA command. After the tag moves,
`verify-npm-latest-promotion` consumes the same authorization and transition
evidence, proves the exact public bytes and tag state, rejects a reused
authorization ID, and records both the signed authorization and a strict
read-only verification result.

Create the short-lived owner authorization locally; never store an owner private
key in GitHub. The helper accepts exactly one protected key path or already-open
file descriptor, verifies that the key is present in the reviewed trust policy,
checks the transition binding and the live tag values supplied by the owner,
writes a mode-0600 receipt, and prints the base64 workflow input:

```sh
node scripts/authorize-npm-latest-promotion.mjs \
  --evidence npm-next-transition.json \
  --binding npm-latest-promotion-binding.json \
  --trust-policy owner-promotion-trust.json \
  --private-key /secure/offline/owner-ed25519.pem \
  --current-latest <latest> --current-next <candidate-version> \
  --output signed-npm-latest-promotion.json
```

The authorization lifetime is at most 15 minutes (10 minutes by default).
From its creation through the final verification, do not merge into release
`main`: both workflows require the same exact current release SHA. If `main`
advances or the receipt expires, stop and issue a fresh authorization after
re-verifying the unchanged transition.

The post-state result JSON is intentionally not signed by a GitHub-held key.
The archived owner-signed Ed25519 authorization covers the exact transition
evidence digest and promotion preconditions; its canonical SHA-256 digest is
embedded in the result. The result's own digest is recorded in the GitHub run
summary. The uploaded bundle retains the signed receipt, transition evidence,
promotion binding, public trust policy, raw bounded transition run and artifact
provenance, selected-artifact metadata, registry metadata and bytes, maintainer
snapshot, verification provenance with public-key/digest bindings, and
verification result for 90 days. The promotion trust policy is public-only: it
must contain Ed25519 public keys and identifiers, never private key material.
GitHub artifacts are deletable and expiring; they are not an immutable archive.
The owner must copy the whole bundle into the owner-controlled release archive
before that window expires. External verification checks the archived public
key against its SPKI digest, verifies the owner signature and canonical
digests, and compares the bounded run/artifact metadata to the verification
provenance. This avoids placing a long-lived owner signing secret in GitHub.
The owner signature does not cover the post-state result, and that result must
not be described as independently signed.

The exact bounded archive file set is:

- `signed-npm-latest-promotion.json`, `npm-next-transition.json`, and
  `npm-latest-promotion-binding.json`;
- `npm-latest-promotion-trust-policy.json`,
  `npm-latest-verification-provenance.json`, and
  `npm-latest-verification.json`;
- `transition-run-metadata.json`, `transition-artifacts-metadata.json`, and
  `transition-artifact-selection.json`;
- `npm-registry-metadata.json`, `npm-registry-package.tgz`, and
  `npm-maintainers.json`.

The final mutation is intentionally human and exact:

```sh
npm dist-tag add "@sift-wiki/q@<version>" latest
```

Only Nicholas or Charles may run it. npm prompts for 2FA. The command moves a
label to the already published and canaried version; it cannot alter that
version's immutable tarball.

The npm registry does not provide compare-and-swap for `npm publish --tag next`.
The workflow therefore requires the provider maintainer set to equal exactly
`jxiao1024` and `unobtainiumrock`, snapshots maintainers and tags, rechecks both
in the same shell step immediately before the write, and rechecks them again
immediately afterward and after the canary. This fails closed against ordinary
drift, but it cannot make a concurrent direct npm owner honor a repository lock.
Removing every other npm maintainer is therefore an activation prerequisite,
not merely an audit recommendation.

If a canary rejects a version already placed on `next`, never leave that stale
candidate blocking later releases and never clear it ad hoc. Nicholas or Charles
runs the read-only status command, records the reason, then performs the explicit
2FA reset that points `next` back to the unchanged `latest` version and emits a
mode-0600 reconciliation receipt:

```sh
node scripts/reconcile-rejected-next.mjs status --rejected-version <version> \
  --npm-cli-js /absolute/path/to/npm-cli.js \
  --npm-userconfig /secure/owner-only.npmrc
node scripts/reconcile-rejected-next.mjs reset --rejected-version <version> \
  --npm-cli-js /absolute/path/to/npm-cli.js \
  --npm-userconfig /secure/owner-only.npmrc \
  --confirm RESET-REJECTED-NEXT-TO-LATEST \
  --reason '<at least 20 characters describing the rejected canary>' \
  --receipt-output rejected-next-reconciliation.json
```

Both commands require the same absolute npm CLI and mode-0600 owner-only npm
userconfig arguments. The helper runs the CLI through the current absolute Node
binary, refuses symlinked or group/world-writable CLI material, records its
SHA-256 digest, requires npm 11.19.0, scrubs ambient npm configuration, and verifies the
effective unscoped and `@sift-wiki` registries are exactly
`https://registry.npmjs.org/`. The reset reserves its exclusive receipt output
before the first npm provider call, so a missing, existing, or unavailable
receipt path cannot mutate `next`.

## Break glass

The two-person rule has exactly two production owners: Nicholas
(`Unobtainiumrock`) and Charles (`orange-juice-1024`). If the other owner is
unreachable and a release cannot wait, an admin may lift only the reviewer rule
for one recorded window:

```text
ops/break-glass.sh status
ops/break-glass.sh open "hotfix reason; other owner unreachable"
# dispatch or verify the exact release
ops/break-glass.sh close
```

The workflows' hard actor gates remain in force while the glass is open, so the
window never grants Tianjun or another collaborator production/npm runtime
authority. `close` always restores Nicholas and Charles, no self-review, no
administrator bypass, and the main-only branch policy.
