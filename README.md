# sift-q-release

Release lane and public issue tracker for [`@sift-wiki/q`](https://www.npmjs.com/package/@sift-wiki/q),
the Sift Q installer CLI.

The source code is private (`Sift-wiki/sift-q-refactor`). This repository
contains no source: the only code here is
[`.github/workflows/publish-npm.yml`](.github/workflows/publish-npm.yml),
the workflow that publishes the package to npm. It lives in a public
repository because npm trusted publishing (OIDC) requires a GitHub-hosted
runner, and GitHub-hosted runners are free only for public repositories.

## How a release happens

1. A version bump lands on `main` of the private repository, with its CI
   ("all gates passed") and release-gates workflows green on that commit.
2. A maintainer dispatches `publish-npm` here from `main`, first with
   `dry_run=true`. The job checks the private `main` out with a read-only
   token, installs, packs the tarball, installs that tarball into a clean
   prefix and runs it (`sift-q --version`, `sift-q install --dry-run`), and
   runs the private repository's publish guard against the exact commit.
3. The maintainer dispatches again with `dry_run=false`. The same steps run,
   then `npm publish` authenticates with the job's OIDC identity (no npm
   token exists anywhere) and the run verifies `latest` on the registry.
4. Rollback is roll-forward: npm versions are immutable and the OIDC lane
   cannot move dist-tags, so a bad release is followed by a fixed patch.

The package ships **without a provenance attestation**. npm would generate
one automatically for an OIDC publish from this public repository, but it
would name a commit of this repository as the build source, and this
repository contains no source. Rather than publish a misleading attestation,
the workflow sets `NPM_CONFIG_PROVENANCE=false`; the private source commit
that was published is recorded in each run's step summary.

## Issues

Bug reports and questions about `@sift-wiki/q` go in this repository's
issue tracker.

## Repository posture

This repository is the trust root of the npm lane, so it is locked down harder than the
workflow it holds:

- `main` accepts changes only through a pull request with one approval from a code owner
  who is not the author; no bypass actors.
- The `production` environment requires a reviewer's approval for every run, forbids
  self-review, and does not let admins bypass; its deployment-branch policy is `main` only,
  and the read-only source token is released only there.
- `tests/publish-npm-workflow.test.mjs` pins the workflow's security invariants (two jobs,
  `id-token` only on the publisher, SHA-pinned actions, exact npm, `single-branch` checkout,
  `--ignore-scripts` in the publisher, provenance off, kill switch first). `ci.yml` runs it on
  every pull request; each invariant has been mutation-verified.
- The lane has a kill switch: the `production` environment variable `NPM_PUBLISHER_LANE`
  must equal `github-actions-oidc` or the first step refuses. Environment admins can flip it
  without a workflow edit.

## Break glass

The two-person rule (required reviewer ≠ dispatcher) has three reviewers — Unobtainiumrock,
goodnight000, siftwiki — so one person's absence never blocks a release. If *no* second reviewer is
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
