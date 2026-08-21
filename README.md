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
