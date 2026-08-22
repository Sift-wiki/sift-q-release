# Tokenless staged npm release

This is the activation path for future `@sift-wiki/q` versions. It consumes one
exact candidate that already passed the private `deploy-development` lane and
stages those bytes directly with the intended immutable tag `latest`.

It does **not** publish the version to `next` first. npm's staged and published
packages share the same version index, so a version already published to
`next` cannot be staged. Existing versions on `next` are outside this workflow.

## Authority boundaries

`candidate-selection` contains only:

- `CANDIDATE_SELECTION_LANE=exact-development-candidate`
- `SIFT_Q_READ_TOKEN`, fine-grained read-only access to the private source
- `DEVELOPMENT_CANDIDATE_TRUST_POLICY_JSON`
- `NPM_OWNER_TRUST_POLICY_JSON`, the public Ed25519 owner trust policy
- `NPM_STAGE_TRANSFER_PUBLIC_KEY_PEM`, an RSA 3072-bit-or-larger public key

`production` contains only the release switches and public owner trust policy:

- `NPM_STAGING_LANE=oidc-stage-latest-v1`
- `NPM_APPROVAL_VERIFICATION_LANE=signed-stage-approval-v1`
- `NPM_OWNER_TRUST_POLICY_JSON`
- `NPM_STAGE_TRANSFER_PUBLIC_KEY_PEM`
- `NPM_STAGE_TRANSFER_PRIVATE_KEY_PEM`, available only inside `production`

The production environment must not contain an npm token or private-source
credential. Its required reviewers are Nicholas and Charles, self-review and
admin bypass are disabled, and deployments are limited to `main`.

Exactly one npm trusted-publisher relationship is allowed. It is restricted to
this public repository, `.github/workflows/stage-npm-latest.yml`, the
`production` environment, and staged publishing only. It must not authorize
normal publish, dist-tag mutation, or stage-management commands. Nicholas and
Charles only may complete interactive npm approval, both with 2FA. Granular and
classic npm tokens are disallowed. The historical private publisher and every
prior public npm mutation workflow remain disabled.

## Stage authorization

The machine-readable schema names are exact:

- `sift-q-npm-stage-binding/v1`
- `sift-q-npm-signed-stage-authorization/v1`
- `sift-q-npm-owner-trust/v1`
- `sift-q-npm-stage-plan/v1`
- `sift-q-npm-stage-result/v1`
- `sift-q-npm-signed-stage-approval/v1`
- `sift-q-npm-approval-result/v1`
- `sift-q-npm-stage-command-manifest/v1`
- `sift-q-sealed-stage-transfer/v1`

An owner signs the entire `sift-q-npm-signed-stage-authorization/v1` envelope with an
Ed25519 key present in `NPM_OWNER_TRUST_POLICY_JSON`. The envelope has a unique
authorization ID, a validity window no longer than 15 minutes, and an exact
binding to:

- package name, stable version, and intended tag `latest`
- private candidate run ID and attempt
- signed candidate receipt digest
- source and tree SHAs
- exact tarball digest
- public release repository, numeric repository ID, exact
  `.github/workflows/stage-npm-latest.yml` path, and release SHA
- expected current `latest`
- the SHA-256 fingerprint of the DER-encoded RSA transfer public-key SPKI

The candidate and command handoffs are RSA-OAEP/SHA-256 + AES-256-GCM sealed.
Public Actions artifacts contain only authenticated ciphertext; the RSA private
key exists only in `production`. Before the selection job uploads the first
ciphertext, it verifies the owner signature and proves the configured public
key has the signed SPKI fingerprint. Before production opens that handoff and
before it seals the command handoff, it also proves the private key derives the
same public SPKI. The OIDC job independently derives the public SPKI from its
private key and compares it with the verified signed fingerprint before it
decrypts. A substituted public key therefore fails before unpublished bytes
are uploaded, and a mismatched private key fails before either decryption.

The OIDC job decrypts into ephemeral runner
storage, requires at least two minutes of authorization lifetime immediately
before staging, and verifies an exact-byte manifest containing the verifier and
its complete transitive module closure. It has no checkout and no source
credential. Provenance is pinned off because this relay does not contain the
private source. The only npm mutation is:

```sh
npm stage publish npm-package.tgz --tag latest --ignore-scripts --access public --json
```

The workflow then proves the version is still not public, proves `latest` did
not move, and writes `npm-stage-result.json` with the npm stage ID, SHA-1,
integrity, tarball digest, authorization, replay record, and the exact approval
handoff. It never calls `npm stage approve`, `list`, `view`, or `download`.

## Human review and 2FA approval

Nicholas or Charles downloads and reviews the staged package through npmjs.com,
then approves it there, or uses:

```sh
npm stage approve <stage-id>
```

That approval is deliberately outside CI because npm requires interactive 2FA
and does not support OIDC for stage-management commands.

After the stage exists, Nicholas or Charles approves through npm's interactive
2FA flow. That owner then signs a short-lived
`sift-q-npm-signed-stage-approval/v1` envelope. The owner trust policy is
`sift-q-npm-owner-trust/v1`; every key binds one GitHub actor to one npm
username. The attestation binds `approvedBy`, the approval method, stage ID,
stage receipt digest, exact version and tarball digest, tag `latest`, and
expected post-approval `latest`. Its timestamp must be later than the stage
receipt. Dispatch
`verify-npm-stage-approval` with the successful stage run ID, stage receipt
digest, and base64-encoded attestation.

That second workflow has no OIDC permission and no npm token. It fetches exactly
one successful current-`main` stage receipt, rechecks its digest, downloads the
canonical public registry tarball, verifies its metadata and bytes, verifies
the signed approval attestation, proves `latest` selects the version, and emits
`npm-approval-result.json`. Each approval ID is consumed once under the shared
release lock. The receipt distinguishes the dispatching GitHub actor from the
owner-attested npm username; npm's audit record remains authoritative for who
actually approved the stage.

## Activation checklist

1. Land the workflows, verifier, tests, and this contract through reviewed
   `main`.
2. Keep both historical publish mutation paths disabled.
3. Create and protect `candidate-selection` and `production` exactly as above.
4. Install only the public Ed25519 owner trust policy; keep private signing keys
   offline. Generate the RSA transfer keypair, record its DER-SPKI SHA-256 in
   every signed stage authorization, install only its public half in
   `candidate-selection`, and install the matching keypair in `production`.
5. Configure the one npm trusted publisher for `stage-npm-latest.yml`,
   `production`, and staged publishing only.
6. Require interactive 2FA approval by Nicholas and Charles only, and disallow
   all granular or classic npm tokens from either workflow.
7. Run one reviewed dry selection against a development-qualified candidate.
8. Stage, independently review, approve with npm 2FA, and run the separate
   approval verifier.
9. Preserve both receipts with the private development candidate receipt and
   release decision record.

Until every item is complete, leave `NPM_STAGING_LANE` unset so the workflow
fails before it reads candidate bytes or requests OIDC authority.
