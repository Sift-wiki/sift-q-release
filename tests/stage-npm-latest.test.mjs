import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign as signMessage,
} from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  APPROVAL_RESULT_SCHEMA,
  COMMAND_MANIFEST_SCHEMA,
  OWNER_TRUST_SCHEMA,
  PACKAGE_NAME,
  RELEASE_REPOSITORY,
  SIGNED_APPROVAL_ATTESTATION_SCHEMA,
  SIGNED_STAGE_AUTHORIZATION_SCHEMA,
  STAGE_RESULT_SCHEMA,
  assertStageAuthorityRemaining,
  createCommandManifest,
  prepareStage,
  recordStageResult,
  stageBindingFor,
  transferPublicKeySpkiSha256,
  verifyApprovedStage,
  verifyCommandManifest,
  verifyTransferRecipient,
} from "../scripts/stage-npm-latest.mjs";
import { canonicalJson } from "../scripts/verify-registry-transition.mjs";

const VERSION = "1.2.3";
const LATEST = "1.2.2";
const RELEASE_SHA = "1".repeat(40);
const SOURCE_SHA = "2".repeat(40);
const TREE_SHA = "3".repeat(40);
const RECEIPT_DIGEST = `sha256:${"4".repeat(64)}`;
const NOW = new Date("2026-08-21T12:00:00.000Z");
const APPROVAL_NOW = new Date("2026-08-21T12:02:00.000Z");
const STAGE_ID = "9f36a244-2242-4c68-8162-c86562df3c6d";
const TRANSFER_KEYS = generateKeyPairSync("rsa", { modulusLength: 3072 });
const OTHER_TRANSFER_KEYS = generateKeyPairSync("rsa", { modulusLength: 3072 });
const TRANSFER_PUBLIC_KEY_PEM = TRANSFER_KEYS.publicKey.export({
  format: "pem",
  type: "spki",
});
const TRANSFER_PRIVATE_KEY_PEM = TRANSFER_KEYS.privateKey.export({
  format: "pem",
  type: "pkcs8",
});
const OTHER_TRANSFER_PUBLIC_KEY_PEM = OTHER_TRANSFER_KEYS.publicKey.export({
  format: "pem",
  type: "spki",
});
const OTHER_TRANSFER_PRIVATE_KEY_PEM = OTHER_TRANSFER_KEYS.privateKey.export({
  format: "pem",
  type: "pkcs8",
});
const TRANSFER_SPKI_SHA256 = transferPublicKeySpkiSha256(
  TRANSFER_PUBLIC_KEY_PEM,
);

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sha1(bytes) {
  return createHash("sha1").update(bytes).digest("hex");
}

function integrity(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

function makePackage(root) {
  const packageRoot = join(root, "package");
  const destination = join(root, "pack");
  mkdirSync(packageRoot);
  mkdirSync(destination);
  writeFileSync(
    join(packageRoot, "package.json"),
    `${JSON.stringify({
      name: PACKAGE_NAME,
      version: VERSION,
      repository: {
        type: "git",
        url: "git+https://github.com/Sift-wiki/sift-q-release.git",
      },
      bin: { "sift-q": "bin.cjs" },
      files: ["bin.cjs"],
    })}\n`,
  );
  writeFileSync(join(packageRoot, "bin.cjs"), "#!/usr/bin/env node\n", {
    mode: 0o755,
  });
  const packed = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--ignore-scripts", "--json", "--pack-destination", destination],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env: { ...process.env, npm_config_cache: join(root, "cache") },
      },
    ),
  );
  return readFileSync(join(destination, packed[0].filename));
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "stage-npm-latest-"));
  const tarball = makePackage(root);
  const selectedCandidate = {
    candidateReceiptDigest: RECEIPT_DIGEST,
    currentMainSha: SOURCE_SHA,
    runAttempt: 2,
    runId: 32500000000,
    sourceSha: SOURCE_SHA,
    tarballDigest: sha256(tarball),
    tarballSha256: sha256(tarball).slice("sha256:".length),
    treeSha: TREE_SHA,
    version: VERSION,
  };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyId = "owner-key-2026";
  const trustPolicy = {
    schemaVersion: OWNER_TRUST_SCHEMA,
    keys: [
      {
        algorithm: "Ed25519",
        githubActor: "Unobtainiumrock",
        keyId,
        npmUsername: "unobtainiumrock",
        publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
      },
    ],
  };
  const sign = (body) => ({
    ...body,
    signature: signMessage(
      null,
      Buffer.from(canonicalJson(body)),
      privateKey,
    ).toString("base64"),
  });
  const authorization = sign({
    schemaVersion: SIGNED_STAGE_AUTHORIZATION_SCHEMA,
    algorithm: "Ed25519",
    authorizationId: "authorization-2026-08-21-0001",
    authorizedAt: "2026-08-21T11:59:00.000Z",
    expiresAt: "2026-08-21T12:09:00.000Z",
    keyId,
    binding: stageBindingFor({
      selectedCandidate,
      tarball,
      releaseSha: RELEASE_SHA,
      expectedLatestBefore: LATEST,
      transferPublicKeySpkiSha256: TRANSFER_SPKI_SHA256,
    }),
  });
  const plan = prepareStage({
    authorization,
    trustPolicy,
    selectedCandidate,
    tarball,
    releaseSha: RELEASE_SHA,
    currentLatest: LATEST,
    versionIsAbsent: true,
    transferPublicKeyPem: TRANSFER_PUBLIC_KEY_PEM,
    now: () => NOW,
  });
  const stageOutput = {
    [PACKAGE_NAME]: {
      stageId: STAGE_ID,
      name: PACKAGE_NAME,
      version: VERSION,
      shasum: sha1(tarball),
      integrity: integrity(tarball),
    },
  };
  const stageReceipt = recordStageResult({
    plan,
    selectedCandidate,
    tarball,
    stageOutput,
    actor: "Unobtainiumrock",
    workflowRunId: 123,
    workflowRunAttempt: 1,
    commandArtifactName: `npm-stage-authorization-${authorization.authorizationId}`,
    commandManifestDigest: `sha256:${"5".repeat(64)}`,
    replayArtifactId: 456,
    stagedAt: () => NOW,
  });
  const stageReceiptDigest = sha256(canonicalJson(stageReceipt));
  const approvalAttestation = sign({
    schemaVersion: SIGNED_APPROVAL_ATTESTATION_SCHEMA,
    algorithm: "Ed25519",
    approvalId: "approval-2026-08-21-0001",
    authorizedAt: "2026-08-21T12:01:00.000Z",
    expiresAt: "2026-08-21T12:30:00.000Z",
    keyId,
    binding: {
      approvalMethod: "npmjs.com",
      approvedBy: "unobtainiumrock",
      expectedLatestAfter: VERSION,
      packageName: PACKAGE_NAME,
      stageId: STAGE_ID,
      stageReceiptDigest,
      tag: "latest",
      tarballDigest: selectedCandidate.tarballDigest,
      version: VERSION,
    },
  });
  return {
    approvalAttestation,
    authorization,
    plan,
    root,
    selectedCandidate,
    sign,
    stageOutput,
    stageReceipt,
    stageReceiptDigest,
    tarball,
    transferPrivateKeyPem: TRANSFER_PRIVATE_KEY_PEM,
    transferPublicKeyPem: TRANSFER_PUBLIC_KEY_PEM,
    trustPolicy,
  };
}

test("prepares one signed exact-candidate stage plan", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  assert.equal(value.plan.binding.version, VERSION);
  assert.equal(value.plan.binding.tag, "latest");
  assert.equal(value.plan.binding.releaseRepositoryId, 1_341_269_682);
  assert.equal(
    value.plan.binding.stageWorkflowPath,
    ".github/workflows/stage-npm-latest.yml",
  );
  assert.equal(value.plan.binding.tarballDigest, sha256(value.tarball));
  assert.equal(
    value.plan.binding.transferPublicKeySpkiSha256,
    TRANSFER_SPKI_SHA256,
  );
  assert.ok(
    assertStageAuthorityRemaining(value.plan, () => NOW).remainingMs >= 120_000,
  );
});

test("refuses a stable version that does not strictly advance latest", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  assert.throws(
    () =>
      stageBindingFor({
        selectedCandidate: value.selectedCandidate,
        tarball: value.tarball,
        releaseSha: RELEASE_SHA,
        expectedLatestBefore: VERSION,
        transferPublicKeySpkiSha256: TRANSFER_SPKI_SHA256,
      }),
    /must strictly advance current latest/,
  );
});

for (const [label, mutate, expected] of [
  [
    "changed latest",
    (v) => (v.currentLatest = "1.2.1"),
    /current latest differs/,
  ],
  [
    "existing version",
    (v) => (v.versionIsAbsent = false),
    /already exists publicly/,
  ],
  [
    "changed tarball",
    (v) => (v.tarball = Buffer.from("changed")),
    /tarball bytes differ/,
  ],
  [
    "wrong release SHA",
    (v) => (v.releaseSha = "9".repeat(40)),
    /binding differs/,
  ],
]) {
  test(`refuses ${label} before staging`, (t) => {
    const value = fixture();
    t.after(() => rmSync(value.root, { force: true, recursive: true }));
    const args = {
      authorization: value.authorization,
      trustPolicy: value.trustPolicy,
      selectedCandidate: value.selectedCandidate,
      tarball: value.tarball,
      releaseSha: RELEASE_SHA,
      currentLatest: LATEST,
      versionIsAbsent: true,
      transferPublicKeyPem: value.transferPublicKeyPem,
      now: () => NOW,
    };
    mutate(args);
    assert.throws(() => prepareStage(args), expected);
  });
}

for (const [label, mutate, expected] of [
  [
    "pre-stage attestation",
    (body) => (body.authorizedAt = "2026-08-21T11:59:59.000Z"),
    /predates the npm stage/,
  ],
  [
    "approver not bound to signing key",
    (body) => (body.binding.approvedBy = "goodnight00"),
    /signer is not the attested npm approver/,
  ],
]) {
  test(`refuses ${label}`, (t) => {
    const value = fixture();
    t.after(() => rmSync(value.root, { force: true, recursive: true }));
    const body = structuredClone(value.approvalAttestation);
    delete body.signature;
    mutate(body);
    const approvalAttestation = value.sign(body);
    const tarball = join(value.root, "registry.tgz");
    writeFileSync(tarball, value.tarball);
    assert.throws(
      () =>
        verifyApprovedStage({
          stageReceipt: value.stageReceipt,
          expectedStageReceiptDigest: value.stageReceiptDigest,
          approvalAttestation,
          trustPolicy: value.trustPolicy,
          registryMetadata: {
            name: PACKAGE_NAME,
            version: VERSION,
            dist: {
              shasum: sha1(value.tarball),
              integrity: integrity(value.tarball),
            },
          },
          registryTarball: tarball,
          currentLatest: VERSION,
          actor: "Unobtainiumrock",
          workflowRunId: 124,
          workflowRunAttempt: 1,
          releaseSha: RELEASE_SHA,
          now: () => APPROVAL_NOW,
        }),
      expected,
    );
  });
}

test("refuses a tampered signed authorization", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  value.authorization.binding.version = "1.2.4";
  assert.throws(
    () =>
      prepareStage({
        authorization: value.authorization,
        trustPolicy: value.trustPolicy,
        selectedCandidate: value.selectedCandidate,
        tarball: value.tarball,
        releaseSha: RELEASE_SHA,
        currentLatest: LATEST,
        versionIsAbsent: true,
        transferPublicKeyPem: value.transferPublicKeyPem,
        now: () => NOW,
      }),
    /signature is invalid/,
  );
});

test("refuses a substituted transfer public key before ciphertext upload", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  assert.throws(
    () =>
      verifyTransferRecipient({
        authorization: value.authorization,
        trustPolicy: value.trustPolicy,
        publicKeyPem: OTHER_TRANSFER_PUBLIC_KEY_PEM,
        now: () => NOW,
      }),
    /transfer public key differs from signed stage authority/,
  );
});

test("refuses a transfer private key that does not derive the signed SPKI", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  assert.throws(
    () =>
      verifyTransferRecipient({
        authorization: value.authorization,
        trustPolicy: value.trustPolicy,
        publicKeyPem: value.transferPublicKeyPem,
        privateKeyPem: OTHER_TRANSFER_PRIVATE_KEY_PEM,
        now: () => NOW,
      }),
    /transfer private key differs from signed stage authority/,
  );
});

test("refuses stage authority with less than two minutes remaining", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  assert.throws(
    () =>
      assertStageAuthorityRemaining(
        value.plan,
        () => new Date("2026-08-21T12:07:01Z"),
      ),
    /insufficient remaining validity/,
  );
});

test("records the exact npm stage output and interactive handoff", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  assert.equal(value.stageReceipt.schemaVersion, STAGE_RESULT_SCHEMA);
  assert.equal(value.stageReceipt.outcome, "staged-awaiting-interactive-2fa");
  assert.equal(
    value.stageReceipt.approval.cliCommand,
    `npm stage approve ${STAGE_ID}`,
  );
  assert.equal(value.stageReceipt.npm.integrity, integrity(value.tarball));
});

for (const [label, overrides, expected] of [
  ["unexpected actor", { actor: "other" }, /actor is not/],
  [
    "changed stage digest",
    {
      stageOutput: {
        [PACKAGE_NAME]: {
          stageId: STAGE_ID,
          name: PACKAGE_NAME,
          version: VERSION,
          shasum: "0".repeat(40),
          integrity: "sha512-" + "A".repeat(86) + "==",
        },
      },
    },
    /shasum differs/,
  ],
]) {
  test(`refuses ${label} in the stage result`, (t) => {
    const value = fixture();
    t.after(() => rmSync(value.root, { force: true, recursive: true }));
    assert.throws(
      () =>
        recordStageResult({
          plan: value.plan,
          selectedCandidate: value.selectedCandidate,
          tarball: value.tarball,
          stageOutput: value.stageOutput,
          actor: "Unobtainiumrock",
          workflowRunId: 123,
          workflowRunAttempt: 1,
          commandArtifactName: `npm-stage-authorization-${value.authorization.authorizationId}`,
          commandManifestDigest: `sha256:${"5".repeat(64)}`,
          replayArtifactId: 456,
          ...overrides,
        }),
      expected,
    );
  });
}

test("verifies the separately approved exact public bytes", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  const tarball = join(value.root, "registry.tgz");
  writeFileSync(tarball, value.tarball);
  const result = verifyApprovedStage({
    stageReceipt: value.stageReceipt,
    expectedStageReceiptDigest: value.stageReceiptDigest,
    approvalAttestation: value.approvalAttestation,
    trustPolicy: value.trustPolicy,
    registryMetadata: {
      name: PACKAGE_NAME,
      version: VERSION,
      dist: {
        shasum: sha1(value.tarball),
        integrity: integrity(value.tarball),
      },
    },
    registryTarball: tarball,
    currentLatest: VERSION,
    actor: "goodnight000",
    workflowRunId: 124,
    workflowRunAttempt: 1,
    releaseSha: RELEASE_SHA,
    now: () => APPROVAL_NOW,
  });
  assert.equal(result.schemaVersion, APPROVAL_RESULT_SCHEMA);
  assert.equal(result.outcome, "approved-and-registry-verified");
  assert.equal(result.npm.latest, VERSION);
});

for (const [label, mutate, expected] of [
  [
    "wrong stage receipt digest",
    (v) => (v.expectedStageReceiptDigest = `sha256:${"0".repeat(64)}`),
    /receipt digest differs/,
  ],
  [
    "latest did not move",
    (v) => (v.currentLatest = LATEST),
    /latest does not select/,
  ],
  [
    "wrong release SHA",
    (v) => (v.releaseSha = "8".repeat(40)),
    /release SHA differs/,
  ],
  [
    "tampered approval",
    (v) =>
      (v.approvalAttestation.binding.stageId =
        "8f36a244-2242-4c68-8162-c86562df3c6d"),
    /signature is invalid/,
  ],
]) {
  test(`refuses approval verification with ${label}`, (t) => {
    const value = fixture();
    t.after(() => rmSync(value.root, { force: true, recursive: true }));
    const tarball = join(value.root, "registry.tgz");
    writeFileSync(tarball, value.tarball);
    const args = {
      stageReceipt: value.stageReceipt,
      expectedStageReceiptDigest: value.stageReceiptDigest,
      approvalAttestation: value.approvalAttestation,
      trustPolicy: value.trustPolicy,
      registryMetadata: {
        name: PACKAGE_NAME,
        version: VERSION,
        dist: {
          shasum: sha1(value.tarball),
          integrity: integrity(value.tarball),
        },
      },
      registryTarball: tarball,
      currentLatest: VERSION,
      actor: "Unobtainiumrock",
      workflowRunId: 124,
      workflowRunAttempt: 1,
      releaseSha: RELEASE_SHA,
      now: () => APPROVAL_NOW,
    };
    mutate(args);
    assert.throws(() => verifyApprovedStage(args), expected);
  });
}

test("command manifest binds the exact immutable staging command files", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  const command = join(value.root, "command");
  mkdirSync(command);
  mkdirSync(join(command, "scripts"));
  writeFileSync(
    join(command, "authorization.json"),
    canonicalJson(value.authorization),
  );
  writeFileSync(join(command, "npm-package.tgz"), value.tarball);
  writeFileSync(join(command, "plan.json"), canonicalJson(value.plan));
  writeFileSync(
    join(command, "selected-candidate.json"),
    canonicalJson(value.selectedCandidate),
  );
  writeFileSync(
    join(command, "trust-policy.json"),
    canonicalJson(value.trustPolicy),
  );
  for (const name of [
    "stage-npm-latest.mjs",
    "verify-exact-candidate.mjs",
    "verify-registry-transition.mjs",
  ]) {
    writeFileSync(
      join(command, "scripts", name),
      readFileSync(new URL(`../scripts/${name}`, import.meta.url)),
    );
  }
  const output = join(command, "command-manifest.json");
  const created = createCommandManifest(command, output);
  assert.equal(created.manifest.schemaVersion, COMMAND_MANIFEST_SCHEMA);
  assert.deepEqual(
    verifyCommandManifest(command, created.manifestDigest),
    created.manifest,
  );
  assert.doesNotThrow(() =>
    execFileSync(
      "node",
      [
        join(command, "scripts", "stage-npm-latest.mjs"),
        "verify-command-manifest",
        "--directory",
        command,
        "--expected-digest",
        created.manifestDigest,
      ],
      { cwd: value.root, stdio: "pipe" },
    ),
  );
  writeFileSync(join(command, "plan.json"), "changed\n");
  assert.throws(
    () => verifyCommandManifest(command, created.manifestDigest),
    /plan.json differs/,
  );
});
