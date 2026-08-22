#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PACKAGE_REPOSITORY,
  SOURCE_REPOSITORY,
  packageManifestFromTarball,
} from "./verify-exact-candidate.mjs";
import { canonicalJson } from "./verify-registry-transition.mjs";

export const PACKAGE_NAME = "@sift-wiki/q";
export const RELEASE_REPOSITORY = "Sift-wiki/sift-q-release";
export const RELEASE_REPOSITORY_ID = 1_341_269_682;
export const STAGE_WORKFLOW_PATH = ".github/workflows/stage-npm-latest.yml";
export const APPROVAL_WORKFLOW_PATH =
  ".github/workflows/verify-npm-stage-approval.yml";
export const STAGE_BINDING_SCHEMA = "sift-q-npm-stage-binding/v1";
export const SIGNED_STAGE_AUTHORIZATION_SCHEMA =
  "sift-q-npm-signed-stage-authorization/v1";
export const OWNER_TRUST_SCHEMA = "sift-q-npm-owner-trust/v1";
export const STAGE_PLAN_SCHEMA = "sift-q-npm-stage-plan/v1";
export const STAGE_RESULT_SCHEMA = "sift-q-npm-stage-result/v1";
export const SIGNED_APPROVAL_ATTESTATION_SCHEMA =
  "sift-q-npm-signed-stage-approval/v1";
export const APPROVAL_RESULT_SCHEMA = "sift-q-npm-approval-result/v1";
export const COMMAND_MANIFEST_SCHEMA = "sift-q-npm-stage-command-manifest/v1";
export const ALLOWED_PRODUCTION_ACTORS = Object.freeze([
  "Unobtainiumrock",
  "goodnight000",
]);

const GIT_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]{86}==$/;
const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const IDENTIFIER = /^[A-Za-z0-9._-]{16,128}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,128}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_AUTHORIZATION_MS = 15 * 60 * 1000;
const MAX_APPROVAL_ATTESTATION_MS = 60 * 60 * 1000;
const MIN_STAGE_AUTHORITY_REMAINING_MS = 2 * 60 * 1000;
const COMMAND_FILES = Object.freeze([
  "authorization.json",
  "npm-package.tgz",
  "plan.json",
  "scripts/stage-npm-latest.mjs",
  "scripts/verify-exact-candidate.mjs",
  "scripts/verify-registry-transition.mjs",
  "selected-candidate.json",
  "trust-policy.json",
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys, label) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} is invalid`,
  );
  invariant(
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort()),
    `${label} fields differ`,
  );
  return value;
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sha1(bytes) {
  return createHash("sha1").update(bytes).digest("hex");
}

function integrity(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

function regularFile(path, label) {
  const stat = lstatSync(resolve(path));
  invariant(
    stat.isFile() && !stat.isSymbolicLink(),
    `${label} is not a regular file`,
  );
  invariant(
    stat.size > 0 && stat.size <= MAX_INPUT_BYTES,
    `${label} size differs`,
  );
  return stat;
}

function jsonFile(path, label) {
  const input = resolve(path);
  regularFile(input, label);
  try {
    return JSON.parse(readFileSync(input, "utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function writeExclusive(path, value) {
  const output = resolve(path);
  const bytes = canonicalJson(value);
  const descriptor = openSync(output, "wx", 0o600);
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const directory = openSync(dirname(output), "r");
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
  return sha256(bytes);
}

function positiveInteger(value, label) {
  invariant(/^[1-9][0-9]*$/.test(String(value)), `${label} is invalid`);
  const result = Number(value);
  invariant(Number.isSafeInteger(result), `${label} is invalid`);
  return result;
}

function stableVersion(value, label) {
  invariant(
    typeof value === "string" && STABLE_VERSION.test(value),
    `${label} is not a stable version`,
  );
  return value;
}

function assertStrictlyNewerVersion(version, current, label = "stage version") {
  const candidate = stableVersion(version, label)
    .split(".")
    .map((part) => BigInt(part));
  const baseline = stableVersion(current, "current latest")
    .split(".")
    .map((part) => BigInt(part));
  const comparison =
    candidate[0] - baseline[0] ||
    candidate[1] - baseline[1] ||
    candidate[2] - baseline[2];
  invariant(comparison > 0n, `${label} must strictly advance current latest`);
}

function validateSelectedCandidate(candidate, tarball) {
  exactKeys(
    candidate,
    [
      "candidateReceiptDigest",
      "currentMainSha",
      "runAttempt",
      "runId",
      "sourceSha",
      "tarballDigest",
      "tarballSha256",
      "treeSha",
      "version",
    ],
    "selected candidate",
  );
  invariant(
    SHA256.test(candidate.candidateReceiptDigest) &&
      GIT_SHA.test(candidate.currentMainSha) &&
      GIT_SHA.test(candidate.sourceSha) &&
      GIT_SHA.test(candidate.treeSha) &&
      SHA256.test(candidate.tarballDigest) &&
      candidate.tarballSha256 ===
        candidate.tarballDigest.slice("sha256:".length),
    "selected candidate identity differs",
  );
  positiveInteger(candidate.runId, "candidate run id");
  positiveInteger(candidate.runAttempt, "candidate run attempt");
  stableVersion(candidate.version, "candidate version");
  invariant(
    sha256(tarball) === candidate.tarballDigest,
    "selected candidate tarball bytes differ",
  );
  const manifest = packageManifestFromTarball(tarball);
  invariant(
    manifest.name === PACKAGE_NAME && manifest.version === candidate.version,
    "selected candidate package identity differs",
  );
  invariant(
    JSON.stringify(manifest.repository) === JSON.stringify(PACKAGE_REPOSITORY),
    "selected candidate repository differs",
  );
  return candidate;
}

export function stageBindingFor({
  selectedCandidate,
  tarball,
  releaseSha,
  expectedLatestBefore,
  transferPublicKeySpkiSha256,
}) {
  const candidate = validateSelectedCandidate(selectedCandidate, tarball);
  invariant(GIT_SHA.test(releaseSha), "release SHA is invalid");
  invariant(
    SHA256.test(transferPublicKeySpkiSha256),
    "transfer public key SPKI fingerprint is invalid",
  );
  stableVersion(expectedLatestBefore, "expected latest");
  assertStrictlyNewerVersion(candidate.version, expectedLatestBefore);
  return {
    schemaVersion: STAGE_BINDING_SCHEMA,
    candidateReceiptDigest: candidate.candidateReceiptDigest,
    candidateRunAttempt: candidate.runAttempt,
    candidateRunId: candidate.runId,
    expectedLatestBefore,
    packageName: PACKAGE_NAME,
    releaseRepository: RELEASE_REPOSITORY,
    releaseRepositoryId: RELEASE_REPOSITORY_ID,
    releaseSha,
    sourceRepository: SOURCE_REPOSITORY,
    sourceSha: candidate.sourceSha,
    stageWorkflowPath: STAGE_WORKFLOW_PATH,
    tag: "latest",
    tarballDigest: candidate.tarballDigest,
    transferPublicKeySpkiSha256,
    treeSha: candidate.treeSha,
    version: candidate.version,
  };
}

function validateBinding(binding) {
  exactKeys(
    binding,
    [
      "candidateReceiptDigest",
      "candidateRunAttempt",
      "candidateRunId",
      "expectedLatestBefore",
      "packageName",
      "releaseRepository",
      "releaseRepositoryId",
      "releaseSha",
      "schemaVersion",
      "sourceRepository",
      "sourceSha",
      "stageWorkflowPath",
      "tag",
      "tarballDigest",
      "transferPublicKeySpkiSha256",
      "treeSha",
      "version",
    ],
    "stage binding",
  );
  invariant(
    binding.schemaVersion === STAGE_BINDING_SCHEMA &&
      binding.packageName === PACKAGE_NAME &&
      binding.releaseRepository === RELEASE_REPOSITORY &&
      binding.releaseRepositoryId === RELEASE_REPOSITORY_ID &&
      binding.sourceRepository === SOURCE_REPOSITORY &&
      binding.stageWorkflowPath === STAGE_WORKFLOW_PATH &&
      binding.tag === "latest" &&
      SHA256.test(binding.candidateReceiptDigest) &&
      SHA256.test(binding.tarballDigest) &&
      SHA256.test(binding.transferPublicKeySpkiSha256) &&
      GIT_SHA.test(binding.releaseSha) &&
      GIT_SHA.test(binding.sourceSha) &&
      GIT_SHA.test(binding.treeSha),
    "stage binding identity differs",
  );
  positiveInteger(binding.candidateRunId, "candidate run id");
  positiveInteger(binding.candidateRunAttempt, "candidate run attempt");
  stableVersion(binding.expectedLatestBefore, "expected latest");
  stableVersion(binding.version, "stage version");
  assertStrictlyNewerVersion(binding.version, binding.expectedLatestBefore);
  return binding;
}

function transferKeyFingerprint(key, label) {
  invariant(
    key.asymmetricKeyType === "rsa" &&
      (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 3072,
    `${label} is not RSA 3072-bit-or-larger`,
  );
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  return sha256(publicKey.export({ format: "der", type: "spki" }));
}

export function transferPublicKeySpkiSha256(publicKeyPem) {
  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new Error("transfer public key is invalid");
  }
  return transferKeyFingerprint(key, "transfer public key");
}

export function transferPrivateKeySpkiSha256(privateKeyPem) {
  let key;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw new Error("transfer private key is invalid");
  }
  return transferKeyFingerprint(key, "transfer private key");
}

function validateTrustPolicy(policy) {
  exactKeys(policy, ["keys", "schemaVersion"], "owner trust policy");
  invariant(
    policy.schemaVersion === OWNER_TRUST_SCHEMA &&
      Array.isArray(policy.keys) &&
      policy.keys.length >= 1 &&
      policy.keys.length <= 4,
    "owner trust policy identity differs",
  );
  const keyIds = new Set();
  const fingerprints = new Set();
  const githubActors = new Set();
  const npmUsernames = new Set();
  for (const key of policy.keys) {
    exactKeys(
      key,
      ["algorithm", "githubActor", "keyId", "npmUsername", "publicKeyPem"],
      "owner trust key",
    );
    invariant(
      key.algorithm === "Ed25519" &&
        KEY_ID.test(key.keyId) &&
        ALLOWED_PRODUCTION_ACTORS.includes(key.githubActor) &&
        ["unobtainiumrock", "goodnight00"].includes(key.npmUsername) &&
        typeof key.publicKeyPem === "string",
      "owner trust key identity differs",
    );
    let publicKey;
    try {
      publicKey = createPublicKey(key.publicKeyPem);
    } catch {
      throw new Error("owner trust public key is invalid");
    }
    invariant(
      publicKey.asymmetricKeyType === "ed25519",
      "owner trust key is not Ed25519",
    );
    const fingerprint = sha256(
      publicKey.export({ format: "der", type: "spki" }),
    );
    invariant(!keyIds.has(key.keyId), "owner trust key ID is duplicated");
    invariant(
      !fingerprints.has(fingerprint),
      "owner trust key material is duplicated",
    );
    invariant(
      !githubActors.has(key.githubActor),
      "owner GitHub actor is duplicated",
    );
    invariant(
      !npmUsernames.has(key.npmUsername),
      "owner npm username is duplicated",
    );
    keyIds.add(key.keyId);
    fingerprints.add(fingerprint);
    githubActors.add(key.githubActor);
    npmUsernames.add(key.npmUsername);
  }
  return policy;
}

function verifyEnvelope({
  envelope,
  trustPolicy,
  schemaVersion,
  idField,
  bindingLabel,
  maxWindowMs,
  now,
}) {
  exactKeys(
    envelope,
    [
      "algorithm",
      "authorizedAt",
      "binding",
      "expiresAt",
      idField,
      "keyId",
      "schemaVersion",
      "signature",
    ],
    bindingLabel,
  );
  invariant(
    envelope.schemaVersion === schemaVersion &&
      envelope.algorithm === "Ed25519" &&
      IDENTIFIER.test(envelope[idField]) &&
      KEY_ID.test(envelope.keyId) &&
      /^[A-Za-z0-9+/]{86}==$/.test(envelope.signature ?? ""),
    `${bindingLabel} identity differs`,
  );
  const authorizedAt = Date.parse(envelope.authorizedAt);
  const expiresAt = Date.parse(envelope.expiresAt);
  const observedAt = now().getTime();
  invariant(
    Number.isFinite(authorizedAt) &&
      Number.isFinite(expiresAt) &&
      expiresAt > authorizedAt &&
      expiresAt - authorizedAt <= maxWindowMs,
    `${bindingLabel} time window is invalid`,
  );
  invariant(authorizedAt <= observedAt, `${bindingLabel} is future-dated`);
  invariant(observedAt <= expiresAt, `${bindingLabel} is expired`);
  const policy = validateTrustPolicy(trustPolicy);
  const key = policy.keys.find((entry) => entry.keyId === envelope.keyId);
  invariant(key !== undefined, `${bindingLabel} signer is not trusted`);
  const body = structuredClone(envelope);
  delete body.signature;
  invariant(
    verifySignature(
      null,
      Buffer.from(canonicalJson(body)),
      createPublicKey(key.publicKeyPem),
      Buffer.from(envelope.signature, "base64"),
    ),
    `${bindingLabel} signature is invalid`,
  );
  return { authorizedAt, expiresAt, key };
}

export function verifyTransferRecipient({
  authorization,
  trustPolicy,
  publicKeyPem,
  privateKeyPem,
  now = () => new Date(),
}) {
  const times = verifyEnvelope({
    envelope: authorization,
    trustPolicy,
    schemaVersion: SIGNED_STAGE_AUTHORIZATION_SCHEMA,
    idField: "authorizationId",
    bindingLabel: "signed stage authorization",
    maxWindowMs: MAX_AUTHORIZATION_MS,
    now,
  });
  const binding = validateBinding(authorization.binding);
  const fingerprint = transferPublicKeySpkiSha256(publicKeyPem);
  invariant(
    fingerprint === binding.transferPublicKeySpkiSha256,
    "transfer public key differs from signed stage authority",
  );
  if (privateKeyPem !== undefined) {
    invariant(
      transferPrivateKeySpkiSha256(privateKeyPem) === fingerprint,
      "transfer private key differs from signed stage authority",
    );
  }
  return {
    authorizedAt: times.authorizedAt,
    expiresAt: times.expiresAt,
    transferPublicKeySpkiSha256: fingerprint,
  };
}

export function prepareStage({
  authorization,
  trustPolicy,
  selectedCandidate,
  tarball,
  releaseSha,
  currentLatest,
  versionIsAbsent,
  transferPublicKeyPem,
  now = () => new Date(),
}) {
  const observedNow = now();
  const times = verifyTransferRecipient({
    authorization,
    trustPolicy,
    publicKeyPem: transferPublicKeyPem,
    now: () => observedNow,
  });
  const binding = validateBinding(authorization.binding);
  const expected = stageBindingFor({
    selectedCandidate,
    tarball,
    releaseSha,
    expectedLatestBefore: binding.expectedLatestBefore,
    transferPublicKeySpkiSha256: times.transferPublicKeySpkiSha256,
  });
  invariant(
    canonicalJson(binding) === canonicalJson(expected),
    "signed stage binding differs from selected candidate",
  );
  invariant(
    currentLatest === binding.expectedLatestBefore,
    "current latest differs from signed stage precondition",
  );
  invariant(versionIsAbsent === true, "stage version already exists publicly");
  const body = {
    schemaVersion: STAGE_PLAN_SCHEMA,
    authorization: {
      authorizationId: authorization.authorizationId,
      expiresAt: authorization.expiresAt,
      keyId: authorization.keyId,
      receiptDigest: sha256(canonicalJson(authorization)),
      verifiedAt: observedNow.toISOString(),
    },
    binding,
    release: {
      repository: RELEASE_REPOSITORY,
      repositoryId: RELEASE_REPOSITORY_ID,
      sha: releaseSha,
      workflowPath: STAGE_WORKFLOW_PATH,
    },
  };
  invariant(
    Date.parse(body.authorization.verifiedAt) <= times.expiresAt,
    "stage authorization expired during verification",
  );
  return { ...body, planDigest: sha256(canonicalJson(body)) };
}

function validatePlan(plan) {
  exactKeys(
    plan,
    ["authorization", "binding", "planDigest", "release", "schemaVersion"],
    "stage plan",
  );
  const body = structuredClone(plan);
  delete body.planDigest;
  invariant(
    plan.schemaVersion === STAGE_PLAN_SCHEMA &&
      plan.planDigest === sha256(canonicalJson(body)),
    "stage plan identity differs",
  );
  validateBinding(plan.binding);
  return plan;
}

export function assertStageAuthorityRemaining(plan, now = () => new Date()) {
  validatePlan(plan);
  const remaining = Date.parse(plan.authorization.expiresAt) - now().getTime();
  invariant(
    remaining >= MIN_STAGE_AUTHORITY_REMAINING_MS,
    "stage authorization has insufficient remaining validity",
  );
  return { remainingMs: remaining };
}

function validateStageOutput(stageOutput, tarball, plan) {
  exactKeys(stageOutput, [PACKAGE_NAME], "npm stage output");
  const item = stageOutput[PACKAGE_NAME];
  invariant(
    item !== null && typeof item === "object",
    "npm stage result is invalid",
  );
  invariant(UUID.test(item.stageId ?? ""), "npm stage ID is invalid");
  invariant(
    item.name === PACKAGE_NAME && item.version === plan.binding.version,
    "npm staged package identity differs",
  );
  const expectedShasum = sha1(tarball);
  const expectedIntegrity = integrity(tarball);
  invariant(
    SHA1.test(item.shasum ?? "") && item.shasum === expectedShasum,
    "npm staged shasum differs",
  );
  invariant(
    SHA512_INTEGRITY.test(item.integrity ?? "") &&
      item.integrity === expectedIntegrity,
    "npm staged integrity differs",
  );
  return {
    integrity: item.integrity,
    shasum: item.shasum,
    stageId: item.stageId.toLowerCase(),
  };
}

export function recordStageResult({
  plan,
  selectedCandidate,
  tarball,
  stageOutput,
  actor,
  workflowRunId,
  workflowRunAttempt,
  commandArtifactName,
  commandManifestDigest,
  replayArtifactId,
  stagedAt = () => new Date(),
}) {
  validatePlan(plan);
  validateSelectedCandidate(selectedCandidate, tarball);
  invariant(
    sha256(tarball) === plan.binding.tarballDigest,
    "staged tarball differs from plan",
  );
  invariant(
    ALLOWED_PRODUCTION_ACTORS.includes(actor),
    "stage actor is not a production owner",
  );
  invariant(
    commandArtifactName ===
      `npm-stage-authorization-${plan.authorization.authorizationId}`,
    "stage command artifact identity differs",
  );
  invariant(
    SHA256.test(commandManifestDigest),
    "stage command manifest digest is invalid",
  );
  const staged = validateStageOutput(stageOutput, tarball, plan);
  const recordedAt = stagedAt().toISOString();
  invariant(
    Number.isFinite(Date.parse(recordedAt)),
    "stage result time is invalid",
  );
  return {
    schemaVersion: STAGE_RESULT_SCHEMA,
    outcome: "staged-awaiting-interactive-2fa",
    recordedAt,
    actor,
    approval: {
      allowedNpmApprovers: ["unobtainiumrock", "goodnight00"],
      cliCommand: `npm stage approve ${staged.stageId}`,
      requirement: "interactive-npm-2fa",
    },
    authorization: structuredClone(plan.authorization),
    binding: structuredClone(plan.binding),
    command: {
      artifactName: commandArtifactName,
      manifestDigest: commandManifestDigest,
      replayArtifactId: positiveInteger(
        replayArtifactId,
        "stage replay artifact id",
      ),
    },
    npm: {
      integrity: staged.integrity,
      shasum: staged.shasum,
      stageId: staged.stageId,
      tag: "latest",
    },
    release: {
      repository: RELEASE_REPOSITORY,
      repositoryId: RELEASE_REPOSITORY_ID,
      sha: plan.release.sha,
      workflowPath: STAGE_WORKFLOW_PATH,
      workflowRunAttempt: positiveInteger(
        workflowRunAttempt,
        "stage workflow run attempt",
      ),
      workflowRunId: positiveInteger(workflowRunId, "stage workflow run id"),
    },
  };
}

function validateStageReceipt(receipt) {
  exactKeys(
    receipt,
    [
      "actor",
      "approval",
      "authorization",
      "binding",
      "command",
      "npm",
      "outcome",
      "recordedAt",
      "release",
      "schemaVersion",
    ],
    "stage receipt",
  );
  invariant(
    receipt.schemaVersion === STAGE_RESULT_SCHEMA &&
      receipt.outcome === "staged-awaiting-interactive-2fa" &&
      UUID.test(receipt.npm?.stageId ?? "") &&
      receipt.npm.tag === "latest" &&
      SHA256.test(receipt.binding?.tarballDigest ?? ""),
    "stage receipt identity differs",
  );
  exactKeys(
    receipt.approval,
    ["allowedNpmApprovers", "cliCommand", "requirement"],
    "stage receipt approval handoff",
  );
  exactKeys(
    receipt.authorization,
    ["authorizationId", "expiresAt", "keyId", "receiptDigest", "verifiedAt"],
    "stage receipt authorization",
  );
  exactKeys(
    receipt.command,
    ["artifactName", "manifestDigest", "replayArtifactId"],
    "stage receipt command",
  );
  exactKeys(
    receipt.npm,
    ["integrity", "shasum", "stageId", "tag"],
    "stage receipt npm result",
  );
  exactKeys(
    receipt.release,
    [
      "repository",
      "repositoryId",
      "sha",
      "workflowPath",
      "workflowRunAttempt",
      "workflowRunId",
    ],
    "stage receipt release",
  );
  invariant(
    canonicalJson(receipt.approval.allowedNpmApprovers) ===
      canonicalJson(["unobtainiumrock", "goodnight00"]) &&
      receipt.approval.requirement === "interactive-npm-2fa" &&
      receipt.approval.cliCommand ===
        `npm stage approve ${receipt.npm.stageId}` &&
      Number.isFinite(Date.parse(receipt.recordedAt)) &&
      ALLOWED_PRODUCTION_ACTORS.includes(receipt.actor) &&
      SHA1.test(receipt.npm.shasum) &&
      SHA512_INTEGRITY.test(receipt.npm.integrity) &&
      receipt.release.repository === RELEASE_REPOSITORY &&
      receipt.release.repositoryId === RELEASE_REPOSITORY_ID &&
      receipt.release.workflowPath === STAGE_WORKFLOW_PATH &&
      receipt.release.sha === receipt.binding.releaseSha,
    "stage receipt approval handoff differs",
  );
  positiveInteger(
    receipt.command.replayArtifactId,
    "stage receipt replay artifact id",
  );
  positiveInteger(
    receipt.release.workflowRunAttempt,
    "stage receipt workflow run attempt",
  );
  positiveInteger(
    receipt.release.workflowRunId,
    "stage receipt workflow run id",
  );
  validateBinding(receipt.binding);
  return receipt;
}

export function verifyApprovedStage({
  stageReceipt,
  expectedStageReceiptDigest,
  approvalAttestation,
  trustPolicy,
  registryMetadata,
  registryTarball,
  currentLatest,
  actor,
  workflowRunId,
  workflowRunAttempt,
  releaseSha,
  now = () => new Date(),
}) {
  const receipt = validateStageReceipt(stageReceipt);
  invariant(
    sha256(canonicalJson(receipt)) === expectedStageReceiptDigest &&
      SHA256.test(expectedStageReceiptDigest),
    "stage receipt digest differs",
  );
  const approvalTimes = verifyEnvelope({
    envelope: approvalAttestation,
    trustPolicy,
    schemaVersion: SIGNED_APPROVAL_ATTESTATION_SCHEMA,
    idField: "approvalId",
    bindingLabel: "signed approval attestation",
    maxWindowMs: MAX_APPROVAL_ATTESTATION_MS,
    now,
  });
  exactKeys(
    approvalAttestation.binding,
    [
      "approvalMethod",
      "approvedBy",
      "expectedLatestAfter",
      "packageName",
      "stageId",
      "stageReceiptDigest",
      "tag",
      "tarballDigest",
      "version",
    ],
    "approval attestation binding",
  );
  const expectedBinding = {
    approvalMethod: approvalAttestation.binding.approvalMethod,
    approvedBy: approvalAttestation.binding.approvedBy,
    expectedLatestAfter: receipt.binding.version,
    packageName: PACKAGE_NAME,
    stageId: receipt.npm.stageId,
    stageReceiptDigest: expectedStageReceiptDigest,
    tag: "latest",
    tarballDigest: receipt.binding.tarballDigest,
    version: receipt.binding.version,
  };
  invariant(
    approvalAttestation.binding.approvalMethod === "npmjs.com" ||
      approvalAttestation.binding.approvalMethod === "npm-cli",
    "approval method is invalid",
  );
  invariant(
    ["unobtainiumrock", "goodnight00"].includes(
      approvalAttestation.binding.approvedBy,
    ),
    "npm approver is not Nicholas or Charles",
  );
  invariant(
    approvalTimes.key.npmUsername === approvalAttestation.binding.approvedBy,
    "approval signer is not the attested npm approver",
  );
  invariant(
    approvalTimes.authorizedAt > Date.parse(receipt.recordedAt),
    "approval attestation predates the npm stage",
  );
  invariant(
    canonicalJson(approvalAttestation.binding) ===
      canonicalJson(expectedBinding),
    "signed approval binding differs from stage receipt",
  );
  invariant(
    currentLatest === receipt.binding.version,
    "latest does not select approved version",
  );
  invariant(
    ALLOWED_PRODUCTION_ACTORS.includes(actor),
    "approval verifier actor is not a production owner",
  );
  invariant(
    releaseSha === receipt.release.sha,
    "approval verifier release SHA differs",
  );
  invariant(
    registryMetadata?.name === PACKAGE_NAME &&
      registryMetadata.version === receipt.binding.version,
    "approved registry package identity differs",
  );
  const bytes = readFileSync(registryTarball);
  invariant(
    sha256(bytes) === receipt.binding.tarballDigest,
    "approved registry bytes differ",
  );
  invariant(
    registryMetadata.dist?.shasum === sha1(bytes) &&
      registryMetadata.dist?.integrity === integrity(bytes),
    "approved registry metadata differs from bytes",
  );
  validateSelectedCandidate(
    {
      candidateReceiptDigest: receipt.binding.candidateReceiptDigest,
      currentMainSha: receipt.binding.sourceSha,
      runAttempt: receipt.binding.candidateRunAttempt,
      runId: receipt.binding.candidateRunId,
      sourceSha: receipt.binding.sourceSha,
      tarballDigest: receipt.binding.tarballDigest,
      tarballSha256: receipt.binding.tarballDigest.slice("sha256:".length),
      treeSha: receipt.binding.treeSha,
      version: receipt.binding.version,
    },
    bytes,
  );
  return {
    schemaVersion: APPROVAL_RESULT_SCHEMA,
    outcome: "approved-and-registry-verified",
    recordedAt: now().toISOString(),
    verification: {
      dispatchedBy: actor,
      statement:
        "registry effect verified; npm approver identity is owner-attested and remains auditable by npm",
    },
    approval: {
      approvalId: approvalAttestation.approvalId,
      approvalMethod: approvalAttestation.binding.approvalMethod,
      approvedBy: approvalAttestation.binding.approvedBy,
      attestationDigest: sha256(canonicalJson(approvalAttestation)),
      keyId: approvalAttestation.keyId,
    },
    npm: {
      integrity: registryMetadata.dist.integrity,
      latest: currentLatest,
      packageName: PACKAGE_NAME,
      shasum: registryMetadata.dist.shasum,
      stageId: receipt.npm.stageId,
      tarballDigest: receipt.binding.tarballDigest,
      version: receipt.binding.version,
    },
    release: {
      repository: RELEASE_REPOSITORY,
      repositoryId: RELEASE_REPOSITORY_ID,
      sha: releaseSha,
      workflowPath: APPROVAL_WORKFLOW_PATH,
      workflowRunAttempt: positiveInteger(
        workflowRunAttempt,
        "approval workflow run attempt",
      ),
      workflowRunId: positiveInteger(workflowRunId, "approval workflow run id"),
    },
    stageReceiptDigest: expectedStageReceiptDigest,
  };
}

function filesRecursively(root) {
  const files = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
      (a, b) => a.name.localeCompare(b.name, "en"),
    )) {
      const path = join(directory, entry.name);
      const name = relative(root, path).replaceAll("\\", "/");
      invariant(!entry.isSymbolicLink(), `command file ${name} is a symlink`);
      if (entry.isDirectory()) visit(path);
      else {
        invariant(entry.isFile(), `command file ${name} has unsupported type`);
        files.push(name);
      }
    }
  }
  visit(root);
  return files.sort();
}

export function createCommandManifest(directory, output) {
  const root = resolve(directory);
  const names = filesRecursively(root);
  invariant(
    JSON.stringify(names) === JSON.stringify([...COMMAND_FILES]),
    "stage command file set differs",
  );
  const files = names.map((name) => {
    const path = join(root, name);
    const stat = regularFile(path, `command file ${name}`);
    return { bytes: stat.size, digest: sha256(readFileSync(path)), name };
  });
  const manifest = { schemaVersion: COMMAND_MANIFEST_SCHEMA, files };
  return { manifest, manifestDigest: writeExclusive(output, manifest) };
}

export function verifyCommandManifest(directory, expectedDigest) {
  invariant(SHA256.test(expectedDigest), "command manifest digest is invalid");
  const root = resolve(directory);
  const names = filesRecursively(root);
  const expectedNames = [...COMMAND_FILES, "command-manifest.json"].sort();
  invariant(
    JSON.stringify(names) === JSON.stringify(expectedNames),
    "stage command directory differs",
  );
  const manifestPath = join(root, "command-manifest.json");
  invariant(
    sha256(readFileSync(manifestPath)) === expectedDigest,
    "command manifest bytes differ",
  );
  const manifest = jsonFile(manifestPath, "command manifest");
  exactKeys(manifest, ["files", "schemaVersion"], "command manifest");
  invariant(
    manifest.schemaVersion === COMMAND_MANIFEST_SCHEMA &&
      Array.isArray(manifest.files) &&
      manifest.files.length === COMMAND_FILES.length,
    "command manifest identity differs",
  );
  for (let index = 0; index < COMMAND_FILES.length; index += 1) {
    const entry = manifest.files[index];
    exactKeys(entry, ["bytes", "digest", "name"], "command manifest entry");
    invariant(
      entry.name === COMMAND_FILES[index],
      "command manifest order differs",
    );
    const path = join(root, entry.name);
    const stat = regularFile(path, `command file ${entry.name}`);
    invariant(
      stat.size === entry.bytes && sha256(readFileSync(path)) === entry.digest,
      `command file ${entry.name} differs`,
    );
  }
  return manifest;
}

function parseArguments(argv, allowed) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    invariant(
      key?.startsWith("--") && argv[index + 1] !== undefined,
      "stage arguments are invalid",
    );
    invariant(allowed.has(key), `unknown argument ${key}`);
    invariant(!values.has(key), `duplicate argument ${key}`);
    values.set(key, argv[index + 1]);
  }
  return values;
}

function required(values, key) {
  const value = values.get(key);
  invariant(value !== undefined && value !== "", `missing ${key}`);
  return value;
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (command === "verify-transfer-recipient") {
    const values = parseArguments(
      rest,
      new Set([
        "--authorization",
        "--private-key",
        "--public-key",
        "--trust-policy",
      ]),
    );
    const privateKeyPath = values.get("--private-key");
    const result = verifyTransferRecipient({
      authorization: jsonFile(
        required(values, "--authorization"),
        "stage authorization",
      ),
      trustPolicy: jsonFile(
        required(values, "--trust-policy"),
        "owner trust policy",
      ),
      publicKeyPem: readFileSync(required(values, "--public-key"), "utf8"),
      privateKeyPem:
        privateKeyPath === undefined
          ? undefined
          : readFileSync(privateKeyPath, "utf8"),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (command === "prepare") {
    const values = parseArguments(
      rest,
      new Set([
        "--authorization",
        "--current-latest",
        "--output",
        "--release-sha",
        "--selected-candidate",
        "--tarball",
        "--transfer-public-key",
        "--trust-policy",
        "--version-is-absent",
      ]),
    );
    const plan = prepareStage({
      authorization: jsonFile(
        required(values, "--authorization"),
        "stage authorization",
      ),
      trustPolicy: jsonFile(
        required(values, "--trust-policy"),
        "owner trust policy",
      ),
      selectedCandidate: jsonFile(
        required(values, "--selected-candidate"),
        "selected candidate",
      ),
      tarball: readFileSync(required(values, "--tarball")),
      releaseSha: required(values, "--release-sha"),
      currentLatest: required(values, "--current-latest"),
      versionIsAbsent: required(values, "--version-is-absent") === "true",
      transferPublicKeyPem: readFileSync(
        required(values, "--transfer-public-key"),
        "utf8",
      ),
    });
    const planFileDigest = writeExclusive(required(values, "--output"), plan);
    process.stdout.write(
      `${JSON.stringify({ authorizationId: plan.authorization.authorizationId, planDigest: plan.planDigest, planFileDigest, version: plan.binding.version })}\n`,
    );
    return;
  }
  if (command === "check-authority") {
    const values = parseArguments(rest, new Set(["--plan"]));
    process.stdout.write(
      `${JSON.stringify(assertStageAuthorityRemaining(jsonFile(required(values, "--plan"), "stage plan")))}\n`,
    );
    return;
  }
  if (command === "record-stage") {
    const values = parseArguments(
      rest,
      new Set([
        "--actor",
        "--command-artifact-name",
        "--command-manifest-digest",
        "--output",
        "--plan",
        "--replay-artifact-id",
        "--selected-candidate",
        "--stage-output",
        "--tarball",
        "--workflow-run-attempt",
        "--workflow-run-id",
      ]),
    );
    const result = recordStageResult({
      plan: jsonFile(required(values, "--plan"), "stage plan"),
      selectedCandidate: jsonFile(
        required(values, "--selected-candidate"),
        "selected candidate",
      ),
      tarball: readFileSync(required(values, "--tarball")),
      stageOutput: jsonFile(
        required(values, "--stage-output"),
        "npm stage output",
      ),
      actor: required(values, "--actor"),
      workflowRunId: required(values, "--workflow-run-id"),
      workflowRunAttempt: required(values, "--workflow-run-attempt"),
      commandArtifactName: required(values, "--command-artifact-name"),
      commandManifestDigest: required(values, "--command-manifest-digest"),
      replayArtifactId: required(values, "--replay-artifact-id"),
    });
    const receiptDigest = writeExclusive(required(values, "--output"), result);
    process.stdout.write(
      `${JSON.stringify({ receiptDigest, stageId: result.npm.stageId })}\n`,
    );
    return;
  }
  if (command === "verify-approval") {
    const values = parseArguments(
      rest,
      new Set([
        "--actor",
        "--approval-attestation",
        "--current-latest",
        "--output",
        "--registry-metadata",
        "--registry-tarball",
        "--release-sha",
        "--stage-receipt",
        "--stage-receipt-digest",
        "--trust-policy",
        "--workflow-run-attempt",
        "--workflow-run-id",
      ]),
    );
    const result = verifyApprovedStage({
      stageReceipt: jsonFile(
        required(values, "--stage-receipt"),
        "stage receipt",
      ),
      expectedStageReceiptDigest: required(values, "--stage-receipt-digest"),
      approvalAttestation: jsonFile(
        required(values, "--approval-attestation"),
        "approval attestation",
      ),
      trustPolicy: jsonFile(
        required(values, "--trust-policy"),
        "owner trust policy",
      ),
      registryMetadata: jsonFile(
        required(values, "--registry-metadata"),
        "registry metadata",
      ),
      registryTarball: required(values, "--registry-tarball"),
      currentLatest: required(values, "--current-latest"),
      actor: required(values, "--actor"),
      workflowRunId: required(values, "--workflow-run-id"),
      workflowRunAttempt: required(values, "--workflow-run-attempt"),
      releaseSha: required(values, "--release-sha"),
    });
    const receiptDigest = writeExclusive(required(values, "--output"), result);
    process.stdout.write(
      `${JSON.stringify({ approvalId: result.approval.approvalId, receiptDigest })}\n`,
    );
    return;
  }
  if (command === "create-command-manifest") {
    const values = parseArguments(rest, new Set(["--directory", "--output"]));
    const result = createCommandManifest(
      required(values, "--directory"),
      required(values, "--output"),
    );
    process.stdout.write(
      `${JSON.stringify({ manifestDigest: result.manifestDigest })}\n`,
    );
    return;
  }
  if (command === "verify-command-manifest") {
    const values = parseArguments(
      rest,
      new Set(["--directory", "--expected-digest"]),
    );
    verifyCommandManifest(
      required(values, "--directory"),
      required(values, "--expected-digest"),
    );
    process.stdout.write('{"verified":true}\n');
    return;
  }
  throw new Error(`unknown command ${command ?? ""}`);
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(
      `npm staged release refused: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}
