#!/usr/bin/env node
// Vendored verifier from Sift-wiki/sift-q-refactor@4647c4cc8cd665f91385fcf248219c27c99870a9.
// This checked-in public copy is release authority; candidate source may not replace it.
import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { gunzipSync } from "node:zlib";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  PRODUCTION_PROMOTION_REQUEST_SCHEMA,
  PRODUCTION_PROMOTION_SELECTION_SCHEMA,
  candidateReceiptDigest,
  selectProductionCandidate,
} from "./candidate-contract.mjs";
import { canonicalJson, sha256Digest } from "./readiness-contract.mjs";

export const NPM_OIDC_SELECTION_SCHEMA = "sift-q-npm-oidc-selection/v3";
export const NPM_REGISTRY_PLAN_SCHEMA = "sift-q-npm-registry-plan/v2";
export const NPM_PUBLICATION_RESULT_SCHEMA = "sift-q-npm-publication-result/v4";
export const NPM_REGISTRY_CANARY_SCHEMA = "sift-q-npm-registry-canary/v1";
export const SIGNED_NPM_REGISTRY_CANARY_SCHEMA =
  "sift-q-signed-npm-registry-canary/v1";
export const NPM_RUNTIME_CANARY_SCHEMA = "sift-q-npm-runtime-canary/v1";
export const SIGNED_NPM_RUNTIME_CANARY_SCHEMA =
  "sift-q-signed-npm-runtime-canary/v1";
export const NPM_PUBLISHER_LANDING_SCHEMA = "sift-q-npm-publisher-landing/v1";
export const SIGNED_NPM_PUBLISHER_LANDING_SCHEMA =
  "sift-q-signed-npm-publisher-landing/v1";

const CANONICAL_REPOSITORY = "Sift-wiki/sift-q-refactor";
const CANONICAL_REPOSITORY_ID = 1_329_084_838;
const CANONICAL_PACKAGE = "@sift-wiki/q";
const CANONICAL_PACKAGE_REPOSITORY = Object.freeze({
  type: "git",
  url: "git+https://github.com/Sift-wiki/sift-q-refactor.git",
});
const RELAY_REPOSITORY = "Sift-wiki/sift-q-release";
const RELAY_REPOSITORY_ID = 1_341_269_682;
const RELAY_WORKFLOW_ID = 339_025_463;
const CANDIDATE_WORKFLOW_PATH = ".github/workflows/deploy-development.yml";
const PUBLISH_WORKFLOW_PATH = ".github/workflows/publish-npm.yml";
const RELAY_ACTIVE_RUN_STATUSES = [
  "in_progress",
  "pending",
  "queued",
  "requested",
  "waiting",
];
const DEVELOPMENT_ENVIRONMENT_ID = "sift-q-development";
const PRODUCTION_ENVIRONMENT_ID = "sift-q-production";
const PRODUCTION_GITHUB_ENVIRONMENT = "production";
const ALLOWED_PRODUCTION_ACTORS = new Set(["Unobtainiumrock", "goodnight000"]);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const RUN_ID = /^[1-9][0-9]*$/;
const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const PACKAGE_NAME = /^@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/;
const AUTHORITY_KEYS = [
  "dispatchActor",
  "executingActor",
  "githubEnvironment",
  "landingTransitionReceiptDigest",
  "repository",
  "repositoryId",
  "workflowRef",
];
const SELECTION_KEYS = [
  "authority",
  "candidateSelection",
  "package",
  "schemaVersion",
  "selectionDigest",
];
const SELECTION_PACKAGE_KEYS = [
  "name",
  "runtimeCanaryReceiptDigest",
  "tarballBytes",
  "tarballDigest",
  "version",
];
const CANARY_ENVELOPE_KEYS = [
  "keyId",
  "payload",
  "schemaVersion",
  "signatureBase64",
];
const CANARY_PAYLOAD_KEYS = [
  "dryRun",
  "finishedAt",
  "homeIsolation",
  "install",
  "package",
  "repository",
  "schemaVersion",
  "source",
  "version",
];
const CANARY_PACKAGE_KEYS = ["name", "tarballDigest", "version"];
const CANARY_INSTALL_KEYS = [
  "command",
  "exitCode",
  "scriptsPolicy",
  "stderr",
  "stdout",
];
const CANARY_VERSION_KEYS = ["command", "exitCode", "stderr", "stdout"];
const CANARY_DRY_RUN_KEYS = [
  "command",
  "exitCode",
  "harness",
  "stderr",
  "stdout",
];
const SOURCE_KEYS = ["ref", "sha", "treeSha"];
const LOCK_KEYS = ["etag", "releaseError", "s3Uri", "state", "versionId"];
const LANDING_POLICY_KEYS = ["ownerKeyId", "ownerPublicKeySpkiBase64"];
const LANDING_PAYLOAD_KEYS = [
  "authorization",
  "evidenceDigests",
  "finishedAt",
  "landedSha",
  "repository",
  "repositoryId",
  "schemaVersion",
  "startedAt",
  "workflow",
];
const LANDING_AUTHORIZATION_KEYS = ["actor", "authorizedAt", "decisionDigest"];
const LANDING_EVIDENCE_KEYS = [
  "main",
  "repository",
  "runs",
  "workflow",
  "workflowBefore",
];
const LANDING_WORKFLOW_KEYS = [
  "id",
  "name",
  "path",
  "stateAfter",
  "stateBefore",
];
const PACKAGE_REPOSITORY_KEYS = ["type", "url"];
const REGISTRY_HANDOFF_POLICY_KEYS = [
  "lockUri",
  "receiptSigningKeyArn",
  "receiptSigningPublicKeySpkiBase64",
];
const PUBLICATION_RESULT_KEYS = [
  "authority",
  "boundaryEvidenceDigests",
  "candidateReceiptDigest",
  "currentMainDigest",
  "finishedAt",
  "handoff",
  "mutationLock",
  "outcome",
  "packageName",
  "productionEnvironmentId",
  "publisherSource",
  "registry",
  "repository",
  "run",
  "schemaVersion",
  "selectionDigest",
  "source",
  "startedAt",
  "tarballDigest",
  "transportAction",
  "version",
];
const PUBLICATION_REGISTRY_KEYS = [
  "latestVersion",
  "nextVersion",
  "registryCanaryDigest",
  "servedTarballDigest",
  "url",
];
const PUBLICATION_HANDOFF_KEYS = [
  "authority",
  "requiredOperation",
  "workflowMayPromoteLatest",
];

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

export function canonicalSiftQVersionOutput(version) {
  return `sift-q ${version}\n`;
}

function exactKeys(value, expected, label) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} invalid`,
  );
  invariant(
    canonicalJson(Object.keys(value).sort()) === canonicalJson(expected),
    `${label} keys drift`,
  );
}

function safeEqual(left, right) {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function digestBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function parseTime(value, label) {
  invariant(typeof value === "string", `${label} is missing`);
  const milliseconds = Date.parse(value);
  invariant(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    `${label} is invalid`,
  );
  return milliseconds;
}

function boundedText(value, label) {
  invariant(
    typeof value === "string" &&
      value.length <= 16_384 &&
      !value.includes("\0"),
    `${label} is invalid or unbounded`,
  );
  return value;
}

function validateSource(source, label) {
  exactKeys(source, SOURCE_KEYS, label);
  invariant(source.ref === "refs/heads/main", `${label} is not accepted main`);
  invariant(GIT_SHA.test(source.sha), `${label} SHA is invalid`);
  invariant(GIT_SHA.test(source.treeSha), `${label} tree SHA is invalid`);
  return source;
}

function verifySignedPayload(envelope, trustPolicy, expectedSchema, label) {
  exactKeys(envelope, CANARY_ENVELOPE_KEYS, `${label} envelope`);
  invariant(
    envelope.schemaVersion === expectedSchema,
    `${label} envelope schema differs`,
  );
  invariant(
    envelope.keyId === trustPolicy.candidateKeyId,
    `${label} signing key differs`,
  );
  invariant(
    typeof envelope.signatureBase64 === "string" &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(envelope.signatureBase64),
    `${label} signature is missing or invalid`,
  );
  const publicKey = createPublicKey({
    key: Buffer.from(trustPolicy.candidatePublicKeySpkiBase64, "base64"),
    format: "der",
    type: "spki",
  });
  invariant(
    publicKey.asymmetricKeyType === "ed25519",
    `${label} signing key is not Ed25519`,
  );
  invariant(
    verify(
      null,
      Buffer.from(canonicalJson(envelope.payload)),
      publicKey,
      Buffer.from(envelope.signatureBase64, "base64"),
    ),
    `${label} signature is invalid`,
  );
  return envelope.payload;
}

export function runtimeCanaryReceiptDigest(signedRuntimeCanary) {
  return sha256Digest(signedRuntimeCanary);
}

export function landingTransitionReceiptDigest(signedLandingTransition) {
  return sha256Digest(signedLandingTransition);
}

export function validateSignedLandingTransition({
  signedLandingTransition,
  trustPolicy,
  now = Date.now(),
}) {
  exactKeys(
    trustPolicy,
    LANDING_POLICY_KEYS,
    "npm landing-transition trust policy",
  );
  invariant(
    typeof trustPolicy.ownerPublicKeySpkiBase64 === "string" &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(trustPolicy.ownerPublicKeySpkiBase64),
    "npm landing-transition owner key is invalid",
  );
  invariant(
    digestBytes(Buffer.from(trustPolicy.ownerPublicKeySpkiBase64, "base64")) ===
      trustPolicy.ownerKeyId,
    "npm landing-transition owner key identity differs",
  );
  exactKeys(
    signedLandingTransition,
    CANARY_ENVELOPE_KEYS,
    "npm landing-transition envelope",
  );
  invariant(
    signedLandingTransition.schemaVersion ===
      SIGNED_NPM_PUBLISHER_LANDING_SCHEMA,
    "npm landing-transition envelope schema differs",
  );
  invariant(
    signedLandingTransition.keyId === trustPolicy.ownerKeyId,
    "npm landing-transition signing key differs",
  );
  invariant(
    typeof signedLandingTransition.signatureBase64 === "string" &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(signedLandingTransition.signatureBase64),
    "npm landing-transition signature is missing or invalid",
  );
  const publicKey = createPublicKey({
    key: Buffer.from(trustPolicy.ownerPublicKeySpkiBase64, "base64"),
    format: "der",
    type: "spki",
  });
  invariant(
    publicKey.asymmetricKeyType === "ed25519",
    "npm landing-transition key is not Ed25519",
  );
  invariant(
    verify(
      null,
      Buffer.from(canonicalJson(signedLandingTransition.payload)),
      publicKey,
      Buffer.from(signedLandingTransition.signatureBase64, "base64"),
    ),
    "npm landing-transition signature is invalid",
  );
  const payload = signedLandingTransition.payload;
  exactKeys(payload, LANDING_PAYLOAD_KEYS, "npm landing-transition receipt");
  invariant(
    payload.schemaVersion === NPM_PUBLISHER_LANDING_SCHEMA,
    "npm landing-transition schema differs",
  );
  invariant(
    payload.repository === CANONICAL_REPOSITORY &&
      payload.repositoryId === CANONICAL_REPOSITORY_ID,
    "npm landing-transition repository differs",
  );
  invariant(
    GIT_SHA.test(payload.landedSha),
    "npm landing-transition landed SHA is invalid",
  );
  exactKeys(
    payload.authorization,
    LANDING_AUTHORIZATION_KEYS,
    "npm landing-transition authorization",
  );
  invariant(
    ALLOWED_PRODUCTION_ACTORS.has(payload.authorization.actor),
    "npm landing-transition actor is not an owner authority",
  );
  invariant(
    SHA256.test(payload.authorization.decisionDigest),
    "npm landing-transition decision digest is invalid",
  );
  const authorizedAt = parseTime(
    payload.authorization.authorizedAt,
    "npm landing-transition authorizedAt",
  );
  exactKeys(
    payload.workflow,
    LANDING_WORKFLOW_KEYS,
    "npm landing-transition workflow",
  );
  invariant(
    Number.isSafeInteger(payload.workflow.id) && payload.workflow.id > 0,
    "npm landing-transition workflow id is invalid",
  );
  invariant(
    payload.workflow.name === "publish-qualified-npm-candidate" &&
      payload.workflow.path === PUBLISH_WORKFLOW_PATH &&
      (payload.workflow.stateBefore === "active" ||
        payload.workflow.stateBefore === "disabled_manually") &&
      payload.workflow.stateAfter === "disabled_manually",
    "npm landing-transition workflow disposition differs",
  );
  exactKeys(
    payload.evidenceDigests,
    LANDING_EVIDENCE_KEYS,
    "npm landing-transition evidence",
  );
  for (const digest of Object.values(payload.evidenceDigests)) {
    invariant(
      SHA256.test(digest),
      "npm landing-transition API evidence digest is invalid",
    );
  }
  const startedAt = parseTime(
    payload.startedAt,
    "npm landing-transition startedAt",
  );
  const finishedAt = parseTime(
    payload.finishedAt,
    "npm landing-transition finishedAt",
  );
  invariant(
    authorizedAt <= startedAt && startedAt <= finishedAt,
    "npm landing-transition chronology differs",
  );
  invariant(finishedAt <= now, "npm landing-transition is future-dated");
  return {
    landedSha: payload.landedSha,
    workflowId: payload.workflow.id,
    receiptDigest: landingTransitionReceiptDigest(signedLandingTransition),
  };
}

export function validateSignedNpmRuntimeCanary({
  signedRuntimeCanary,
  trustPolicy,
  expectedSource,
  expectedPackage,
  expectedReceiptDigest,
  qualificationFinishedAt,
  now = Date.now(),
}) {
  invariant(
    SHA256.test(expectedReceiptDigest),
    "expected runtime-canary receipt digest is invalid",
  );
  invariant(
    safeEqual(
      runtimeCanaryReceiptDigest(signedRuntimeCanary),
      expectedReceiptDigest,
    ),
    "runtime-canary receipt digest differs",
  );
  const payload = verifySignedPayload(
    signedRuntimeCanary,
    trustPolicy,
    SIGNED_NPM_RUNTIME_CANARY_SCHEMA,
    "npm runtime canary",
  );
  exactKeys(payload, CANARY_PAYLOAD_KEYS, "npm runtime-canary receipt");
  invariant(
    payload.schemaVersion === NPM_RUNTIME_CANARY_SCHEMA,
    "npm runtime-canary schema differs",
  );
  invariant(
    payload.repository === CANONICAL_REPOSITORY,
    "npm runtime-canary repository differs",
  );
  validateSource(payload.source, "npm runtime-canary source");
  invariant(
    canonicalJson(payload.source) === canonicalJson(expectedSource),
    "npm runtime-canary source differs",
  );
  exactKeys(payload.package, CANARY_PACKAGE_KEYS, "npm runtime-canary package");
  invariant(
    canonicalJson(payload.package) === canonicalJson(expectedPackage),
    "npm runtime-canary package differs",
  );
  invariant(
    payload.homeIsolation === "fresh-empty-temporary-home",
    "npm runtime-canary HOME isolation differs",
  );

  exactKeys(
    payload.install,
    CANARY_INSTALL_KEYS,
    "npm runtime-canary install result",
  );
  invariant(
    payload.install.command ===
      "npm install ./npm-package.tgz --no-audit --no-fund",
    "npm runtime-canary install command differs",
  );
  invariant(
    payload.install.scriptsPolicy === "consumer-default",
    "npm runtime-canary install scripts policy differs",
  );
  invariant(
    payload.install.exitCode === 0,
    "npm runtime-canary install did not pass",
  );
  boundedText(payload.install.stdout, "npm runtime-canary install stdout");
  boundedText(payload.install.stderr, "npm runtime-canary install stderr");

  exactKeys(
    payload.version,
    CANARY_VERSION_KEYS,
    "npm runtime-canary version result",
  );
  invariant(
    payload.version.command === "sift-q --version",
    "npm runtime-canary version command differs",
  );
  invariant(
    payload.version.exitCode === 0,
    "npm runtime-canary version command did not pass",
  );
  invariant(
    payload.version.stdout ===
      canonicalSiftQVersionOutput(expectedPackage.version) &&
      payload.version.stderr === "",
    "npm runtime-canary version output differs",
  );

  exactKeys(
    payload.dryRun,
    CANARY_DRY_RUN_KEYS,
    "npm runtime-canary dry-run result",
  );
  invariant(
    payload.dryRun.harness === "claude",
    "npm runtime-canary harness differs",
  );
  invariant(
    payload.dryRun.command === "sift-q --dry-run --json --client claude",
    "npm runtime-canary dry-run command differs",
  );
  invariant(
    payload.dryRun.exitCode === 0,
    "npm runtime-canary dry-run did not pass",
  );
  boundedText(payload.dryRun.stdout, "npm runtime-canary dry-run stdout");
  invariant(
    payload.dryRun.stderr === "",
    "npm runtime-canary dry-run stderr is not empty",
  );
  let report;
  try {
    report = JSON.parse(payload.dryRun.stdout);
  } catch {
    throw new Error("npm runtime-canary dry-run stdout is not JSON");
  }
  invariant(
    report?.detection?.platform?.ok === true,
    "npm runtime-canary platform check failed",
  );
  invariant(
    canonicalJson(report?.plan?.map((step) => step?.id)) ===
      canonicalJson(["fetch-hosted-content", "register-claude"]),
    "npm runtime-canary dry-run plan differs",
  );
  invariant(
    Array.isArray(report?.result?.stepResults) &&
      report.result.stepResults.length === 0,
    "npm runtime-canary dry-run performed writes",
  );

  const finishedAt = parseTime(
    payload.finishedAt,
    "npm runtime-canary finishedAt",
  );
  const qualificationAt = parseTime(
    qualificationFinishedAt,
    "candidate qualification finishedAt",
  );
  const skew = trustPolicy.clockSkewSeconds * 1000;
  invariant(
    finishedAt <= qualificationAt,
    "candidate qualification predates npm runtime canary",
  );
  invariant(
    finishedAt <= now + skew,
    "npm runtime-canary evidence is in the future",
  );
  invariant(
    finishedAt >= now - trustPolicy.maximumEvidenceAgeSeconds * 1000,
    "npm runtime-canary evidence is stale",
  );
  return structuredClone(payload);
}

function stableVersion(value, label) {
  const match = typeof value === "string" ? STABLE_VERSION.exec(value) : null;
  invariant(match !== null, `${label} must be a stable x.y.z version`);
  return match.slice(1).map((part) => BigInt(part));
}

function compareVersions(left, right) {
  const leftParts = stableVersion(left, "candidate version");
  const rightParts = stableVersion(right, "registry latest version");
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] < rightParts[index]) return -1;
    if (leftParts[index] > rightParts[index]) return 1;
  }
  return 0;
}

function parseTarString(bytes) {
  const zero = bytes.indexOf(0);
  return bytes.subarray(0, zero === -1 ? bytes.length : zero).toString("utf8");
}

function parseTarSize(bytes) {
  const value = parseTarString(bytes).trim();
  invariant(/^[0-7]+$/.test(value), "npm tarball has an invalid entry size");
  const size = Number.parseInt(value, 8);
  invariant(
    Number.isSafeInteger(size) && size >= 0,
    "npm tarball entry is too large",
  );
  return size;
}

function safeTarPath(path) {
  invariant(
    path !== "" &&
      !path.startsWith("/") &&
      !path.includes("\\") &&
      !path.split("/").includes(".."),
    "npm tarball contains an unsafe path",
  );
}

export function packageManifestFromTarball(tarball) {
  let archive;
  try {
    archive = gunzipSync(tarball, { maxOutputLength: 64 * 1024 * 1024 });
  } catch {
    throw new Error("npm tarball is not a bounded gzip archive");
  }
  let offset = 0;
  const manifests = [];
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = parseTarString(header.subarray(0, 100));
    const prefix = parseTarString(header.subarray(345, 500));
    const path = prefix === "" ? name : `${prefix}/${name}`;
    safeTarPath(path);
    const size = parseTarSize(header.subarray(124, 136));
    const type = String.fromCharCode(header[156] || 48);
    invariant(
      type === "0" || type === "5",
      "npm tarball contains a non-file entry",
    );
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    invariant(contentEnd <= archive.length, "npm tarball entry is truncated");
    if (path === "package/package.json") {
      invariant(type === "0", "npm package manifest is not a regular file");
      manifests.push(archive.subarray(contentStart, contentEnd));
    }
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  invariant(
    manifests.length === 1,
    "npm tarball must contain exactly one package/package.json",
  );
  let manifest;
  try {
    manifest = JSON.parse(manifests[0].toString("utf8"));
  } catch {
    throw new Error("npm tarball package manifest is invalid JSON");
  }
  invariant(
    manifest !== null &&
      typeof manifest === "object" &&
      !Array.isArray(manifest),
    "npm tarball package manifest is invalid",
  );
  return manifest;
}

function validateAuthority(authority) {
  exactKeys(authority, AUTHORITY_KEYS, "npm production authority");
  invariant(
    ALLOWED_PRODUCTION_ACTORS.has(authority.dispatchActor),
    "npm dispatch actor is not a production authority",
  );
  invariant(
    ALLOWED_PRODUCTION_ACTORS.has(authority.executingActor),
    "npm executing actor is not a production authority",
  );
  invariant(
    authority.repository === CANONICAL_REPOSITORY,
    "npm authority repository differs",
  );
  invariant(
    authority.repositoryId === CANONICAL_REPOSITORY_ID,
    "npm authority repository id differs",
  );
  invariant(
    SHA256.test(authority.landingTransitionReceiptDigest),
    "npm landing-transition authority digest is invalid",
  );
  invariant(
    authority.githubEnvironment === PRODUCTION_GITHUB_ENVIRONMENT,
    "npm GitHub environment differs",
  );
  invariant(
    authority.workflowRef ===
      `${CANONICAL_REPOSITORY}/${PUBLISH_WORKFLOW_PATH}@refs/heads/main`,
    "npm publisher workflow ref differs",
  );
  return authority;
}

export function validateDevelopmentArtifactRun(run, expectedRunId) {
  invariant(RUN_ID.test(String(expectedRunId)), "candidate run id is invalid");
  invariant(run?.id === Number(expectedRunId), "candidate run id differs");
  invariant(
    run?.repository?.id === CANONICAL_REPOSITORY_ID,
    "candidate run repository id differs",
  );
  invariant(
    run.repository.full_name === CANONICAL_REPOSITORY,
    "candidate run repository differs",
  );
  invariant(
    run.path === CANDIDATE_WORKFLOW_PATH,
    "candidate run workflow path differs",
  );
  invariant(
    run.event === "workflow_run",
    "candidate run was not automatic accepted-main qualification",
  );
  invariant(
    run.head_branch === "main" && GIT_SHA.test(run.head_sha),
    "candidate run source differs",
  );
  invariant(
    run.status === "completed" && run.conclusion === "success",
    "candidate run is not green",
  );
  invariant(
    Number.isSafeInteger(run.run_attempt) && run.run_attempt > 0,
    "candidate run attempt is invalid",
  );
  invariant(
    run.artifacts_url ===
      `https://api.github.com/repos/${CANONICAL_REPOSITORY}/actions/runs/${expectedRunId}/artifacts`,
    "candidate run artifact authority differs",
  );
  return {
    runId: Number(expectedRunId),
    runAttempt: run.run_attempt,
    sha: run.head_sha,
  };
}

export function validateCurrentMainIdentity(commit, expectedSha) {
  invariant(GIT_SHA.test(expectedSha), "expected current main SHA is invalid");
  invariant(
    commit !== null && typeof commit === "object",
    "current main response is invalid",
  );
  invariant(GIT_SHA.test(commit.sha), "current main response SHA is invalid");
  invariant(
    commit.sha === expectedSha,
    "publisher SHA is no longer current main",
  );
  return { sha: commit.sha };
}

export function validateCandidateLineage({
  candidateSha,
  currentMainSha,
  isAncestor,
}) {
  invariant(GIT_SHA.test(candidateSha), "candidate lineage SHA is invalid");
  invariant(
    GIT_SHA.test(currentMainSha),
    "current main lineage SHA is invalid",
  );
  invariant(
    isAncestor === true,
    "qualified candidate is not an ancestor of current main",
  );
  return { candidateSha, currentMainSha };
}

export function validateRelayPublisherDisabled(
  repository,
  workflow,
  runsByStatus,
) {
  invariant(
    repository?.id === RELAY_REPOSITORY_ID,
    "npm relay repository id differs",
  );
  invariant(
    repository.full_name === RELAY_REPOSITORY,
    "npm relay repository differs",
  );
  invariant(repository.private === false, "npm relay repository is not public");
  invariant(
    repository.default_branch === "main",
    "npm relay default branch differs",
  );
  invariant(
    workflow?.id === RELAY_WORKFLOW_ID,
    "npm relay workflow id differs",
  );
  invariant(workflow.name === "publish-npm", "npm relay workflow name differs");
  invariant(
    workflow.path === PUBLISH_WORKFLOW_PATH,
    "npm relay workflow path differs",
  );
  invariant(
    workflow.state === "disabled_manually",
    "interim npm relay workflow is not manually disabled",
  );
  exactKeys(
    runsByStatus,
    RELAY_ACTIVE_RUN_STATUSES,
    "npm relay active-run queries",
  );
  for (const status of RELAY_ACTIVE_RUN_STATUSES) {
    const response = runsByStatus[status];
    invariant(
      Number.isSafeInteger(response?.total_count) && response.total_count === 0,
      `interim npm relay still has ${status} runs`,
    );
    invariant(
      Array.isArray(response.workflow_runs) &&
        response.workflow_runs.length === 0,
      `interim npm relay ${status} run response is ambiguous`,
    );
  }
  return {
    repositoryId: repository.id,
    workflowId: workflow.id,
    state: workflow.state,
  };
}

export function validateExactPublisherExclusive(
  workflow,
  runsByStatus,
  currentRunId,
) {
  invariant(
    RUN_ID.test(String(currentRunId)),
    "current publisher run id is invalid",
  );
  invariant(
    Number.isSafeInteger(workflow?.id) && workflow.id > 0,
    "npm publisher workflow id is invalid",
  );
  invariant(
    workflow.name === "publish-qualified-npm-candidate",
    "npm publisher workflow name differs",
  );
  invariant(
    workflow.path === PUBLISH_WORKFLOW_PATH,
    "npm publisher workflow path differs",
  );
  invariant(
    workflow.state === "active",
    "npm exact publisher is not the active exclusive lane",
  );
  exactKeys(
    runsByStatus,
    RELAY_ACTIVE_RUN_STATUSES,
    "npm exact-publisher active-run queries",
  );
  for (const status of RELAY_ACTIVE_RUN_STATUSES) {
    const response = runsByStatus[status];
    invariant(
      Number.isSafeInteger(response?.total_count) &&
        Array.isArray(response.workflow_runs),
      `npm exact-publisher ${status} run response is ambiguous`,
    );
    if (status === "in_progress") {
      invariant(
        response.total_count === 1 &&
          response.workflow_runs.length === 1 &&
          response.workflow_runs[0]?.id === Number(currentRunId) &&
          response.workflow_runs[0]?.status === "in_progress",
        "another npm exact-publisher run is active at the mutation boundary",
      );
    } else {
      invariant(
        response.total_count === 0 && response.workflow_runs.length === 0,
        `npm exact publisher still has ${status} runs`,
      );
    }
  }
  return {
    workflowId: workflow.id,
    state: workflow.state,
    currentRunId: Number(currentRunId),
  };
}

export function validateNpmCandidate({
  signedCandidate,
  signedRuntimeCanary,
  trustPolicy,
  tarball,
  expectedSha,
  expectedTreeSha,
  expectedReceiptDigest,
  authority,
  now = Date.now(),
}) {
  invariant(
    GIT_SHA.test(expectedSha) && GIT_SHA.test(expectedTreeSha),
    "expected candidate source is invalid",
  );
  invariant(
    SHA256.test(expectedReceiptDigest),
    "expected candidate receipt digest is invalid",
  );
  invariant(
    trustPolicy.repository === CANONICAL_REPOSITORY,
    "candidate repository policy is not the canonical repository",
  );
  invariant(
    trustPolicy.npmPackageName === CANONICAL_PACKAGE,
    "candidate npm package policy is not the canonical package",
  );
  invariant(
    trustPolicy.developmentEnvironmentId === DEVELOPMENT_ENVIRONMENT_ID,
    "development environment policy differs",
  );
  invariant(
    trustPolicy.productionEnvironmentId === PRODUCTION_ENVIRONMENT_ID,
    "production environment policy differs",
  );
  const actualReceiptDigest = candidateReceiptDigest(signedCandidate);
  invariant(
    safeEqual(actualReceiptDigest, expectedReceiptDigest),
    "candidate receipt digest differs",
  );
  const expectedSource = {
    ref: "refs/heads/main",
    sha: expectedSha,
    treeSha: expectedTreeSha,
  };
  const promotionRequest = {
    schemaVersion: PRODUCTION_PROMOTION_REQUEST_SCHEMA,
    candidateReceiptDigest: expectedReceiptDigest,
    fromEnvironmentId: DEVELOPMENT_ENVIRONMENT_ID,
    toEnvironmentId: PRODUCTION_ENVIRONMENT_ID,
    source: expectedSource,
    artifacts: signedCandidate?.payload?.artifacts,
  };
  const candidateSelection = selectProductionCandidate({
    signedCandidate,
    trustPolicy,
    expectedSource,
    promotionRequest,
    now,
  });
  const manifest = packageManifestFromTarball(tarball);
  const npmArtifact = candidateSelection.artifacts.npm;
  validateSignedNpmRuntimeCanary({
    signedRuntimeCanary,
    trustPolicy,
    expectedSource,
    expectedPackage: {
      name: npmArtifact.packageName,
      version: npmArtifact.version,
      tarballDigest: npmArtifact.tarballDigest,
    },
    expectedReceiptDigest: npmArtifact.runtimeCanaryReceiptDigest,
    qualificationFinishedAt: signedCandidate.payload.qualification.finishedAt,
    now,
  });
  invariant(
    manifest.name === npmArtifact.packageName,
    "npm tarball package name differs from candidate",
  );
  invariant(
    manifest.version === npmArtifact.version,
    "npm tarball version differs from candidate",
  );
  invariant(
    PACKAGE_NAME.test(manifest.name),
    "npm tarball package name is invalid",
  );
  invariant(
    manifest.name === CANONICAL_PACKAGE,
    "npm tarball is not the canonical package",
  );
  exactKeys(
    manifest.repository,
    PACKAGE_REPOSITORY_KEYS,
    "npm tarball repository",
  );
  invariant(
    manifest.repository.type === CANONICAL_PACKAGE_REPOSITORY.type &&
      manifest.repository.url === CANONICAL_PACKAGE_REPOSITORY.url,
    "npm tarball repository is not canonical",
  );
  stableVersion(manifest.version, "production npm candidate version");
  const tarballDigest = digestBytes(tarball);
  invariant(
    safeEqual(tarballDigest, npmArtifact.tarballDigest),
    "npm tarball bytes differ from candidate",
  );
  const validatedAuthority = validateAuthority(authority);
  const selected = {
    schemaVersion: NPM_OIDC_SELECTION_SCHEMA,
    authority: structuredClone(validatedAuthority),
    candidateSelection,
    package: {
      name: manifest.name,
      version: manifest.version,
      tarballDigest,
      tarballBytes: tarball.length,
      runtimeCanaryReceiptDigest: npmArtifact.runtimeCanaryReceiptDigest,
    },
  };
  return { ...selected, selectionDigest: sha256Digest(selected) };
}

function packageOfSelection(selection) {
  exactKeys(selection, SELECTION_KEYS, "npm OIDC selection");
  invariant(
    selection.schemaVersion === NPM_OIDC_SELECTION_SCHEMA,
    "npm OIDC selection schema differs",
  );
  invariant(
    selection.candidateSelection?.schemaVersion ===
      PRODUCTION_PROMOTION_SELECTION_SCHEMA,
    "production promotion selection schema differs",
  );
  const copy = structuredClone(selection);
  delete copy.selectionDigest;
  invariant(
    selection.selectionDigest === sha256Digest(copy),
    "npm OIDC selection digest differs",
  );
  validateAuthority(selection.authority);
  exactKeys(selection.package, SELECTION_PACKAGE_KEYS, "selected npm package");
  invariant(
    PACKAGE_NAME.test(selection.package?.name),
    "selected npm package is invalid",
  );
  invariant(
    selection.package.name === CANONICAL_PACKAGE,
    "selected npm package is not canonical",
  );
  invariant(
    SHA256.test(selection.package.tarballDigest),
    "selected npm tarball digest is invalid",
  );
  invariant(
    SHA256.test(selection.package.runtimeCanaryReceiptDigest),
    "selected npm runtime-canary receipt digest is invalid",
  );
  stableVersion(selection.package.version, "selected npm version");
  invariant(
    selection.package.name ===
      selection.candidateSelection?.artifacts?.npm?.packageName,
    "selected npm package differs",
  );
  invariant(
    selection.package.version ===
      selection.candidateSelection.artifacts.npm.version,
    "selected npm version differs",
  );
  invariant(
    selection.package.tarballDigest ===
      selection.candidateSelection.artifacts.npm.tarballDigest,
    "selected npm tarball differs",
  );
  invariant(
    selection.package.runtimeCanaryReceiptDigest ===
      selection.candidateSelection.artifacts.npm.runtimeCanaryReceiptDigest,
    "selected npm runtime-canary receipt differs",
  );
  return selection.package;
}

function validateReleasedMutationLock(lock, lockUri) {
  exactKeys(lock, LOCK_KEYS, "npm mutation lock result");
  invariant(
    typeof lockUri === "string" &&
      /^s3:\/\/[a-z0-9][a-z0-9.-]+\/.+/.test(lockUri),
    "configured npm mutation lock URI is invalid",
  );
  invariant(lock.s3Uri === lockUri, "npm mutation lock URI differs");
  invariant(
    /^"[0-9a-fA-F]{32}"$/.test(lock.etag),
    "npm mutation lock ETag is invalid",
  );
  invariant(
    typeof lock.versionId === "string" && lock.versionId.length > 0,
    "npm mutation lock version is invalid",
  );
  invariant(lock.state === "released", "npm mutation lock was not released");
  invariant(
    lock.releaseError === null,
    "npm mutation lock release is ambiguous",
  );
  return lock;
}

function versionList(value) {
  const versions = typeof value === "string" ? [value] : value;
  invariant(
    Array.isArray(versions) && versions.length > 0,
    "registry version list is invalid",
  );
  invariant(
    versions.every((version) => typeof version === "string"),
    "registry version list is invalid",
  );
  invariant(
    new Set(versions).size === versions.length,
    "registry version list contains duplicates",
  );
  return versions;
}

export function canonicalRegistryTarballUrl(packageName, version, metadata) {
  invariant(PACKAGE_NAME.test(packageName), "registry package name is invalid");
  stableVersion(version, "registry package version");
  const raw = metadata?.dist?.tarball;
  invariant(typeof raw === "string", "registry tarball URL is missing");
  const url = new URL(raw);
  const leaf = packageName.slice(packageName.indexOf("/") + 1);
  invariant(
    url.origin === "https://registry.npmjs.org",
    "registry tarball origin differs",
  );
  invariant(
    url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "",
    "registry tarball URL carries unsafe authority data",
  );
  invariant(
    url.pathname === `/${packageName}/-/${leaf}-${version}.tgz`,
    "registry tarball path differs",
  );
  return url.href;
}

export function planRegistryReconciliation({
  selection,
  versions,
  latestVersion,
  nextVersion = "",
  existingTarball,
}) {
  const candidate = packageOfSelection(selection);
  const published = versionList(versions);
  stableVersion(latestVersion, "registry latest version");
  if (nextVersion !== "") stableVersion(nextVersion, "registry next version");
  const exists = published.includes(candidate.version);
  if (exists) {
    invariant(
      existingTarball !== undefined,
      "existing registry tarball bytes are required",
    );
    invariant(
      safeEqual(digestBytes(existingTarball), candidate.tarballDigest),
      "registry version exists with different bytes",
    );
    invariant(
      latestVersion === candidate.version || nextVersion === candidate.version,
      "registry version exists but is bound to neither next nor latest",
    );
    return {
      schemaVersion: NPM_REGISTRY_PLAN_SCHEMA,
      action:
        latestVersion === candidate.version ? "already-latest" : "canary-next",
      packageName: candidate.name,
      version: candidate.version,
      tarballDigest: candidate.tarballDigest,
      priorLatestVersion: latestVersion,
      priorNextVersion: nextVersion || null,
      selectionDigest: selection.selectionDigest,
    };
  }
  invariant(
    existingTarball === undefined,
    "registry returned bytes for an absent version",
  );
  invariant(
    compareVersions(candidate.version, latestVersion) > 0,
    "candidate version would move latest backward or sideways",
  );
  invariant(
    nextVersion === "" || nextVersion === latestVersion,
    "registry next tag is occupied by a different unpromoted version",
  );
  return {
    schemaVersion: NPM_REGISTRY_PLAN_SCHEMA,
    action: "publish-next",
    packageName: candidate.name,
    version: candidate.version,
    tarballDigest: candidate.tarballDigest,
    priorLatestVersion: latestVersion,
    priorNextVersion: nextVersion || null,
    selectionDigest: selection.selectionDigest,
  };
}

export function verifyRegistryPostcondition({
  selection,
  versions,
  latestVersion,
  nextVersion,
  registryTarball,
  action,
  lock,
  lockUri,
  registryCanaryDigest,
  currentMainDigest,
  publisherSource,
  boundaryEvidenceDigests,
  run,
  startedAt,
  finishedAt,
}) {
  const candidate = packageOfSelection(selection);
  const published = versionList(versions);
  invariant(
    action === "publish-next" ||
      action === "canary-next" ||
      action === "already-latest",
    "registry action is invalid",
  );
  invariant(
    published.includes(candidate.version),
    "registry does not contain the candidate version",
  );
  invariant(
    latestVersion === candidate.version || nextVersion === candidate.version,
    "registry selects the candidate on neither next nor latest",
  );
  if (action === "already-latest") {
    invariant(
      latestVersion === candidate.version,
      "already-latest action differs from registry",
    );
  } else {
    invariant(
      nextVersion === candidate.version,
      "next transport action differs from registry",
    );
    invariant(
      latestVersion !== candidate.version,
      "next transport cannot reconcile an owner-controller latest promotion",
    );
  }
  invariant(
    safeEqual(digestBytes(registryTarball), candidate.tarballDigest),
    "registry serves different candidate bytes",
  );
  invariant(
    SHA256.test(registryCanaryDigest),
    "registry canary receipt digest is invalid",
  );
  invariant(
    SHA256.test(currentMainDigest),
    "current-main evidence digest is invalid",
  );
  exactKeys(publisherSource, ["ref", "sha", "treeSha"], "npm publisher source");
  invariant(
    publisherSource.ref === "refs/heads/main" &&
      GIT_SHA.test(publisherSource.sha) &&
      GIT_SHA.test(publisherSource.treeSha),
    "npm publisher source differs",
  );
  exactKeys(
    boundaryEvidenceDigests,
    [
      "alternateAuthority",
      "exactPublisher",
      "lockHead",
      "mutationAuthority",
      "registryPlan",
    ],
    "npm mutation-boundary evidence",
  );
  for (const digest of Object.values(boundaryEvidenceDigests)) {
    invariant(
      SHA256.test(digest),
      "npm mutation-boundary evidence digest is invalid",
    );
  }
  exactKeys(run, ["attempt", "id"], "npm publication run");
  invariant(RUN_ID.test(String(run.id)), "npm publication run id is invalid");
  invariant(
    Number.isSafeInteger(run.attempt) && run.attempt > 0,
    "npm run attempt is invalid",
  );
  const started = parseTime(startedAt, "npm publication startedAt");
  const finished = parseTime(finishedAt, "npm publication finishedAt");
  invariant(started <= finished, "npm publication chronology differs");
  const releasedLock = validateReleasedMutationLock(lock, lockUri);
  return {
    schemaVersion: NPM_PUBLICATION_RESULT_SCHEMA,
    outcome:
      latestVersion === candidate.version
        ? "reconciled-existing-latest"
        : "awaiting-owner-controller",
    repository: CANONICAL_REPOSITORY,
    productionEnvironmentId: PRODUCTION_ENVIRONMENT_ID,
    packageName: candidate.name,
    version: candidate.version,
    tarballDigest: candidate.tarballDigest,
    candidateReceiptDigest: selection.candidateSelection.candidateReceiptDigest,
    source: selection.candidateSelection.source,
    publisherSource: structuredClone(publisherSource),
    authority: selection.authority,
    selectionDigest: selection.selectionDigest,
    registry: {
      url: "https://registry.npmjs.org",
      nextVersion: nextVersion || null,
      latestVersion,
      servedTarballDigest: digestBytes(registryTarball),
      registryCanaryDigest,
    },
    handoff: {
      authority: "installed-root-owned-owner-controller",
      requiredOperation:
        latestVersion === candidate.version ? null : "promote-latest",
      workflowMayPromoteLatest: false,
    },
    transportAction: action,
    boundaryEvidenceDigests: structuredClone(boundaryEvidenceDigests),
    currentMainDigest,
    run: structuredClone(run),
    startedAt,
    finishedAt,
    mutationLock: structuredClone(releasedLock),
  };
}

export function validateSignedRegistryCanaryHandoff({
  signedHandoff,
  trustPolicy,
}) {
  exactKeys(
    trustPolicy,
    REGISTRY_HANDOFF_POLICY_KEYS,
    "npm registry-handoff trust policy",
  );
  invariant(
    /^arn:aws:kms:us-east-1:161987606185:key\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      trustPolicy.receiptSigningKeyArn,
    ),
    "npm registry-handoff signing key ARN is invalid",
  );
  invariant(
    typeof trustPolicy.receiptSigningPublicKeySpkiBase64 === "string" &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(
        trustPolicy.receiptSigningPublicKeySpkiBase64,
      ),
    "npm registry-handoff public key is invalid",
  );
  exactKeys(
    signedHandoff,
    CANARY_ENVELOPE_KEYS,
    "npm registry-handoff envelope",
  );
  invariant(
    signedHandoff.schemaVersion === SIGNED_NPM_REGISTRY_CANARY_SCHEMA,
    "npm registry-handoff envelope schema differs",
  );
  const publicKeyBytes = Buffer.from(
    trustPolicy.receiptSigningPublicKeySpkiBase64,
    "base64",
  );
  const keyId = digestBytes(publicKeyBytes);
  invariant(
    signedHandoff.keyId === keyId,
    "npm registry-handoff signing key differs",
  );
  invariant(
    typeof signedHandoff.signatureBase64 === "string" &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(signedHandoff.signatureBase64),
    "npm registry-handoff signature is missing or invalid",
  );
  const publicKey = createPublicKey({
    key: publicKeyBytes,
    format: "der",
    type: "spki",
  });
  invariant(
    publicKey.asymmetricKeyType === "ec" &&
      publicKey.asymmetricKeyDetails?.namedCurve === "prime256v1",
    "npm registry-handoff signing key is not P-256",
  );
  invariant(
    verify(
      "sha256",
      Buffer.from(canonicalJson(signedHandoff.payload)),
      publicKey,
      Buffer.from(signedHandoff.signatureBase64, "base64"),
    ),
    "npm registry-handoff signature is invalid",
  );

  const payload = signedHandoff.payload;
  exactKeys(payload, PUBLICATION_RESULT_KEYS, "npm registry-handoff payload");
  invariant(
    payload.schemaVersion === NPM_PUBLICATION_RESULT_SCHEMA,
    "npm registry-handoff payload schema differs",
  );
  invariant(
    payload.outcome === "awaiting-owner-controller",
    "npm registry-handoff is not promotable",
  );
  invariant(
    payload.repository === CANONICAL_REPOSITORY,
    "npm registry-handoff repository differs",
  );
  invariant(
    payload.productionEnvironmentId === PRODUCTION_ENVIRONMENT_ID,
    "npm registry-handoff production environment differs",
  );
  invariant(
    payload.packageName === CANONICAL_PACKAGE,
    "npm registry-handoff package differs",
  );
  stableVersion(payload.version, "npm registry-handoff version");
  invariant(
    SHA256.test(payload.tarballDigest),
    "npm registry-handoff tarball digest is invalid",
  );
  invariant(
    SHA256.test(payload.candidateReceiptDigest),
    "npm registry-handoff candidate digest is invalid",
  );
  invariant(
    SHA256.test(payload.selectionDigest),
    "npm registry-handoff selection digest is invalid",
  );
  invariant(
    SHA256.test(payload.currentMainDigest),
    "npm registry-handoff current-main digest is invalid",
  );
  exactKeys(
    payload.boundaryEvidenceDigests,
    [
      "alternateAuthority",
      "exactPublisher",
      "lockHead",
      "mutationAuthority",
      "registryPlan",
    ],
    "npm registry-handoff boundary evidence",
  );
  invariant(
    Object.values(payload.boundaryEvidenceDigests).every((digest) =>
      SHA256.test(digest),
    ),
    "npm registry-handoff boundary evidence digest is invalid",
  );
  exactKeys(payload.run, ["attempt", "id"], "npm registry-handoff run");
  invariant(
    RUN_ID.test(String(payload.run.id)),
    "npm registry-handoff run id is invalid",
  );
  invariant(
    Number.isSafeInteger(payload.run.attempt) && payload.run.attempt > 0,
    "npm registry-handoff run attempt is invalid",
  );
  invariant(
    parseTime(payload.startedAt, "npm registry-handoff startedAt") <=
      parseTime(payload.finishedAt, "npm registry-handoff finishedAt"),
    "npm registry-handoff chronology differs",
  );
  validateSource(payload.source, "npm registry-handoff source");
  validateSource(
    payload.publisherSource,
    "npm registry-handoff publisher source",
  );
  validateAuthority(payload.authority);
  exactKeys(
    payload.registry,
    PUBLICATION_REGISTRY_KEYS,
    "npm registry-handoff registry",
  );
  invariant(
    payload.registry.url === "https://registry.npmjs.org",
    "npm registry-handoff registry differs",
  );
  invariant(
    payload.registry.nextVersion === payload.version,
    "npm registry-handoff next tag differs",
  );
  invariant(
    payload.registry.latestVersion !== payload.version,
    "npm registry-handoff latest already moved",
  );
  invariant(
    payload.registry.servedTarballDigest === payload.tarballDigest,
    "npm registry-handoff served bytes differ",
  );
  invariant(
    SHA256.test(payload.registry.registryCanaryDigest),
    "npm registry-handoff canary digest is invalid",
  );
  exactKeys(
    payload.handoff,
    PUBLICATION_HANDOFF_KEYS,
    "npm registry-handoff authority",
  );
  invariant(
    payload.handoff.authority === "installed-root-owned-owner-controller" &&
      payload.handoff.requiredOperation === "promote-latest" &&
      payload.handoff.workflowMayPromoteLatest === false,
    "npm registry-handoff promotion authority differs",
  );
  invariant(
    payload.transportAction === "publish-next" ||
      payload.transportAction === "canary-next",
    "npm registry-handoff transport action differs",
  );
  validateReleasedMutationLock(payload.mutationLock, trustPolicy.lockUri);
  return payload;
}

function argumentsOf(argv) {
  const [command, ...rest] = argv;
  const values = new Map();
  while (rest.length > 0) {
    const key = rest.shift();
    invariant(
      key?.startsWith("--") && rest.length > 0 && !values.has(key),
      "npm publisher command arguments are invalid",
    );
    values.set(key, rest.shift());
  }
  return { command, values };
}

function required(values, key) {
  const value = values.get(key);
  invariant(value !== undefined && value !== "", `missing ${key}`);
  return value;
}

function jsonFile(path) {
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

function writeJson(path, value) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  writeFileSync(resolve(path), text, { mode: 0o600 });
  return text;
}

export function main(
  argv,
  { now = Date.now(), write = (value) => process.stdout.write(value) } = {},
) {
  const { command, values } = argumentsOf([...argv]);
  if (command === "verify-run") {
    const result = validateDevelopmentArtifactRun(
      jsonFile(required(values, "--run")),
      required(values, "--run-id"),
    );
    write(`${JSON.stringify(result)}\n`);
    return result;
  }
  if (command === "verify-lineage") {
    const result = validateCandidateLineage({
      candidateSha: required(values, "--candidate-sha"),
      currentMainSha: required(values, "--current-main-sha"),
      isAncestor: required(values, "--is-ancestor") === "true",
    });
    write(`${JSON.stringify(result)}\n`);
    return result;
  }
  if (command === "verify-current-main") {
    const result = validateCurrentMainIdentity(
      jsonFile(required(values, "--commit")),
      required(values, "--expected-sha"),
    );
    write(`${JSON.stringify(result)}\n`);
    return result;
  }
  if (command === "verify-relay") {
    const result = validateRelayPublisherDisabled(
      jsonFile(required(values, "--repository")),
      jsonFile(required(values, "--workflow")),
      Object.fromEntries(
        RELAY_ACTIVE_RUN_STATUSES.map((status) => [
          status,
          jsonFile(required(values, `--${status.replace("_", "-")}-runs`)),
        ]),
      ),
    );
    write(`${JSON.stringify(result)}\n`);
    return result;
  }
  if (command === "verify-exact-publisher") {
    const result = validateExactPublisherExclusive(
      jsonFile(required(values, "--workflow")),
      Object.fromEntries(
        RELAY_ACTIVE_RUN_STATUSES.map((status) => [
          status,
          jsonFile(required(values, `--${status.replace("_", "-")}-runs`)),
        ]),
      ),
      required(values, "--current-run-id"),
    );
    write(`${JSON.stringify(result)}\n`);
    return result;
  }
  if (command === "verify-landing-transition") {
    const result = validateSignedLandingTransition({
      signedLandingTransition: jsonFile(required(values, "--receipt")),
      trustPolicy: jsonFile(required(values, "--trust-policy")),
      now,
    });
    write(writeJson(required(values, "--output"), result));
    return result;
  }
  if (command === "verify-candidate") {
    const signedCandidate = jsonFile(required(values, "--candidate"));
    const result = validateNpmCandidate({
      signedCandidate,
      signedRuntimeCanary: jsonFile(required(values, "--runtime-canary")),
      trustPolicy: jsonFile(required(values, "--trust-policy")),
      tarball: readFileSync(resolve(required(values, "--tarball"))),
      expectedSha: required(values, "--sha"),
      expectedTreeSha: required(values, "--tree-sha"),
      expectedReceiptDigest: required(values, "--receipt-digest"),
      authority: {
        dispatchActor: required(values, "--dispatch-actor"),
        executingActor: required(values, "--executing-actor"),
        githubEnvironment: required(values, "--github-environment"),
        landingTransitionReceiptDigest: required(
          values,
          "--landing-transition-receipt-digest",
        ),
        repository: required(values, "--repository"),
        repositoryId: Number(required(values, "--repository-id")),
        workflowRef: required(values, "--workflow-ref"),
      },
      now,
    });
    write(writeJson(required(values, "--output"), result));
    return result;
  }
  if (command === "registry-url") {
    const selection = jsonFile(required(values, "--selection"));
    const candidate = packageOfSelection(selection);
    const result = canonicalRegistryTarballUrl(
      candidate.name,
      candidate.version,
      jsonFile(required(values, "--metadata")),
    );
    write(`${result}\n`);
    return result;
  }
  if (command === "plan-registry") {
    const existingPath = values.get("--existing-tarball");
    const nextPath = values.get("--next");
    const result = planRegistryReconciliation({
      selection: jsonFile(required(values, "--selection")),
      versions: jsonFile(required(values, "--versions")),
      latestVersion: readFileSync(
        resolve(required(values, "--latest")),
        "utf8",
      ).trim(),
      nextVersion:
        nextPath === undefined
          ? ""
          : readFileSync(resolve(nextPath), "utf8").trim(),
      existingTarball:
        existingPath === undefined
          ? undefined
          : readFileSync(resolve(existingPath)),
    });
    write(writeJson(required(values, "--output"), result));
    return result;
  }
  if (command === "verify-registry") {
    const result = verifyRegistryPostcondition({
      selection: jsonFile(required(values, "--selection")),
      versions: jsonFile(required(values, "--versions")),
      latestVersion: readFileSync(
        resolve(required(values, "--latest")),
        "utf8",
      ).trim(),
      nextVersion: readFileSync(
        resolve(required(values, "--next")),
        "utf8",
      ).trim(),
      registryTarball: readFileSync(
        resolve(required(values, "--registry-tarball")),
      ),
      action: required(values, "--action"),
      lock: jsonFile(required(values, "--lock-result")),
      lockUri: required(values, "--lock-uri"),
      registryCanaryDigest: required(values, "--registry-canary-digest"),
      currentMainDigest: required(values, "--current-main-digest"),
      publisherSource: {
        ref: "refs/heads/main",
        sha: required(values, "--publisher-sha"),
        treeSha: required(values, "--publisher-tree-sha"),
      },
      boundaryEvidenceDigests: jsonFile(
        required(values, "--boundary-evidence-digests"),
      ),
      run: jsonFile(required(values, "--run-identity")),
      startedAt: required(values, "--started-at"),
      finishedAt: required(values, "--finished-at"),
    });
    write(writeJson(required(values, "--output"), result));
    return result;
  }
  if (command === "verify-registry-handoff") {
    const result = validateSignedRegistryCanaryHandoff({
      signedHandoff: jsonFile(required(values, "--receipt")),
      trustPolicy: jsonFile(required(values, "--trust-policy")),
    });
    write(`${JSON.stringify(result)}\n`);
    return result;
  }
  throw new Error(
    "usage: npm-publisher-contract.mjs <verify-run|verify-lineage|verify-current-main|verify-relay|verify-exact-publisher|verify-landing-transition|verify-candidate|registry-url|plan-registry|verify-registry|verify-registry-handoff> [options]",
  );
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `npm exact-artifact publisher: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
