// Vendored verifier from Sift-wiki/sift-q-refactor@4647c4cc8cd665f91385fcf248219c27c99870a9.
// This checked-in public copy is release authority; candidate source may not replace it.
import { createHash, createPublicKey, verify } from "node:crypto";
import { canonicalJson, sha256Digest } from "./readiness-contract.mjs";

export const DEVELOPMENT_CANDIDATE_SCHEMA = "sift-q-development-candidate/v3";
export const SIGNED_DEVELOPMENT_CANDIDATE_SCHEMA =
  "sift-q-signed-development-candidate/v3";
export const PRODUCTION_PROMOTION_REQUEST_SCHEMA =
  "sift-q-production-promotion-request/v3";
export const PRODUCTION_PROMOTION_SELECTION_SCHEMA =
  "sift-q-production-promotion-selection/v3";
export const HOSTED_NPM_ARTIFACT_CHECK_ID = "hosted-npm-artifact-parity";
export const NPM_RUNTIME_CANARY_CHECK_ID = "npm-clean-home-runtime-canary";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const PACKAGE = /^@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/;
const SEMVER =
  /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const MIGRATION_HEAD = /^[0-9]{14}_[a-z0-9_]+\.sql$/;

const REQUIRED_CHECKS = Object.freeze([
  "image-build",
  HOSTED_NPM_ARTIFACT_CHECK_ID,
  "npm-pack",
  NPM_RUNTIME_CANARY_CHECK_ID,
  "pnpm-quality",
  "pnpm-test",
]);
const TRUST_KEYS = [
  "candidateKeyId",
  "candidatePublicKeySpkiBase64",
  "clockSkewSeconds",
  "developmentEnvironmentId",
  "maximumEvidenceAgeSeconds",
  "maximumReceiptLifetimeSeconds",
  "npmPackageName",
  "productionEnvironmentId",
  "repository",
];
const ENVELOPE_KEYS = ["keyId", "payload", "schemaVersion", "signatureBase64"];
const PAYLOAD_KEYS = [
  "artifacts",
  "developmentDeployment",
  "developmentSmoke",
  "expiresAt",
  "issuedAt",
  "qualification",
  "repository",
  "schemaVersion",
  "source",
];
const SOURCE_KEYS = ["ref", "sha", "treeSha"];
const ARTIFACT_KEYS = ["configuration", "containers", "migrations", "npm"];
const CONFIGURATION_KEYS = ["runtimeDigest", "schemaDigest"];
const CONTAINER_KEYS = [
  "hostedImageDigest",
  "hostedNpmArtifacts",
  "webImageDigest",
];
const HOSTED_NPM_ARTIFACT_KEYS = [
  "indexDigest",
  "packageName",
  "platforms",
  "tarballDigest",
  "version",
];
const HOSTED_NPM_PLATFORM_KEYS = ["linux/amd64", "linux/arm64"];
const HOSTED_NPM_PLATFORM_ARTIFACT_KEYS = [
  "imageManifestDigest",
  "tarballDigest",
];
const MIGRATION_KEYS = ["bundleDigest", "head"];
const NPM_KEYS = [
  "packageName",
  "runtimeCanaryReceiptDigest",
  "tarballDigest",
  "version",
];
const QUALIFICATION_KEYS = ["checks", "finishedAt", "receiptDigest", "source"];
const CHECK_KEYS = ["evidenceDigest", "id", "result"];
const DEPLOYMENT_KEYS = [
  "artifacts",
  "deployedAt",
  "deploymentId",
  "environmentId",
  "receiptDigest",
  "source",
];
const SMOKE_KEYS = [
  "environmentId",
  "finishedAt",
  "observedArtifacts",
  "observedDeploymentId",
  "observedSource",
  "receiptDigest",
  "result",
];
const REQUEST_KEYS = [
  "artifacts",
  "candidateReceiptDigest",
  "fromEnvironmentId",
  "schemaVersion",
  "source",
  "toEnvironmentId",
];

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, expected, label) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} is invalid`,
  );
  invariant(
    canonicalJson(Object.keys(value).sort()) === canonicalJson(expected),
    `${label} keys drift`,
  );
}

function assertIntegerInRange(value, minimum, maximum, label) {
  invariant(
    Number.isSafeInteger(value) && value >= minimum && value <= maximum,
    `${label} is invalid`,
  );
}

function identifier(value, label) {
  invariant(
    typeof value === "string" && IDENTIFIER.test(value),
    `${label} is invalid`,
  );
  return value;
}

function digest(value, label) {
  invariant(
    typeof value === "string" && SHA256.test(value),
    `${label} is invalid`,
  );
  return value;
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

function sameValue(left, right, label) {
  invariant(canonicalJson(left) === canonicalJson(right), `${label} differs`);
}

function canonicalCopy(value) {
  return JSON.parse(canonicalJson(value));
}

function validateTrustPolicy(policy) {
  assertExactKeys(policy, TRUST_KEYS, "development candidate trust policy");
  invariant(
    REPOSITORY.test(policy.repository),
    "candidate repository policy is invalid",
  );
  identifier(
    policy.developmentEnvironmentId,
    "development environment policy ID",
  );
  identifier(
    policy.productionEnvironmentId,
    "production environment policy ID",
  );
  invariant(
    policy.developmentEnvironmentId !== policy.productionEnvironmentId,
    "development and production environment policy IDs are not separate",
  );
  invariant(
    PACKAGE.test(policy.npmPackageName),
    "candidate npm package policy is invalid",
  );
  digest(policy.candidateKeyId, "candidate signing key ID");
  invariant(
    typeof policy.candidatePublicKeySpkiBase64 === "string" &&
      BASE64.test(policy.candidatePublicKeySpkiBase64),
    "candidate public key is invalid",
  );
  invariant(
    signingKeyId(policy.candidatePublicKeySpkiBase64) === policy.candidateKeyId,
    "candidate signing key identity differs",
  );
  assertIntegerInRange(
    policy.maximumReceiptLifetimeSeconds,
    60,
    86_400,
    "candidate maximum receipt lifetime",
  );
  assertIntegerInRange(
    policy.maximumEvidenceAgeSeconds,
    60,
    86_400,
    "candidate maximum evidence age",
  );
  assertIntegerInRange(policy.clockSkewSeconds, 0, 300, "candidate clock skew");
  return policy;
}

function validateSource(source, label) {
  assertExactKeys(source, SOURCE_KEYS, label);
  invariant(source.ref === "refs/heads/main", `${label} is not accepted main`);
  invariant(GIT_SHA.test(source.sha), `${label} SHA is invalid`);
  invariant(GIT_SHA.test(source.treeSha), `${label} tree SHA is invalid`);
  return source;
}

function validateArtifacts(artifacts, policy, label) {
  assertExactKeys(artifacts, ARTIFACT_KEYS, label);
  assertExactKeys(
    artifacts.configuration,
    CONFIGURATION_KEYS,
    `${label} configuration`,
  );
  digest(
    artifacts.configuration.runtimeDigest,
    `${label} runtime configuration digest`,
  );
  digest(
    artifacts.configuration.schemaDigest,
    `${label} configuration schema digest`,
  );

  assertExactKeys(artifacts.containers, CONTAINER_KEYS, `${label} containers`);
  digest(
    artifacts.containers.hostedImageDigest,
    `${label} hosted image digest`,
  );
  digest(artifacts.containers.webImageDigest, `${label} web image digest`);
  invariant(
    artifacts.containers.hostedImageDigest !==
      artifacts.containers.webImageDigest,
    `${label} container digests are not distinct`,
  );

  const hostedNpm = artifacts.containers.hostedNpmArtifacts;
  assertExactKeys(
    hostedNpm,
    HOSTED_NPM_ARTIFACT_KEYS,
    `${label} hosted npm artifacts`,
  );
  digest(hostedNpm.indexDigest, `${label} hosted npm index digest`);
  invariant(
    hostedNpm.indexDigest === artifacts.containers.hostedImageDigest,
    `${label} hosted npm index does not bind the hosted image`,
  );
  assertExactKeys(
    hostedNpm.platforms,
    HOSTED_NPM_PLATFORM_KEYS,
    `${label} hosted npm platforms`,
  );
  const platformImageDigests = [];
  for (const platform of HOSTED_NPM_PLATFORM_KEYS) {
    const platformArtifact = hostedNpm.platforms[platform];
    assertExactKeys(
      platformArtifact,
      HOSTED_NPM_PLATFORM_ARTIFACT_KEYS,
      `${label} hosted npm ${platform}`,
    );
    platformImageDigests.push(
      digest(
        platformArtifact.imageManifestDigest,
        `${label} hosted npm ${platform} image digest`,
      ),
    );
    digest(
      platformArtifact.tarballDigest,
      `${label} hosted npm ${platform} tarball digest`,
    );
  }
  invariant(
    new Set(platformImageDigests).size === HOSTED_NPM_PLATFORM_KEYS.length,
    `${label} hosted npm platform image digests are not distinct`,
  );

  assertExactKeys(artifacts.migrations, MIGRATION_KEYS, `${label} migrations`);
  digest(artifacts.migrations.bundleDigest, `${label} migration bundle digest`);
  invariant(
    typeof artifacts.migrations.head === "string" &&
      MIGRATION_HEAD.test(artifacts.migrations.head),
    `${label} migration head is invalid`,
  );

  assertExactKeys(artifacts.npm, NPM_KEYS, `${label} npm artifact`);
  invariant(
    artifacts.npm.packageName === policy.npmPackageName,
    `${label} npm package differs from policy`,
  );
  invariant(
    SEMVER.test(artifacts.npm.version),
    `${label} npm version is invalid`,
  );
  digest(artifacts.npm.tarballDigest, `${label} npm tarball digest`);
  digest(
    artifacts.npm.runtimeCanaryReceiptDigest,
    `${label} npm runtime-canary receipt digest`,
  );
  invariant(
    hostedNpm.packageName === artifacts.npm.packageName,
    `${label} hosted npm package differs`,
  );
  invariant(
    hostedNpm.version === artifacts.npm.version,
    `${label} hosted npm version differs`,
  );
  invariant(
    hostedNpm.tarballDigest === artifacts.npm.tarballDigest,
    `${label} hosted npm tarball differs`,
  );
  for (const platform of HOSTED_NPM_PLATFORM_KEYS) {
    invariant(
      hostedNpm.platforms[platform].tarballDigest ===
        artifacts.npm.tarballDigest,
      `${label} hosted npm ${platform} tarball differs`,
    );
  }
  return artifacts;
}

function validateQualification(value, source, artifacts) {
  assertExactKeys(value, QUALIFICATION_KEYS, "candidate qualification");
  validateSource(value.source, "candidate qualification source");
  sameValue(value.source, source, "candidate qualification source");
  digest(value.receiptDigest, "candidate qualification receipt digest");
  invariant(
    Array.isArray(value.checks),
    "candidate qualification checks are invalid",
  );
  const checkIds = [];
  for (const check of value.checks) {
    assertExactKeys(check, CHECK_KEYS, "candidate qualification check");
    checkIds.push(identifier(check.id, "candidate qualification check ID"));
    invariant(
      check.result === "passed",
      `candidate qualification check ${check.id} did not pass`,
    );
    digest(
      check.evidenceDigest,
      `candidate qualification check ${check.id} evidence digest`,
    );
  }
  invariant(
    canonicalJson(checkIds) === canonicalJson(REQUIRED_CHECKS),
    "candidate qualification check coverage or order differs",
  );
  const runtimeCanary = value.checks.find(
    (check) => check.id === NPM_RUNTIME_CANARY_CHECK_ID,
  );
  invariant(
    runtimeCanary.evidenceDigest === artifacts.npm.runtimeCanaryReceiptDigest,
    "candidate runtime-canary check does not bind its signed receipt",
  );
  const hostedNpmArtifact = value.checks.find(
    (check) => check.id === HOSTED_NPM_ARTIFACT_CHECK_ID,
  );
  invariant(
    hostedNpmArtifact.evidenceDigest ===
      sha256Digest(artifacts.containers.hostedNpmArtifacts),
    "candidate hosted npm artifact check does not bind its platform evidence",
  );
  return parseTime(value.finishedAt, "candidate qualification finishedAt");
}

function validateDevelopmentDeployment(value, source, artifacts, policy) {
  assertExactKeys(value, DEPLOYMENT_KEYS, "development deployment receipt");
  invariant(
    value.environmentId === policy.developmentEnvironmentId,
    "development deployment environment differs",
  );
  identifier(value.deploymentId, "development deployment ID");
  digest(value.receiptDigest, "development deployment receipt digest");
  validateSource(value.source, "development deployment source");
  validateArtifacts(
    value.artifacts,
    policy,
    "development deployment artifacts",
  );
  sameValue(value.source, source, "development deployment source");
  sameValue(value.artifacts, artifacts, "development deployment artifacts");
  return parseTime(value.deployedAt, "development deployment deployedAt");
}

function validateDevelopmentSmoke(
  value,
  source,
  artifacts,
  deployment,
  policy,
) {
  assertExactKeys(value, SMOKE_KEYS, "development smoke receipt");
  invariant(
    value.environmentId === policy.developmentEnvironmentId,
    "development smoke environment differs",
  );
  invariant(value.result === "passed", "development smoke did not pass");
  invariant(
    value.observedDeploymentId === deployment.deploymentId,
    "development smoke deployment identity differs",
  );
  digest(value.receiptDigest, "development smoke receipt digest");
  validateSource(value.observedSource, "development smoke source");
  validateArtifacts(
    value.observedArtifacts,
    policy,
    "development smoke artifacts",
  );
  sameValue(value.observedSource, source, "development smoke source");
  sameValue(value.observedArtifacts, artifacts, "development smoke artifacts");
  return parseTime(value.finishedAt, "development smoke finishedAt");
}

function validateEvidenceTimes({
  qualificationAt,
  deployedAt,
  smokeAt,
  issuedAt,
  policy,
  now,
}) {
  const skew = policy.clockSkewSeconds * 1000;
  invariant(
    qualificationAt <= deployedAt,
    "development deployed before qualification completed",
  );
  invariant(
    deployedAt <= smokeAt,
    "development smoke completed before deployment",
  );
  invariant(
    smokeAt <= issuedAt + skew,
    "candidate receipt predates development smoke",
  );
  const oldest = now - policy.maximumEvidenceAgeSeconds * 1000;
  invariant(
    qualificationAt >= oldest,
    "candidate qualification evidence is stale",
  );
  invariant(deployedAt >= oldest, "development deployment evidence is stale");
  invariant(smokeAt >= oldest, "development smoke evidence is stale");
  invariant(
    qualificationAt <= now + skew,
    "candidate qualification evidence is in the future",
  );
  invariant(
    deployedAt <= now + skew,
    "development deployment evidence is in the future",
  );
  invariant(
    smokeAt <= now + skew,
    "development smoke evidence is in the future",
  );
}

function validatePayload({ payload, policy, expectedSource, now }) {
  assertExactKeys(payload, PAYLOAD_KEYS, "development candidate receipt");
  invariant(
    payload.schemaVersion === DEVELOPMENT_CANDIDATE_SCHEMA,
    "development candidate receipt schema differs",
  );
  invariant(
    payload.repository === policy.repository,
    "development candidate repository differs",
  );
  const source = validateSource(payload.source, "development candidate source");
  validateSource(expectedSource, "externally selected source");
  sameValue(source, expectedSource, "development candidate source");
  const artifacts = validateArtifacts(
    payload.artifacts,
    policy,
    "development candidate artifacts",
  );

  const issuedAt = parseTime(
    payload.issuedAt,
    "development candidate issuedAt",
  );
  const expiresAt = parseTime(
    payload.expiresAt,
    "development candidate expiresAt",
  );
  const lifetime = expiresAt - issuedAt;
  invariant(lifetime > 0, "development candidate receipt lifetime is invalid");
  invariant(
    lifetime <= policy.maximumReceiptLifetimeSeconds * 1000,
    "development candidate receipt lifetime is too long",
  );
  const skew = policy.clockSkewSeconds * 1000;
  invariant(
    issuedAt <= now + skew,
    "development candidate receipt is not active yet",
  );
  invariant(expiresAt >= now - skew, "development candidate receipt expired");

  const qualificationAt = validateQualification(
    payload.qualification,
    source,
    artifacts,
  );
  const deployedAt = validateDevelopmentDeployment(
    payload.developmentDeployment,
    source,
    artifacts,
    policy,
  );
  const smokeAt = validateDevelopmentSmoke(
    payload.developmentSmoke,
    source,
    artifacts,
    payload.developmentDeployment,
    policy,
  );
  validateEvidenceTimes({
    qualificationAt,
    deployedAt,
    smokeAt,
    issuedAt,
    policy,
    now,
  });
  return payload;
}

function verifyEnvelope({ signedCandidate, policy, expectedSource, now }) {
  assertExactKeys(
    signedCandidate,
    ENVELOPE_KEYS,
    "signed development candidate envelope",
  );
  invariant(
    signedCandidate.schemaVersion === SIGNED_DEVELOPMENT_CANDIDATE_SCHEMA,
    "signed development candidate envelope schema differs",
  );
  invariant(
    signedCandidate.keyId === policy.candidateKeyId,
    "candidate signing key differs",
  );
  invariant(
    typeof signedCandidate.signatureBase64 === "string" &&
      BASE64.test(signedCandidate.signatureBase64),
    "development candidate signature is missing or invalid",
  );
  const publicKey = createPublicKey({
    key: Buffer.from(policy.candidatePublicKeySpkiBase64, "base64"),
    format: "der",
    type: "spki",
  });
  invariant(
    publicKey.asymmetricKeyType === "ed25519",
    "candidate signing key is not Ed25519",
  );
  invariant(
    verify(
      null,
      Buffer.from(canonicalJson(signedCandidate.payload)),
      publicKey,
      Buffer.from(signedCandidate.signatureBase64, "base64"),
    ),
    "development candidate signature is invalid",
  );
  return validatePayload({
    payload: signedCandidate.payload,
    policy,
    expectedSource,
    now,
  });
}

export function signingKeyId(publicKeySpkiBase64) {
  invariant(
    typeof publicKeySpkiBase64 === "string" && BASE64.test(publicKeySpkiBase64),
    "candidate public key is invalid",
  );
  return `sha256:${createHash("sha256")
    .update(Buffer.from(publicKeySpkiBase64, "base64"))
    .digest("hex")}`;
}

export function candidateReceiptDigest(signedCandidate) {
  return sha256Digest(signedCandidate);
}

export function validateDevelopmentCandidate({
  signedCandidate,
  trustPolicy,
  expectedSource,
  now = Date.now(),
}) {
  invariant(Number.isFinite(now), "candidate validation time is invalid");
  const policy = validateTrustPolicy(trustPolicy);
  return canonicalCopy(
    verifyEnvelope({ signedCandidate, policy, expectedSource, now }),
  );
}

export function selectProductionCandidate({
  signedCandidate,
  trustPolicy,
  expectedSource,
  promotionRequest,
  now = Date.now(),
}) {
  const payload = validateDevelopmentCandidate({
    signedCandidate,
    trustPolicy,
    expectedSource,
    now,
  });
  assertExactKeys(
    promotionRequest,
    REQUEST_KEYS,
    "production promotion request",
  );
  invariant(
    promotionRequest.schemaVersion === PRODUCTION_PROMOTION_REQUEST_SCHEMA,
    "production promotion request schema differs",
  );
  invariant(
    promotionRequest.fromEnvironmentId === trustPolicy.developmentEnvironmentId,
    "production promotion source environment differs",
  );
  invariant(
    promotionRequest.toEnvironmentId === trustPolicy.productionEnvironmentId,
    "production promotion target environment differs",
  );
  invariant(
    promotionRequest.candidateReceiptDigest ===
      candidateReceiptDigest(signedCandidate),
    "production promotion candidate receipt differs",
  );
  validateSource(promotionRequest.source, "production promotion source");
  validateArtifacts(
    promotionRequest.artifacts,
    trustPolicy,
    "production promotion artifacts",
  );
  sameValue(
    promotionRequest.source,
    payload.source,
    "production promotion source",
  );
  sameValue(
    promotionRequest.artifacts,
    payload.artifacts,
    "production promotion artifacts",
  );

  return {
    schemaVersion: PRODUCTION_PROMOTION_SELECTION_SCHEMA,
    selectedAt: new Date(now).toISOString(),
    repository: payload.repository,
    fromEnvironmentId: promotionRequest.fromEnvironmentId,
    toEnvironmentId: promotionRequest.toEnvironmentId,
    source: canonicalCopy(payload.source),
    artifacts: canonicalCopy(payload.artifacts),
    candidateReceiptDigest: promotionRequest.candidateReceiptDigest,
    qualificationReceiptDigest: payload.qualification.receiptDigest,
    developmentDeploymentReceiptDigest:
      payload.developmentDeployment.receiptDigest,
    developmentSmokeReceiptDigest: payload.developmentSmoke.receiptDigest,
  };
}
