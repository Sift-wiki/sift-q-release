#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import {
  closeSync,
  copyFileSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  packageManifestFromTarball,
  PACKAGE_REPOSITORY,
} from "./verify-exact-candidate.mjs";
import { EXPECTED_MAINTAINERS } from "./npm-provider-state.mjs";

export const NEXT_TRANSITION_SCHEMA = "sift-q-npm-next-transition/v2";
export const LATEST_PROMOTION_BINDING_SCHEMA =
  "sift-q-npm-latest-promotion-binding/v1";
export const SIGNED_LATEST_PROMOTION_SCHEMA =
  "sift-q-npm-latest-promotion-receipt/v1";
export const LATEST_PROMOTION_TRUST_SCHEMA =
  "sift-q-npm-latest-promotion-trust/v1";
export const LATEST_PROMOTION_RESULT_SCHEMA =
  "sift-q-npm-latest-promotion-verification/v1";
export const PACKAGE_NAME = "@sift-wiki/q";
export const SOURCE_REPOSITORY = "Sift-wiki/sift-q-refactor";
export const RELEASE_REPOSITORY = "Sift-wiki/sift-q-release";
export const CANONICAL_REGISTRY = "https://registry.npmjs.org/";
export const PRODUCTION_ACTORS = ["Unobtainiumrock", "orange-juice-1024"];

const SHA = /^[0-9a-f]{40}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]{86}==$/;
const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const AUTHORIZATION_ID = /^[A-Za-z0-9._-]{16,128}$/;
const MAX_PROMOTION_AUTHORIZATION_WINDOW_MS = 15 * 60 * 1000;

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

function sha512Integrity(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

function instant(value, label) {
  invariant(ISO_INSTANT.test(value), `${label} is invalid`);
  const milliseconds = Date.parse(value);
  invariant(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    `${label} is invalid`,
  );
  return milliseconds;
}

function compareStableVersions(left, right) {
  invariant(
    STABLE_VERSION.test(left) && STABLE_VERSION.test(right),
    "stable version comparison input is invalid",
  );
  const leftParts = left.split(".").map(BigInt);
  const rightParts = right.split(".").map(BigInt);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] > rightParts[index]) return 1;
    if (leftParts[index] < rightParts[index]) return -1;
  }
  return 0;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalValue(value))}\n`;
}

function jsonFile(path, label) {
  let value;
  try {
    value = JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  return value;
}

function regularFile(path, label) {
  const stat = lstatSync(resolve(path));
  invariant(
    stat.isFile() && !stat.isSymbolicLink(),
    `${label} is not a regular file`,
  );
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

function run(command, args, options, label) {
  const result = spawnSync(command, args, {
    ...options,
    encoding: "utf8",
    timeout: 60_000,
    maxBuffer: 128 * 1024,
  });
  invariant(result.error === undefined, `${label} could not execute`);
  invariant(
    result.status === 0,
    `${label} failed with exit ${String(result.status)}`,
  );
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function treeSnapshot(root) {
  const entries = [];
  function visit(directory, prefix) {
    const children = readdirSync(directory, { withFileTypes: true }).sort(
      (a, b) => a.name.localeCompare(b.name, "en"),
    );
    for (const child of children) {
      const path = join(directory, child.name);
      const relative = prefix === "" ? child.name : `${prefix}/${child.name}`;
      const stat = lstatSync(path);
      if (stat.isDirectory()) {
        entries.push({
          path: relative,
          type: "directory",
          mode: stat.mode & 0o777,
        });
        visit(path, relative);
      } else if (stat.isFile()) {
        entries.push({
          path: relative,
          type: "file",
          mode: stat.mode & 0o777,
          size: stat.size,
          digest: sha256(readFileSync(path)),
        });
      } else if (stat.isSymbolicLink()) {
        entries.push({
          path: relative,
          type: "symlink",
          target: readlinkSync(path),
        });
      } else {
        throw new Error(`canary tree contains unsupported entry ${relative}`);
      }
    }
  }
  visit(root, "");
  return entries;
}

function unchangedTree(root, before, label) {
  invariant(
    canonicalJson(treeSnapshot(root)) === canonicalJson(before),
    `registry canary wrote ${label}`,
  );
}

function validateRegistryMetadata(value, version) {
  invariant(value?.name === PACKAGE_NAME, "registry package name differs");
  invariant(value.version === version, "registry package version differs");
  invariant(
    value.dist !== null && typeof value.dist === "object",
    "registry dist metadata is invalid",
  );
  invariant(
    SHA512_INTEGRITY.test(value.dist.integrity ?? ""),
    "registry integrity is invalid",
  );
  invariant(SHA1.test(value.dist.shasum ?? ""), "registry shasum is invalid");
  let tarball;
  try {
    tarball = new URL(value.dist.tarball);
  } catch {
    throw new Error("registry tarball URL is invalid");
  }
  invariant(
    tarball.protocol === "https:" &&
      tarball.hostname === "registry.npmjs.org" &&
      tarball.port === "" &&
      tarball.username === "" &&
      tarball.password === "" &&
      tarball.search === "" &&
      tarball.hash === "" &&
      tarball.pathname === `/@sift-wiki/q/-/q-${version}.tgz`,
    "registry tarball URL is not canonical",
  );
  return {
    integrity: value.dist.integrity,
    shasum: value.dist.shasum,
    tarballUrl: tarball.href,
  };
}

export function runRegistryCanary(tarballPath, version) {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-canary-"));
  try {
    const home = join(root, "home");
    const consumer = join(root, "consumer");
    const runDirectory = join(root, "run");
    mkdirSync(home, { mode: 0o700 });
    mkdirSync(consumer, { mode: 0o700 });
    mkdirSync(runDirectory, { mode: 0o700 });
    writeFileSync(
      join(consumer, "package.json"),
      `${JSON.stringify({ name: "sift-q-registry-canary-consumer", private: true })}\n`,
      { mode: 0o600 },
    );
    copyFileSync(resolve(tarballPath), join(consumer, "registry-package.tgz"));
    const env = {
      CI: "1",
      HOME: home,
      NPM_CONFIG_CACHE: join(root, "npm-cache"),
      NPM_CONFIG_REGISTRY: CANONICAL_REGISTRY,
      NPM_CONFIG_USERCONFIG: "/dev/null",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      USERPROFILE: home,
      XDG_CACHE_HOME: join(home, ".cache"),
      XDG_CONFIG_HOME: join(home, ".config"),
      XDG_DATA_HOME: join(home, ".local", "share"),
    };
    const install = run(
      "npm",
      [
        "install",
        "./registry-package.tgz",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
      ],
      { cwd: consumer, env },
      "registry-byte install",
    );
    invariant(install.stderr === "", "registry-byte install wrote to stderr");
    const binary = join(consumer, "node_modules", ".bin", "sift-q");
    const binaryStat = lstatSync(binary);
    invariant(
      binaryStat.isFile() || binaryStat.isSymbolicLink(),
      "installed sift-q executable is missing",
    );
    const runtimeEnv = {
      ...env,
      PATH: `${join(consumer, "node_modules", ".bin")}:${env.PATH}`,
    };
    const homeBefore = treeSnapshot(home);
    const consumerBefore = treeSnapshot(consumer);
    const runBefore = treeSnapshot(runDirectory);
    invariant(homeBefore.length === 0, "registry canary HOME is not empty");
    const versionResult = run(
      binary,
      ["--version"],
      { cwd: runDirectory, env: runtimeEnv },
      "installed sift-q --version",
    );
    invariant(
      versionResult.stdout === `sift-q ${version}\n` &&
        versionResult.stderr === "",
      "installed sift-q version output differs",
    );
    const dryRun = run(
      binary,
      ["--dry-run", "--json", "--client", "claude"],
      { cwd: runDirectory, env: runtimeEnv },
      "installed sift-q dry-run",
    );
    invariant(dryRun.stderr === "", "installed sift-q dry-run wrote to stderr");
    let report;
    try {
      report = JSON.parse(dryRun.stdout);
    } catch {
      throw new Error("installed sift-q dry-run output is not JSON");
    }
    const plan = report?.plan?.map((step) => step?.id);
    invariant(
      report?.detection?.platform?.ok === true,
      "installed sift-q platform canary failed",
    );
    invariant(
      JSON.stringify(plan) ===
        JSON.stringify(["fetch-hosted-content", "register-claude"]),
      "installed sift-q dry-run plan differs",
    );
    invariant(
      Array.isArray(report?.result?.stepResults) &&
        report.result.stepResults.length === 0,
      "installed sift-q dry-run performed writes",
    );
    unchangedTree(home, homeBefore, "HOME or XDG surfaces");
    unchangedTree(consumer, consumerBefore, "the installed consumer tree");
    unchangedTree(runDirectory, runBefore, "the run directory");
    return {
      dryRunCommand: "sift-q --dry-run --json --client claude",
      dryRunPlan: plan,
      homeIsolation: "fresh-empty-temporary-home",
      installCommand:
        "npm install ./registry-package.tgz --ignore-scripts --no-audit --no-fund --package-lock=false",
      versionCommand: "sift-q --version",
      versionOutput: versionResult.stdout.trimEnd(),
      writesObserved: 0,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export function validateNextTransitionEvidence(value) {
  exactKeys(
    value,
    [
      "artifact",
      "authority",
      "candidate",
      "canary",
      "observedAt",
      "package",
      "registry",
      "schemaVersion",
      "source",
    ],
    "transition evidence",
  );
  invariant(
    value.schemaVersion === NEXT_TRANSITION_SCHEMA,
    "transition schema differs",
  );
  invariant(
    value.authority === "unsigned-non-authoritative-transition-evidence",
    "transition authority differs",
  );
  instant(value.observedAt, "transition observedAt");
  exactKeys(value.package, ["name", "version"], "transition package");
  invariant(
    value.package.name === PACKAGE_NAME &&
      STABLE_VERSION.test(value.package.version),
    "transition package differs",
  );
  exactKeys(
    value.source,
    ["repository", "sha", "treeSha"],
    "transition source",
  );
  invariant(
    value.source.repository === SOURCE_REPOSITORY &&
      SHA.test(value.source.sha) &&
      SHA.test(value.source.treeSha),
    "transition source differs",
  );
  exactKeys(
    value.candidate,
    ["receiptDigest", "runAttempt", "runId"],
    "transition candidate",
  );
  invariant(
    SHA256.test(value.candidate.receiptDigest),
    "transition candidate receipt digest is invalid",
  );
  invariant(
    Number.isSafeInteger(value.candidate.runId) && value.candidate.runId > 0,
    "transition run id is invalid",
  );
  invariant(
    Number.isSafeInteger(value.candidate.runAttempt) &&
      value.candidate.runAttempt > 0,
    "transition run attempt is invalid",
  );
  exactKeys(value.artifact, ["tarballDigest"], "transition artifact");
  invariant(
    SHA256.test(value.artifact.tarballDigest),
    "transition tarball digest is invalid",
  );
  exactKeys(
    value.registry,
    [
      "distTag",
      "distTagVersion",
      "integrity",
      "latestAfter",
      "latestBefore",
      "maintainers",
      "nextBefore",
      "registry",
      "shasum",
      "tarballUrl",
    ],
    "transition registry",
  );
  invariant(
    value.registry.registry === CANONICAL_REGISTRY &&
      value.registry.distTag === "next" &&
      value.registry.distTagVersion === value.package.version &&
      value.registry.latestBefore === value.registry.latestAfter &&
      canonicalJson(value.registry.maintainers) ===
        canonicalJson(EXPECTED_MAINTAINERS) &&
      STABLE_VERSION.test(value.registry.latestBefore) &&
      (value.registry.nextBefore === null ||
        value.registry.nextBefore === value.registry.latestBefore) &&
      SHA512_INTEGRITY.test(value.registry.integrity ?? "") &&
      SHA1.test(value.registry.shasum),
    "transition registry state differs",
  );
  let registryTarballUrl;
  try {
    registryTarballUrl = new URL(value.registry.tarballUrl);
  } catch {
    throw new Error("transition registry tarball URL is invalid");
  }
  invariant(
    registryTarballUrl.protocol === "https:" &&
      registryTarballUrl.hostname === "registry.npmjs.org" &&
      registryTarballUrl.port === "" &&
      registryTarballUrl.username === "" &&
      registryTarballUrl.password === "" &&
      registryTarballUrl.search === "" &&
      registryTarballUrl.hash === "" &&
      registryTarballUrl.pathname ===
        `/@sift-wiki/q/-/q-${value.package.version}.tgz`,
    "transition registry tarball URL differs",
  );
  exactKeys(
    value.canary,
    [
      "dryRunCommand",
      "dryRunPlan",
      "homeIsolation",
      "installCommand",
      "versionCommand",
      "versionOutput",
      "writesObserved",
    ],
    "transition canary",
  );
  invariant(
    value.canary.homeIsolation === "fresh-empty-temporary-home" &&
      value.canary.installCommand ===
        "npm install ./registry-package.tgz --ignore-scripts --no-audit --no-fund --package-lock=false" &&
      value.canary.versionCommand === "sift-q --version" &&
      value.canary.versionOutput === `sift-q ${value.package.version}` &&
      value.canary.dryRunCommand ===
        "sift-q --dry-run --json --client claude" &&
      value.canary.writesObserved === 0 &&
      JSON.stringify(value.canary.dryRunPlan) ===
        JSON.stringify(["fetch-hosted-content", "register-claude"]),
    "transition canary differs",
  );
  return value;
}

export function promotionBindingFor(evidence) {
  validateNextTransitionEvidence(evidence);
  return {
    schemaVersion: LATEST_PROMOTION_BINDING_SCHEMA,
    transitionEvidenceDigest: sha256(canonicalJson(evidence)),
    packageName: evidence.package.name,
    version: evidence.package.version,
    sourceSha: evidence.source.sha,
    treeSha: evidence.source.treeSha,
    candidateReceiptDigest: evidence.candidate.receiptDigest,
    tarballDigest: evidence.artifact.tarballDigest,
    fromDistTag: "next",
    toDistTag: "latest",
    expectedLatestBefore: evidence.registry.latestBefore,
    expectedNextBefore: evidence.registry.nextBefore,
    expectedNextVersion: evidence.package.version,
  };
}

export function validatePromotionBinding(binding, evidence) {
  exactKeys(
    binding,
    [
      "candidateReceiptDigest",
      "expectedLatestBefore",
      "expectedNextBefore",
      "expectedNextVersion",
      "fromDistTag",
      "packageName",
      "schemaVersion",
      "sourceSha",
      "tarballDigest",
      "toDistTag",
      "transitionEvidenceDigest",
      "treeSha",
      "version",
    ],
    "promotion binding",
  );
  invariant(
    canonicalJson(binding) === canonicalJson(promotionBindingFor(evidence)),
    "promotion binding differs from transition evidence",
  );
  return binding;
}

function promotionAuthorizationBody(receipt) {
  return {
    schemaVersion: receipt.schemaVersion,
    algorithm: receipt.algorithm,
    keyId: receipt.keyId,
    authorizationId: receipt.authorizationId,
    authorizedAt: receipt.authorizedAt,
    expiresAt: receipt.expiresAt,
    binding: receipt.binding,
  };
}

export function verifySignedPromotionReceipt({
  receipt,
  trustPolicy,
  evidence,
  currentLatest,
  currentNext,
  promotionComplete = false,
  now = () => new Date(),
}) {
  exactKeys(
    receipt,
    [
      "algorithm",
      "authorizationId",
      "authorizedAt",
      "binding",
      "expiresAt",
      "keyId",
      "schemaVersion",
      "signature",
    ],
    "signed promotion receipt",
  );
  invariant(
    receipt.schemaVersion === SIGNED_LATEST_PROMOTION_SCHEMA &&
      receipt.algorithm === "Ed25519" &&
      /^[A-Za-z0-9._-]{1,128}$/.test(receipt.keyId) &&
      AUTHORIZATION_ID.test(receipt.authorizationId),
    "signed promotion receipt identity differs",
  );
  invariant(
    typeof receipt.signature === "string" &&
      /^[A-Za-z0-9+/]{86}==$/.test(receipt.signature),
    "signed promotion receipt signature is invalid",
  );
  const authorizedAt = instant(receipt.authorizedAt, "promotion authorizedAt");
  const expiresAt = instant(receipt.expiresAt, "promotion expiresAt");
  const nowMilliseconds = now().getTime();
  invariant(
    Number.isFinite(nowMilliseconds),
    "promotion verification time is invalid",
  );
  invariant(
    authorizedAt <= nowMilliseconds,
    "promotion authorization is future-dated",
  );
  invariant(expiresAt > nowMilliseconds, "promotion authorization is expired");
  invariant(
    expiresAt > authorizedAt,
    "promotion authorization window is invalid",
  );
  invariant(
    expiresAt - authorizedAt <= MAX_PROMOTION_AUTHORIZATION_WINDOW_MS,
    "promotion authorization window is too long",
  );
  exactKeys(trustPolicy, ["keys", "schemaVersion"], "promotion trust policy");
  invariant(
    trustPolicy.schemaVersion === LATEST_PROMOTION_TRUST_SCHEMA &&
      Array.isArray(trustPolicy.keys) &&
      trustPolicy.keys.length > 0,
    "promotion trust policy identity differs",
  );
  const keyIds = [];
  const keyFingerprints = [];
  const trustedKeys = new Map();
  for (const key of trustPolicy.keys) {
    exactKeys(
      key,
      ["algorithm", "keyId", "publicKeyPem"],
      "promotion trust key",
    );
    invariant(
      key.algorithm === "Ed25519" &&
        /^[A-Za-z0-9._-]{1,128}$/.test(key.keyId) &&
        typeof key.publicKeyPem === "string" &&
        key.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----"),
      "promotion trust key differs",
    );
    let publicKey;
    try {
      publicKey = createPublicKey(key.publicKeyPem);
    } catch {
      throw new Error("promotion trust public key is invalid");
    }
    invariant(
      publicKey.asymmetricKeyType === "ed25519",
      "promotion trust key is not Ed25519",
    );
    keyIds.push(key.keyId);
    keyFingerprints.push(
      sha256(publicKey.export({ format: "der", type: "spki" })),
    );
    trustedKeys.set(key.keyId, publicKey);
  }
  invariant(
    new Set(keyIds).size === keyIds.length,
    "promotion trust key IDs are duplicated",
  );
  invariant(
    new Set(keyFingerprints).size === keyFingerprints.length,
    "promotion trust key material is duplicated",
  );
  const publicKey = trustedKeys.get(receipt.keyId);
  invariant(publicKey !== undefined, "promotion receipt signer is not trusted");
  const signature = Buffer.from(receipt.signature, "base64");
  invariant(
    signature.length === 64,
    "signed promotion receipt signature is invalid",
  );
  invariant(
    verifySignature(
      null,
      Buffer.from(canonicalJson(promotionAuthorizationBody(receipt))),
      publicKey,
      signature,
    ),
    "signed promotion receipt signature verification failed",
  );
  const binding = validatePromotionBinding(receipt.binding, evidence);
  invariant(
    currentLatest ===
      (promotionComplete ? binding.version : binding.expectedLatestBefore),
    promotionComplete
      ? "current latest does not select the signed promoted version"
      : "current latest differs from the signed promotion precondition",
  );
  invariant(
    currentNext === binding.expectedNextVersion,
    "current next differs from the signed promotion precondition",
  );
  return { authorizationId: receipt.authorizationId, binding };
}

export function verifyCompletedPromotion({
  receipt,
  trustPolicy,
  evidence,
  currentLatest,
  currentNext,
  registryMetadata,
  registryTarballPath,
  actor,
  triggeringActor,
  releaseRepository,
  releaseSha,
  workflowRunId,
  workflowRunAttempt,
  transitionRunId,
  outputPath,
  now = () => new Date(),
}) {
  invariant(
    PRODUCTION_ACTORS.includes(actor),
    "promotion actor is not a production owner",
  );
  invariant(
    PRODUCTION_ACTORS.includes(triggeringActor),
    "promotion triggering actor is not a production owner",
  );
  invariant(
    releaseRepository === RELEASE_REPOSITORY && SHA.test(releaseSha),
    "promotion release identity differs",
  );
  for (const [value, label] of [
    [workflowRunId, "promotion workflow run id"],
    [workflowRunAttempt, "promotion workflow run attempt"],
    [transitionRunId, "promotion transition run id"],
  ]) {
    invariant(Number.isSafeInteger(value) && value > 0, `${label} is invalid`);
  }
  const verified = verifySignedPromotionReceipt({
    receipt,
    trustPolicy,
    evidence,
    currentLatest,
    currentNext,
    promotionComplete: true,
    now,
  });
  regularFile(registryTarballPath, "promoted registry tarball");
  const bytes = readFileSync(resolve(registryTarballPath));
  const metadata = validateRegistryMetadata(
    registryMetadata,
    verified.binding.version,
  );
  invariant(
    sha256(bytes) === verified.binding.tarballDigest,
    "promoted registry tarball digest differs",
  );
  invariant(
    sha1(bytes) === metadata.shasum &&
      sha512Integrity(bytes) === metadata.integrity,
    "promoted registry digest metadata differs",
  );
  invariant(
    metadata.shasum === evidence.registry.shasum &&
      metadata.integrity === evidence.registry.integrity &&
      metadata.tarballUrl === evidence.registry.tarballUrl,
    "promoted registry metadata differs from the canaried transition",
  );
  const verifiedAt = now().toISOString();
  instant(verifiedAt, "promotion verifiedAt");
  const signedAuthorizationDigest = sha256(canonicalJson(receipt));
  const result = {
    schemaVersion: LATEST_PROMOTION_RESULT_SCHEMA,
    authority: "read-only-post-promotion-verification",
    authorizationId: verified.authorizationId,
    actor,
    triggeringActor,
    verifiedAt,
    release: {
      repository: releaseRepository,
      sha: releaseSha,
      workflowRunId,
      workflowRunAttempt,
    },
    transition: {
      runId: transitionRunId,
      evidenceDigest: verified.binding.transitionEvidenceDigest,
    },
    package: {
      name: PACKAGE_NAME,
      version: verified.binding.version,
      tarballDigest: verified.binding.tarballDigest,
      shasum: metadata.shasum,
      integrity: metadata.integrity,
    },
    registry: {
      registry: CANONICAL_REGISTRY,
      next: currentNext,
      latest: currentLatest,
      tarballUrl: metadata.tarballUrl,
    },
    signedAuthorizationDigest,
  };
  const receiptDigest = writeExclusive(outputPath, result);
  return { receiptDigest, result };
}

export function recordRegistryTransition({
  selectedTarballPath,
  registryTarballPath,
  registryMetadataPath,
  sourceSha,
  treeSha,
  candidateRunId,
  candidateRunAttempt,
  candidateReceiptDigest,
  latestBefore,
  latestAfter,
  nextBefore,
  version,
  nextTagVersion,
  providerMaintainers,
  canary,
  outputPath,
  promotionBindingPath,
  now = () => new Date(),
}) {
  invariant(
    SHA.test(sourceSha) && SHA.test(treeSha),
    "candidate source is invalid",
  );
  invariant(
    Number.isSafeInteger(candidateRunId) && candidateRunId > 0,
    "candidate run id is invalid",
  );
  invariant(
    Number.isSafeInteger(candidateRunAttempt) && candidateRunAttempt > 0,
    "candidate run attempt is invalid",
  );
  invariant(
    SHA256.test(candidateReceiptDigest),
    "candidate receipt digest is invalid",
  );
  invariant(STABLE_VERSION.test(version), "candidate version is invalid");
  invariant(
    nextTagVersion === version,
    "next tag does not select the candidate version",
  );
  invariant(
    STABLE_VERSION.test(latestBefore) && latestAfter === latestBefore,
    "latest changed during next publication",
  );
  invariant(
    nextBefore === null || nextBefore === latestBefore,
    "next precondition identifies a distinct in-flight candidate",
  );
  invariant(
    canonicalJson(providerMaintainers) === canonicalJson(EXPECTED_MAINTAINERS),
    "npm maintainer authority differs",
  );
  invariant(
    compareStableVersions(version, latestBefore) > 0,
    "candidate version does not advance latest",
  );
  regularFile(selectedTarballPath, "selected tarball");
  regularFile(registryTarballPath, "registry tarball");
  const selected = readFileSync(resolve(selectedTarballPath));
  const registry = readFileSync(resolve(registryTarballPath));
  const tarballDigest = sha256(selected);
  invariant(
    sha256(registry) === tarballDigest,
    "registry tarball bytes differ from selected candidate",
  );
  const manifest = packageManifestFromTarball(registry);
  invariant(
    manifest.name === PACKAGE_NAME && manifest.version === version,
    "registry tarball manifest differs",
  );
  invariant(
    JSON.stringify(manifest.repository) === JSON.stringify(PACKAGE_REPOSITORY),
    "registry tarball repository differs",
  );
  const registryMetadata = validateRegistryMetadata(
    jsonFile(registryMetadataPath, "registry metadata"),
    version,
  );
  invariant(
    registryMetadata.shasum === sha1(registry),
    "registry shasum differs from registry bytes",
  );
  invariant(
    registryMetadata.integrity === sha512Integrity(registry),
    "registry integrity differs from registry bytes",
  );
  const evidence = validateNextTransitionEvidence({
    schemaVersion: NEXT_TRANSITION_SCHEMA,
    authority: "unsigned-non-authoritative-transition-evidence",
    observedAt: now().toISOString(),
    package: { name: PACKAGE_NAME, version },
    source: { repository: SOURCE_REPOSITORY, sha: sourceSha, treeSha },
    candidate: {
      receiptDigest: candidateReceiptDigest,
      runAttempt: candidateRunAttempt,
      runId: candidateRunId,
    },
    artifact: { tarballDigest },
    registry: {
      distTag: "next",
      distTagVersion: nextTagVersion,
      integrity: registryMetadata.integrity,
      latestAfter,
      latestBefore,
      maintainers: providerMaintainers,
      nextBefore,
      registry: CANONICAL_REGISTRY,
      shasum: registryMetadata.shasum,
      tarballUrl: registryMetadata.tarballUrl,
    },
    canary,
  });
  const binding = promotionBindingFor(evidence);
  const evidenceDigest = writeExclusive(outputPath, evidence);
  invariant(
    evidenceDigest === binding.transitionEvidenceDigest,
    "transition evidence digest differs",
  );
  writeExclusive(promotionBindingPath, binding);
  return { binding, evidence, transitionEvidenceDigest: evidenceDigest };
}

function argumentsOf(argv, allowed) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    invariant(
      key?.startsWith("--") && argv[index + 1] !== undefined,
      "registry transition arguments are invalid",
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

function positiveInteger(value, label) {
  invariant(/^[1-9][0-9]*$/.test(value), `${label} is invalid`);
  const number = Number(value);
  invariant(Number.isSafeInteger(number), `${label} is invalid`);
  return number;
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (command === "canary") {
    const values = argumentsOf(
      rest,
      new Set(["--output", "--registry-tarball", "--version"]),
    );
    const version = required(values, "--version");
    invariant(STABLE_VERSION.test(version), "candidate version is invalid");
    const registryTarball = required(values, "--registry-tarball");
    regularFile(registryTarball, "registry tarball");
    const canary = runRegistryCanary(registryTarball, version);
    const canaryDigest = writeExclusive(required(values, "--output"), canary);
    process.stdout.write(`${JSON.stringify({ canaryDigest })}\n`);
    return;
  }
  if (command === "record") {
    const allowed = new Set([
      "--candidate-receipt-digest",
      "--candidate-run-attempt",
      "--candidate-run-id",
      "--canary",
      "--latest-after",
      "--latest-before",
      "--next-before",
      "--next-tag-version",
      "--output",
      "--promotion-binding-output",
      "--provider-maintainers",
      "--registry-metadata",
      "--registry-tarball",
      "--selected-tarball",
      "--source-sha",
      "--tree-sha",
      "--version",
    ]);
    const values = argumentsOf(rest, allowed);
    const result = recordRegistryTransition({
      selectedTarballPath: required(values, "--selected-tarball"),
      registryTarballPath: required(values, "--registry-tarball"),
      registryMetadataPath: required(values, "--registry-metadata"),
      sourceSha: required(values, "--source-sha"),
      treeSha: required(values, "--tree-sha"),
      candidateRunId: positiveInteger(
        required(values, "--candidate-run-id"),
        "candidate run id",
      ),
      candidateRunAttempt: positiveInteger(
        required(values, "--candidate-run-attempt"),
        "candidate run attempt",
      ),
      candidateReceiptDigest: required(values, "--candidate-receipt-digest"),
      latestBefore: required(values, "--latest-before"),
      latestAfter: required(values, "--latest-after"),
      nextBefore:
        required(values, "--next-before") === "absent"
          ? null
          : required(values, "--next-before"),
      version: required(values, "--version"),
      nextTagVersion: required(values, "--next-tag-version"),
      providerMaintainers: JSON.parse(
        required(values, "--provider-maintainers"),
      ),
      canary: jsonFile(required(values, "--canary"), "registry canary"),
      outputPath: required(values, "--output"),
      promotionBindingPath: required(values, "--promotion-binding-output"),
    });
    process.stdout.write(
      `${JSON.stringify({ transitionEvidenceDigest: result.transitionEvidenceDigest })}\n`,
    );
    return;
  }
  if (command === "verify-promotion-binding") {
    const values = argumentsOf(rest, new Set(["--binding", "--evidence"]));
    const evidence = jsonFile(
      required(values, "--evidence"),
      "transition evidence",
    );
    const binding = jsonFile(
      required(values, "--binding"),
      "promotion binding",
    );
    validatePromotionBinding(binding, evidence);
    process.stdout.write(
      `${JSON.stringify({ transitionEvidenceDigest: binding.transitionEvidenceDigest })}\n`,
    );
    return;
  }
  if (command === "verify-promotion-receipt") {
    const values = argumentsOf(
      rest,
      new Set([
        "--current-latest",
        "--current-next",
        "--evidence",
        "--receipt",
        "--trust-policy",
      ]),
    );
    const evidence = jsonFile(
      required(values, "--evidence"),
      "transition evidence",
    );
    const receipt = jsonFile(
      required(values, "--receipt"),
      "signed promotion receipt",
    );
    const trustPolicy = jsonFile(
      required(values, "--trust-policy"),
      "promotion trust policy",
    );
    const verified = verifySignedPromotionReceipt({
      receipt,
      trustPolicy,
      evidence,
      currentLatest: required(values, "--current-latest"),
      currentNext: required(values, "--current-next"),
    });
    process.stdout.write(
      `${JSON.stringify({ authorizationId: verified.authorizationId, transitionEvidenceDigest: verified.binding.transitionEvidenceDigest })}\n`,
    );
    return;
  }
  if (command === "verify-promotion-result") {
    const values = argumentsOf(
      rest,
      new Set([
        "--actor",
        "--current-latest",
        "--current-next",
        "--evidence",
        "--output",
        "--receipt",
        "--registry-metadata",
        "--registry-tarball",
        "--release-repository",
        "--release-sha",
        "--transition-run-id",
        "--triggering-actor",
        "--trust-policy",
        "--workflow-run-attempt",
        "--workflow-run-id",
      ]),
    );
    const output = verifyCompletedPromotion({
      receipt: jsonFile(
        required(values, "--receipt"),
        "signed promotion receipt",
      ),
      trustPolicy: jsonFile(
        required(values, "--trust-policy"),
        "promotion trust policy",
      ),
      evidence: jsonFile(required(values, "--evidence"), "transition evidence"),
      currentLatest: required(values, "--current-latest"),
      currentNext: required(values, "--current-next"),
      registryMetadata: jsonFile(
        required(values, "--registry-metadata"),
        "registry metadata",
      ),
      registryTarballPath: required(values, "--registry-tarball"),
      actor: required(values, "--actor"),
      triggeringActor: required(values, "--triggering-actor"),
      releaseRepository: required(values, "--release-repository"),
      releaseSha: required(values, "--release-sha"),
      workflowRunId: positiveInteger(
        required(values, "--workflow-run-id"),
        "promotion workflow run id",
      ),
      workflowRunAttempt: positiveInteger(
        required(values, "--workflow-run-attempt"),
        "promotion workflow run attempt",
      ),
      transitionRunId: positiveInteger(
        required(values, "--transition-run-id"),
        "promotion transition run id",
      ),
      outputPath: required(values, "--output"),
    });
    process.stdout.write(
      `${JSON.stringify({ authorizationId: output.result.authorizationId, receiptDigest: output.receiptDigest })}\n`,
    );
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
      `registry transition refused: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}
