#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SOURCE_REPOSITORY = "Sift-wiki/sift-q-refactor";
export const SOURCE_REPOSITORY_ID = 1_329_084_838;
export const SOURCE_WORKFLOW_PATH = ".github/workflows/deploy-development.yml";
export const CANDIDATE_ARTIFACT_NAME = "sift-q-development-candidate";
export const CANDIDATE_FILES = Object.freeze([
  "npm-package.tgz",
  "signed-development-candidate.json",
  "signed-npm-runtime-canary.json",
]);

const PACKAGE_NAME = "@sift-wiki/q";
const PACKAGE_REPOSITORY = Object.freeze({
  type: "git",
  url: "git+https://github.com/Sift-wiki/sift-q-refactor.git",
});
const DEVELOPMENT_ENVIRONMENT_ID = "sift-q-development";
const PRODUCTION_ENVIRONMENT_ID = "sift-q-production";
const GIT_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RUN_ID = /^[1-9][0-9]*$/;
const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function jsonFile(path) {
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactObject(value, expected, label) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} is invalid`,
  );
  invariant(
    JSON.stringify(value) === JSON.stringify(expected),
    `${label} differs`,
  );
}

export function validateRunSelection({
  run,
  artifacts,
  candidateCommit,
  currentMain,
  comparison,
  expectedRunId,
}) {
  invariant(RUN_ID.test(String(expectedRunId)), "candidate run id is invalid");
  invariant(run?.id === Number(expectedRunId), "candidate run id differs");
  invariant(
    run?.repository?.id === SOURCE_REPOSITORY_ID,
    "candidate run repository id differs",
  );
  invariant(
    run.repository.full_name === SOURCE_REPOSITORY,
    "candidate run repository differs",
  );
  invariant(
    run.path === SOURCE_WORKFLOW_PATH,
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
      `https://api.github.com/repos/${SOURCE_REPOSITORY}/actions/runs/${expectedRunId}/artifacts`,
    "candidate run artifact authority differs",
  );

  invariant(
    currentMain?.ref === "refs/heads/main" &&
      GIT_SHA.test(currentMain?.object?.sha),
    "current main ref response is invalid",
  );
  invariant(
    candidateCommit?.sha === run.head_sha,
    "candidate commit response differs",
  );
  invariant(
    GIT_SHA.test(candidateCommit?.commit?.tree?.sha),
    "candidate commit tree is invalid",
  );
  invariant(
    comparison?.status === "identical" || comparison?.status === "ahead",
    "candidate is not an ancestor of current main",
  );
  invariant(
    comparison?.base_commit?.sha === run.head_sha,
    "candidate comparison base differs",
  );
  invariant(
    comparison?.merge_base_commit?.sha === run.head_sha,
    "candidate comparison merge base differs",
  );
  invariant(
    comparison?.head_commit?.sha === currentMain.object.sha,
    "candidate comparison head differs",
  );

  invariant(
    Number.isSafeInteger(artifacts?.total_count) && artifacts.total_count === 1,
    "candidate run must expose exactly one artifact",
  );
  invariant(
    Array.isArray(artifacts.artifacts) && artifacts.artifacts.length === 1,
    "candidate artifact list differs",
  );
  const artifact = artifacts.artifacts[0];
  invariant(
    Number.isSafeInteger(artifact?.id) && artifact.id > 0,
    "candidate artifact id is invalid",
  );
  invariant(
    artifact.name === CANDIDATE_ARTIFACT_NAME,
    "candidate artifact name differs",
  );
  invariant(artifact.expired === false, "candidate artifact is expired");
  invariant(
    Number.isSafeInteger(artifact.size_in_bytes) &&
      artifact.size_in_bytes > 0 &&
      artifact.size_in_bytes <= 50_000_000,
    "candidate artifact size is invalid",
  );
  invariant(
    artifact.archive_download_url ===
      `https://api.github.com/repos/${SOURCE_REPOSITORY}/actions/artifacts/${artifact.id}/zip`,
    "candidate artifact download authority differs",
  );
  if (artifact.workflow_run !== undefined) {
    invariant(
      artifact.workflow_run?.id === run.id,
      "candidate artifact run differs",
    );
    invariant(
      artifact.workflow_run?.head_sha === run.head_sha,
      "candidate artifact SHA differs",
    );
  }
  return {
    artifactId: artifact.id,
    currentMainSha: currentMain.object.sha,
    runAttempt: run.run_attempt,
    runId: run.id,
    sourceSha: run.head_sha,
    treeSha: candidateCommit.commit.tree.sha,
  };
}

export function validateCandidateFiles(directory) {
  const root = resolve(directory);
  const names = readdirSync(root).sort();
  invariant(
    JSON.stringify(names) === JSON.stringify([...CANDIDATE_FILES].sort()),
    "candidate artifact files differ",
  );
  for (const name of names) {
    const stat = lstatSync(resolve(root, name));
    invariant(
      stat.isFile() && !stat.isSymbolicLink(),
      `candidate artifact ${name} is not a regular file`,
    );
  }
  return names;
}

export async function verifyCandidate({
  sourceRoot,
  candidateDirectory,
  trustPolicyPath,
  selection,
  expectedReceiptDigest,
  expectedVersion = "",
  now = Date.now(),
}) {
  invariant(
    SHA256.test(expectedReceiptDigest),
    "candidate receipt digest is invalid",
  );
  invariant(
    GIT_SHA.test(selection?.sourceSha),
    "candidate source SHA is invalid",
  );
  validateCandidateFiles(candidateDirectory);

  const source = resolve(sourceRoot);
  const candidateContract = await import(
    pathToFileURL(resolve(source, "scripts/ol/candidate-contract.mjs")).href
  );
  const npmContract = await import(
    pathToFileURL(resolve(source, "scripts/ol/npm-publisher-contract.mjs")).href
  );
  const candidate = jsonFile(
    resolve(candidateDirectory, "signed-development-candidate.json"),
  );
  const runtimeCanary = jsonFile(
    resolve(candidateDirectory, "signed-npm-runtime-canary.json"),
  );
  const trustPolicy = jsonFile(trustPolicyPath);
  const tarball = readFileSync(resolve(candidateDirectory, "npm-package.tgz"));

  invariant(
    trustPolicy.repository === SOURCE_REPOSITORY,
    "candidate trust repository differs",
  );
  invariant(
    trustPolicy.npmPackageName === PACKAGE_NAME,
    "candidate trust package differs",
  );
  invariant(
    trustPolicy.developmentEnvironmentId === DEVELOPMENT_ENVIRONMENT_ID,
    "candidate trust development environment differs",
  );
  invariant(
    trustPolicy.productionEnvironmentId === PRODUCTION_ENVIRONMENT_ID,
    "candidate trust production environment differs",
  );
  invariant(
    candidateContract.candidateReceiptDigest(candidate) ===
      expectedReceiptDigest,
    "candidate receipt digest differs",
  );

  const treeSha = selection.treeSha;
  invariant(GIT_SHA.test(treeSha), "candidate tree SHA is invalid");
  const expectedSource = {
    ref: "refs/heads/main",
    sha: selection.sourceSha,
    treeSha,
  };
  const payload = candidateContract.validateDevelopmentCandidate({
    signedCandidate: candidate,
    trustPolicy,
    expectedSource,
    now,
  });
  const npmArtifact = payload.artifacts.npm;
  npmContract.validateSignedNpmRuntimeCanary({
    signedRuntimeCanary: runtimeCanary,
    trustPolicy,
    expectedSource,
    expectedPackage: {
      name: npmArtifact.packageName,
      version: npmArtifact.version,
      tarballDigest: npmArtifact.tarballDigest,
    },
    expectedReceiptDigest: npmArtifact.runtimeCanaryReceiptDigest,
    qualificationFinishedAt: payload.qualification.finishedAt,
    now,
  });

  const manifest = npmContract.packageManifestFromTarball(tarball);
  invariant(manifest.name === PACKAGE_NAME, "npm tarball package name differs");
  invariant(
    STABLE_VERSION.test(manifest.version),
    "npm tarball version is not stable",
  );
  invariant(
    manifest.version === npmArtifact.version,
    "npm tarball version differs from candidate",
  );
  exactObject(
    manifest.repository,
    PACKAGE_REPOSITORY,
    "npm tarball repository",
  );
  const tarballDigest = sha256(tarball);
  invariant(
    tarballDigest === npmArtifact.tarballDigest,
    "npm tarball bytes differ from candidate",
  );
  if (expectedVersion !== "") {
    invariant(
      expectedVersion === manifest.version,
      "expected version differs from candidate",
    );
  }

  return {
    candidateReceiptDigest: expectedReceiptDigest,
    currentMainSha: selection.currentMainSha,
    runAttempt: selection.runAttempt,
    runId: selection.runId,
    sourceSha: selection.sourceSha,
    treeSha,
    tarballDigest,
    tarballSha256: tarballDigest.slice("sha256:".length),
    version: manifest.version,
  };
}

function argumentsOf(argv) {
  const [command, ...rest] = argv;
  const values = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    invariant(
      key?.startsWith("--") && index + 1 < rest.length,
      `invalid argument ${key ?? ""}`,
    );
    values.set(key, rest[index + 1]);
  }
  return { command, values };
}

function required(values, key) {
  const value = values.get(key);
  invariant(value !== undefined && value !== "", `missing ${key}`);
  return value;
}

function optional(values, key) {
  return values.get(key) ?? "";
}

async function main(argv) {
  const { command, values } = argumentsOf(argv);
  if (command === "select-run") {
    const result = validateRunSelection({
      run: jsonFile(required(values, "--run")),
      artifacts: jsonFile(required(values, "--artifacts")),
      candidateCommit: jsonFile(required(values, "--candidate-commit")),
      currentMain: jsonFile(required(values, "--current-main")),
      comparison: jsonFile(required(values, "--comparison")),
      expectedRunId: required(values, "--run-id"),
    });
    writeFileSync(
      resolve(required(values, "--output")),
      `${JSON.stringify(result, null, 2)}\n`,
      { mode: 0o600 },
    );
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (command === "verify-candidate") {
    const result = await verifyCandidate({
      sourceRoot: required(values, "--source-root"),
      candidateDirectory: required(values, "--candidate-directory"),
      trustPolicyPath: required(values, "--trust-policy"),
      selection: jsonFile(required(values, "--selection")),
      expectedReceiptDigest: required(values, "--receipt-digest"),
      expectedVersion: optional(values, "--expected-version"),
    });
    writeFileSync(
      resolve(required(values, "--output")),
      `${JSON.stringify(result, null, 2)}\n`,
      { mode: 0o600 },
    );
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  throw new Error(`unknown command ${command ?? ""}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`candidate verification refused: ${error.message}`);
    process.exitCode = 1;
  });
}
