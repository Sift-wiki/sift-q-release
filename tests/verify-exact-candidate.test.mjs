import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  DEVELOPMENT_CANDIDATE_SCHEMA,
  SIGNED_DEVELOPMENT_CANDIDATE_SCHEMA,
  candidateReceiptDigest,
  signingKeyId,
} from "../scripts/vendor/ol/candidate-contract.mjs";
import {
  NPM_RUNTIME_CANARY_SCHEMA,
  SIGNED_NPM_RUNTIME_CANARY_SCHEMA,
  runtimeCanaryReceiptDigest,
} from "../scripts/vendor/ol/npm-publisher-contract.mjs";
import {
  canonicalJson,
  sha256Digest,
} from "../scripts/vendor/ol/readiness-contract.mjs";
import {
  CANDIDATE_ARTIFACT_NAME,
  CANDIDATE_FILES,
  LEGACY_PUBLISH_WORKFLOW_ID,
  LEGACY_PUBLISH_WORKFLOW_NAME,
  LEGACY_PUBLISH_WORKFLOW_PATH,
  PACKAGE_REPOSITORY,
  SOURCE_REPOSITORY,
  SOURCE_REPOSITORY_ID,
  SOURCE_WORKFLOW_ID,
  SOURCE_WORKFLOW_NAME,
  SOURCE_WORKFLOW_PATH,
  validateCandidateFiles,
  validateLegacyPublisherDisabled,
  validateRunSelection,
  verifyCandidate,
} from "../scripts/verify-exact-candidate.mjs";

const runId = 32500000000;
const candidateSha = "1".repeat(40);
const mainSha = "2".repeat(40);
const treeSha = "4".repeat(40);
const artifactId = 777;

function validLegacyPublisher() {
  return {
    repository: {
      id: SOURCE_REPOSITORY_ID,
      full_name: SOURCE_REPOSITORY,
      private: true,
      default_branch: "main",
    },
    workflow: {
      id: LEGACY_PUBLISH_WORKFLOW_ID,
      name: LEGACY_PUBLISH_WORKFLOW_NAME,
      path: LEGACY_PUBLISH_WORKFLOW_PATH,
      state: "disabled_manually",
    },
  };
}

test("accepts only the disabled canonical private publisher", () => {
  const { repository, workflow } = validLegacyPublisher();
  assert.deepEqual(validateLegacyPublisherDisabled(repository, workflow), {
    repository: SOURCE_REPOSITORY,
    repositoryId: SOURCE_REPOSITORY_ID,
    workflowId: LEGACY_PUBLISH_WORKFLOW_ID,
    workflowPath: LEGACY_PUBLISH_WORKFLOW_PATH,
    workflowState: "disabled_manually",
  });
});

for (const state of ["active", "unknown"]) {
  test(`refuses the legacy private publisher state ${state}`, () => {
    const { repository, workflow } = validLegacyPublisher();
    workflow.state = state;
    assert.throws(
      () => validateLegacyPublisherDisabled(repository, workflow),
      /legacy private publisher is not disabled_manually/,
    );
  });
}

for (const [label, mutate, expected] of [
  [
    "repository id",
    (value) => (value.repository.id += 1),
    /repository id differs/,
  ],
  [
    "repository name",
    (value) => (value.repository.full_name = "Sift-wiki/other"),
    /repository differs/,
  ],
  [
    "repository posture",
    (value) => (value.repository.private = false),
    /repository posture differs/,
  ],
  ["workflow id", (value) => (value.workflow.id += 1), /workflow id differs/],
  [
    "workflow name",
    (value) => (value.workflow.name = "publish-npm"),
    /workflow name differs/,
  ],
  [
    "workflow path",
    (value) => (value.workflow.path = ".github/workflows/other.yml"),
    /workflow path differs/,
  ],
]) {
  test(`refuses legacy publisher ${label} substitution`, () => {
    const value = validLegacyPublisher();
    mutate(value);
    assert.throws(
      () => validateLegacyPublisherDisabled(value.repository, value.workflow),
      expected,
    );
  });
}

function validBoundary() {
  return {
    expectedRunId: String(runId),
    run: {
      id: runId,
      repository: { id: SOURCE_REPOSITORY_ID, full_name: SOURCE_REPOSITORY },
      workflow_id: SOURCE_WORKFLOW_ID,
      name: SOURCE_WORKFLOW_NAME,
      path: SOURCE_WORKFLOW_PATH,
      event: "workflow_run",
      head_branch: "main",
      head_sha: candidateSha,
      status: "completed",
      conclusion: "success",
      run_attempt: 1,
      artifacts_url: `https://api.github.com/repos/${SOURCE_REPOSITORY}/actions/runs/${runId}/artifacts`,
    },
    currentMain: { ref: "refs/heads/main", object: { sha: mainSha } },
    candidateCommit: { sha: candidateSha, commit: { tree: { sha: treeSha } } },
    comparison: {
      status: "ahead",
      base_commit: { sha: candidateSha },
      merge_base_commit: { sha: candidateSha },
      head_commit: { sha: mainSha },
    },
    artifacts: {
      total_count: 1,
      artifacts: [
        {
          id: artifactId,
          name: CANDIDATE_ARTIFACT_NAME,
          expired: false,
          size_in_bytes: 1_000_000,
          archive_download_url: `https://api.github.com/repos/${SOURCE_REPOSITORY}/actions/artifacts/${artifactId}/zip`,
          workflow_run: { id: runId, head_sha: candidateSha },
        },
      ],
    },
  };
}

test("selects one successful automatic main candidate from the canonical private workflow", () => {
  assert.deepEqual(validateRunSelection(validBoundary()), {
    artifactId,
    currentMainSha: mainSha,
    runAttempt: 1,
    runId,
    sourceSha: candidateSha,
    treeSha,
  });
});

for (const [label, mutate, expected] of [
  ["repository id", (v) => (v.run.repository.id += 1), /repository id differs/],
  [
    "workflow id",
    (v) => (v.run.workflow_id += 1),
    /workflow id differs/,
  ],
  [
    "workflow name",
    (v) => (v.run.name = "other-development-candidate"),
    /workflow name differs/,
  ],
  [
    "workflow path",
    (v) => (v.run.path = ".github/workflows/ci.yml"),
    /workflow path differs/,
  ],
  [
    "event",
    (v) => (v.run.event = "workflow_dispatch"),
    /not automatic accepted-main/,
  ],
  ["branch", (v) => (v.run.head_branch = "feature"), /source differs/],
  ["conclusion", (v) => (v.run.conclusion = "failure"), /not green/],
  [
    "lineage",
    (v) => (v.comparison.merge_base_commit.sha = "3".repeat(40)),
    /merge base differs/,
  ],
  [
    "artifact name",
    (v) => (v.artifacts.artifacts[0].name = "tarball"),
    /artifact name differs/,
  ],
  [
    "expired artifact",
    (v) => (v.artifacts.artifacts[0].expired = true),
    /artifact is expired/,
  ],
  [
    "artifact download authority",
    (v) =>
      (v.artifacts.artifacts[0].archive_download_url =
        "https://example.test/artifact.zip"),
    /download authority differs/,
  ],
  [
    "oversized artifact",
    (v) => (v.artifacts.artifacts[0].size_in_bytes = 50_000_001),
    /artifact size is invalid/,
  ],
]) {
  test(`refuses candidate ${label} substitution`, () => {
    const value = validBoundary();
    mutate(value);
    assert.throws(() => validateRunSelection(value), expected);
  });
}

test("refuses duplicate or additional artifacts even when one has the canonical name", () => {
  const value = validBoundary();
  value.artifacts.total_count = 2;
  value.artifacts.artifacts.push({
    ...value.artifacts.artifacts[0],
    id: artifactId + 1,
  });
  assert.throws(() => validateRunSelection(value), /exactly one artifact/);
});

test("candidate directory accepts exactly the three expected regular files", () => {
  const directory = mkdtempSync(join(tmpdir(), "sift-q-candidate-"));
  try {
    for (const name of CANDIDATE_FILES)
      writeFileSync(join(directory, name), name);
    assert.deepEqual(
      validateCandidateFiles(directory),
      [...CANDIDATE_FILES].sort(),
    );
    writeFileSync(join(directory, "extra.txt"), "unexpected");
    assert.throws(() => validateCandidateFiles(directory), /files differ/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("candidate directory refuses a symlink in place of an expected file", () => {
  const directory = mkdtempSync(join(tmpdir(), "sift-q-candidate-"));
  try {
    writeFileSync(join(directory, "target"), "bytes");
    for (const name of CANDIDATE_FILES.slice(1))
      writeFileSync(join(directory, name), name);
    symlinkSync(join(directory, "target"), join(directory, CANDIDATE_FILES[0]));
    rmSync(join(directory, "target"));
    assert.throws(
      () => validateCandidateFiles(directory),
      /not a regular file/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("candidate verification executes only pinned public verifier code", () => {
  const verifier = readFileSync(
    new URL("../scripts/verify-exact-candidate.mjs", import.meta.url),
    "utf8",
  );
  assert.match(verifier, /\.\/vendor\/ol\/candidate-contract\.mjs/);
  assert.match(verifier, /\.\/vendor\/ol\/npm-publisher-contract\.mjs/);
  assert.doesNotMatch(
    verifier,
    /sourceRoot|--source-root|scripts\/ol\/candidate-contract/,
  );
  for (const name of [
    "candidate-contract.mjs",
    "readiness-contract.mjs",
    "npm-publisher-contract.mjs",
  ]) {
    const source = readFileSync(
      new URL(`../scripts/vendor/ol/${name}`, import.meta.url),
      "utf8",
    );
    assert.match(
      source,
      /Sift-wiki\/sift-q-refactor@4647c4cc8cd665f91385fcf248219c27c99870a9/,
    );
  }
});

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function signedCandidateFixture(tarball) {
  const now = Date.parse("2026-08-21T00:00:00.000Z");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiBase64 = publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64");
  const keyId = signingKeyId(publicKeySpkiBase64);
  const trustPolicy = {
    candidateKeyId: keyId,
    candidatePublicKeySpkiBase64: publicKeySpkiBase64,
    clockSkewSeconds: 60,
    developmentEnvironmentId: "sift-q-development",
    maximumEvidenceAgeSeconds: 3_600,
    maximumReceiptLifetimeSeconds: 3_600,
    npmPackageName: "@sift-wiki/q",
    productionEnvironmentId: "sift-q-production",
    repository: SOURCE_REPOSITORY,
  };
  const source = {
    ref: "refs/heads/main",
    sha: candidateSha,
    treeSha,
  };
  const tarballDigest = digest(tarball);
  const runtimePayload = {
    schemaVersion: NPM_RUNTIME_CANARY_SCHEMA,
    repository: SOURCE_REPOSITORY,
    source: structuredClone(source),
    package: { name: "@sift-wiki/q", version: "1.2.3", tarballDigest },
    homeIsolation: "fresh-empty-temporary-home",
    install: {
      command: "npm install ./npm-package.tgz --no-audit --no-fund",
      scriptsPolicy: "consumer-default",
      exitCode: 0,
      stdout: "added 1 package\n",
      stderr: "",
    },
    version: {
      command: "sift-q --version",
      exitCode: 0,
      stdout: "sift-q 1.2.3\n",
      stderr: "",
    },
    dryRun: {
      command: "sift-q --dry-run --json --client claude",
      harness: "claude",
      exitCode: 0,
      stdout: JSON.stringify({
        detection: { platform: { ok: true } },
        plan: [{ id: "fetch-hosted-content" }, { id: "register-claude" }],
        result: { stepResults: [] },
      }),
      stderr: "",
    },
    finishedAt: "2026-08-20T23:35:00.000Z",
  };
  const signedRuntimeCanary = {
    schemaVersion: SIGNED_NPM_RUNTIME_CANARY_SCHEMA,
    keyId,
    payload: runtimePayload,
    signatureBase64: sign(
      null,
      Buffer.from(canonicalJson(runtimePayload)),
      privateKey,
    ).toString("base64"),
  };
  const runtimeCanaryDigest = runtimeCanaryReceiptDigest(signedRuntimeCanary);
  const npmArtifact = {
    packageName: "@sift-wiki/q",
    version: "1.2.3",
    tarballDigest,
    runtimeCanaryReceiptDigest: runtimeCanaryDigest,
  };
  const hostedImageDigest = sha256Digest({ fixture: "hosted" });
  const hostedNpmArtifacts = {
    indexDigest: hostedImageDigest,
    packageName: npmArtifact.packageName,
    platforms: {
      "linux/amd64": {
        imageManifestDigest: sha256Digest({ fixture: "hosted-amd64" }),
        tarballDigest,
      },
      "linux/arm64": {
        imageManifestDigest: sha256Digest({ fixture: "hosted-arm64" }),
        tarballDigest,
      },
    },
    tarballDigest,
    version: npmArtifact.version,
  };
  const artifacts = {
    configuration: {
      runtimeDigest: sha256Digest({ fixture: "runtime" }),
      schemaDigest: sha256Digest({ fixture: "schema" }),
    },
    containers: {
      hostedImageDigest,
      hostedNpmArtifacts,
      webImageDigest: sha256Digest({ fixture: "web" }),
    },
    migrations: {
      bundleDigest: sha256Digest({ fixture: "migrations" }),
      head: "20260820120000_freeze_advisory_priority.sql",
    },
    npm: npmArtifact,
  };
  const payload = {
    schemaVersion: DEVELOPMENT_CANDIDATE_SCHEMA,
    repository: SOURCE_REPOSITORY,
    source,
    artifacts,
    qualification: {
      source: structuredClone(source),
      finishedAt: "2026-08-20T23:40:00.000Z",
      receiptDigest: sha256Digest({ fixture: "qualification" }),
      checks: [
        "image-build",
        "hosted-npm-artifact-parity",
        "npm-pack",
        "npm-clean-home-runtime-canary",
        "pnpm-quality",
        "pnpm-test",
      ].map((id) => ({
        id,
        result: "passed",
        evidenceDigest:
          id === "npm-clean-home-runtime-canary"
            ? runtimeCanaryDigest
            : id === "hosted-npm-artifact-parity"
              ? sha256Digest(hostedNpmArtifacts)
              : sha256Digest({ fixture: id }),
      })),
    },
    developmentDeployment: {
      environmentId: "sift-q-development",
      deploymentId: "dev-release:8",
      source: structuredClone(source),
      artifacts: structuredClone(artifacts),
      deployedAt: "2026-08-20T23:45:00.000Z",
      receiptDigest: sha256Digest({ fixture: "deployment" }),
    },
    developmentSmoke: {
      environmentId: "sift-q-development",
      observedDeploymentId: "dev-release:8",
      observedSource: structuredClone(source),
      observedArtifacts: structuredClone(artifacts),
      result: "passed",
      finishedAt: "2026-08-20T23:50:00.000Z",
      receiptDigest: sha256Digest({ fixture: "smoke" }),
    },
    issuedAt: "2026-08-20T23:55:00.000Z",
    expiresAt: "2026-08-21T00:55:00.000Z",
  };
  const signedCandidate = {
    schemaVersion: SIGNED_DEVELOPMENT_CANDIDATE_SCHEMA,
    keyId,
    payload,
    signatureBase64: sign(
      null,
      Buffer.from(canonicalJson(payload)),
      privateKey,
    ).toString("base64"),
  };
  return {
    now,
    receiptDigest: candidateReceiptDigest(signedCandidate),
    signedCandidate,
    signedRuntimeCanary,
    trustPolicy,
  };
}

test("verified handoff binds source, canary, package metadata and exact tarball bytes", async () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-relay-verifier-"));
  try {
    const candidateDirectory = join(root, "candidate");
    const packageRoot = join(root, "package");
    mkdirSync(candidateDirectory);
    mkdirSync(packageRoot);

    assert.deepEqual(PACKAGE_REPOSITORY, {
      type: "git",
      url: "git+https://github.com/Sift-wiki/sift-q-release.git",
    });
    const writePackageManifest = (url) =>
      writeFileSync(
        join(packageRoot, "package.json"),
        JSON.stringify({
          name: "@sift-wiki/q",
          version: "1.2.3",
          repository: { type: "git", url },
          files: ["README.md"],
        }),
      );
    writePackageManifest("git+https://github.com/Sift-wiki/sift-q-release.git");
    writeFileSync(join(packageRoot, "README.md"), "real packed fixture\n");
    const pack = () => {
      const result = JSON.parse(
        execFileSync(
          "npm",
          [
            "pack",
            "--ignore-scripts",
            "--json",
            "--pack-destination",
            candidateDirectory,
          ],
          {
            cwd: packageRoot,
            encoding: "utf8",
            env: { ...process.env, npm_config_cache: join(root, "npm-cache") },
          },
        ),
      );
      assert.equal(result.length, 1);
      renameSync(
        join(candidateDirectory, result[0].filename),
        join(candidateDirectory, "npm-package.tgz"),
      );
      return readFileSync(join(candidateDirectory, "npm-package.tgz"));
    };
    const tarball = pack();
    const tarballDigest = digest(tarball);
    const fixture = signedCandidateFixture(tarball);
    writeFileSync(
      join(candidateDirectory, "signed-development-candidate.json"),
      JSON.stringify(fixture.signedCandidate),
    );
    writeFileSync(
      join(candidateDirectory, "signed-npm-runtime-canary.json"),
      JSON.stringify(fixture.signedRuntimeCanary),
    );
    const trustPolicyPath = join(root, "trust.json");
    writeFileSync(trustPolicyPath, JSON.stringify(fixture.trustPolicy));
    const selection = {
      sourceSha: candidateSha,
      treeSha,
      currentMainSha: mainSha,
      runAttempt: 1,
      runId,
    };

    const verified = await verifyCandidate({
      candidateDirectory,
      trustPolicyPath,
      selection,
      expectedReceiptDigest: fixture.receiptDigest,
      expectedVersion: "1.2.3",
      now: fixture.now,
    });
    assert.equal(verified.tarballDigest, tarballDigest);
    assert.equal(verified.sourceSha, candidateSha);
    assert.equal(verified.version, "1.2.3");

    rmSync(join(candidateDirectory, "npm-package.tgz"));
    writePackageManifest(
      "git+https://github.com/Sift-wiki/sift-q-refactor.git",
    );
    pack();
    await assert.rejects(
      verifyCandidate({
        candidateDirectory,
        trustPolicyPath,
        selection,
        expectedReceiptDigest: fixture.receiptDigest,
        expectedVersion: "1.2.3",
        now: fixture.now,
      }),
      /npm tarball repository differs/,
    );

    rmSync(join(candidateDirectory, "npm-package.tgz"));
    writePackageManifest("git+https://github.com/Sift-wiki/sift-q-release.git");
    writeFileSync(join(packageRoot, "README.md"), "repacked fixture bytes\n");
    pack();
    await assert.rejects(
      verifyCandidate({
        candidateDirectory,
        trustPolicyPath,
        selection,
        expectedReceiptDigest: fixture.receiptDigest,
        expectedVersion: "1.2.3",
        now: fixture.now,
      }),
      /tarball bytes differ/,
    );

    const tampered = structuredClone(fixture.signedCandidate);
    tampered.payload.issuedAt = "2026-08-20T23:54:59.000Z";
    writeFileSync(
      join(candidateDirectory, "signed-development-candidate.json"),
      JSON.stringify(tampered),
    );
    await assert.rejects(
      verifyCandidate({
        candidateDirectory,
        trustPolicyPath,
        selection,
        expectedReceiptDigest: candidateReceiptDigest(tampered),
        expectedVersion: "1.2.3",
        now: fixture.now,
      }),
      /development candidate signature is invalid/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
