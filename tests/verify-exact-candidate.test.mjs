import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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
  CANDIDATE_ARTIFACT_NAME,
  CANDIDATE_FILES,
  LEGACY_PUBLISH_WORKFLOW_ID,
  LEGACY_PUBLISH_WORKFLOW_NAME,
  LEGACY_PUBLISH_WORKFLOW_PATH,
  PACKAGE_REPOSITORY,
  SOURCE_REPOSITORY,
  SOURCE_REPOSITORY_ID,
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

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

test("verified handoff binds source, canary, package metadata and exact tarball bytes", async () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-relay-verifier-"));
  try {
    const sourceRoot = join(root, "source");
    const contractRoot = join(sourceRoot, "scripts", "ol");
    const candidateDirectory = join(root, "candidate");
    const packageRoot = join(root, "package");
    mkdirSync(contractRoot, { recursive: true });
    mkdirSync(candidateDirectory);
    mkdirSync(packageRoot);
    writeFileSync(
      join(contractRoot, "candidate-contract.mjs"),
      `
      export const candidateReceiptDigest = (candidate) => candidate.receiptDigest;
      export function validateDevelopmentCandidate({ signedCandidate, expectedSource }) {
        if (JSON.stringify(signedCandidate.payload.source) !== JSON.stringify(expectedSource)) {
          throw new Error("stub source differs");
        }
        return signedCandidate.payload;
      }
      `,
    );
    writeFileSync(
      join(contractRoot, "npm-publisher-contract.mjs"),
      `
      export function validateSignedNpmRuntimeCanary({ signedRuntimeCanary, expectedPackage }) {
        if (signedRuntimeCanary.ok !== true || expectedPackage.version !== "1.2.3") {
          throw new Error("stub runtime canary differs");
        }
      }
      `,
    );

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
    const receiptDigest = `sha256:${"7".repeat(64)}`;
    const runtimeDigest = `sha256:${"8".repeat(64)}`;
    const candidate = {
      receiptDigest,
      payload: {
        source: { ref: "refs/heads/main", sha: candidateSha, treeSha },
        qualification: { finishedAt: "2026-08-21T00:00:00.000Z" },
        artifacts: {
          npm: {
            packageName: "@sift-wiki/q",
            version: "1.2.3",
            tarballDigest,
            runtimeCanaryReceiptDigest: runtimeDigest,
          },
        },
      },
    };
    writeFileSync(
      join(candidateDirectory, "signed-development-candidate.json"),
      JSON.stringify(candidate),
    );
    writeFileSync(
      join(candidateDirectory, "signed-npm-runtime-canary.json"),
      JSON.stringify({ ok: true }),
    );
    const trustPolicyPath = join(root, "trust.json");
    writeFileSync(
      trustPolicyPath,
      JSON.stringify({
        repository: SOURCE_REPOSITORY,
        npmPackageName: "@sift-wiki/q",
        developmentEnvironmentId: "sift-q-development",
        productionEnvironmentId: "sift-q-production",
      }),
    );
    const selection = {
      sourceSha: candidateSha,
      treeSha,
      currentMainSha: mainSha,
      runAttempt: 1,
      runId,
    };

    const verified = await verifyCandidate({
      sourceRoot,
      candidateDirectory,
      trustPolicyPath,
      selection,
      expectedReceiptDigest: receiptDigest,
      expectedVersion: "1.2.3",
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
        sourceRoot,
        candidateDirectory,
        trustPolicyPath,
        selection,
        expectedReceiptDigest: receiptDigest,
        expectedVersion: "1.2.3",
      }),
      /npm tarball repository differs/,
    );

    rmSync(join(candidateDirectory, "npm-package.tgz"));
    writePackageManifest("git+https://github.com/Sift-wiki/sift-q-release.git");
    writeFileSync(join(packageRoot, "README.md"), "repacked fixture bytes\n");
    pack();
    await assert.rejects(
      verifyCandidate({
        sourceRoot,
        candidateDirectory,
        trustPolicyPath,
        selection,
        expectedReceiptDigest: receiptDigest,
        expectedVersion: "1.2.3",
      }),
      /tarball bytes differ/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
