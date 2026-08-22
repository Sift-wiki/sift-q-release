import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign as signMessage,
} from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  CANONICAL_REGISTRY,
  LATEST_PROMOTION_BINDING_SCHEMA,
  LATEST_PROMOTION_RESULT_SCHEMA,
  LATEST_PROMOTION_TRUST_SCHEMA,
  NEXT_TRANSITION_SCHEMA,
  SIGNED_LATEST_PROMOTION_SCHEMA,
  canonicalJson,
  promotionBindingFor,
  recordRegistryTransition,
  runRegistryCanary,
  validateNextTransitionEvidence,
  validatePromotionBinding,
  verifyCompletedPromotion,
  verifySignedPromotionReceipt,
} from "../scripts/verify-registry-transition.mjs";

const SOURCE_SHA = "1".repeat(40);
const TREE_SHA = "2".repeat(40);
const RECEIPT_DIGEST = `sha256:${"3".repeat(64)}`;
const VERSION = "1.2.3";

function sha1(bytes) {
  return createHash("sha1").update(bytes).digest("hex");
}

function integrity(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

function makePackage(
  root,
  { versionOutput = `sift-q ${VERSION}`, writeHome = false } = {},
) {
  const packageRoot = join(
    root,
    `package-${Math.random().toString(16).slice(2)}`,
  );
  const destination = join(root, `pack-${Math.random().toString(16).slice(2)}`);
  mkdirSync(packageRoot);
  mkdirSync(destination);
  writeFileSync(
    join(packageRoot, "package.json"),
    `${JSON.stringify({
      name: "@sift-wiki/q",
      version: VERSION,
      repository: {
        type: "git",
        url: "git+https://github.com/Sift-wiki/sift-q-release.git",
      },
      bin: { "sift-q": "bin.cjs" },
      files: ["bin.cjs"],
    })}\n`,
  );
  writeFileSync(
    join(packageRoot, "bin.cjs"),
    `#!/usr/bin/env node
const args = process.argv.slice(2);
${writeHome ? 'require("node:fs").writeFileSync(require("node:path").join(process.env.HOME, "unexpected-write"), "unsafe");' : ""}
if (args.length === 1 && args[0] === "--version") {
  process.stdout.write(${JSON.stringify(`${versionOutput}\n`)});
} else if (JSON.stringify(args) === JSON.stringify(["--dry-run", "--json", "--client", "claude"])) {
  process.stdout.write(JSON.stringify({
    detection: { platform: { ok: true } },
    plan: [{ id: "fetch-hosted-content" }, { id: "register-claude" }],
    result: { stepResults: [] }
  }));
} else {
  process.stderr.write("unexpected arguments\\n");
  process.exitCode = 1;
}
`,
    { mode: 0o755 },
  );
  const packed = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--ignore-scripts", "--json", "--pack-destination", destination],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env: { ...process.env, npm_config_cache: join(root, "npm-cache") },
      },
    ),
  );
  assert.equal(packed.length, 1);
  return join(destination, packed[0].filename);
}

function validCanary() {
  return {
    dryRunCommand: "sift-q --dry-run --json --client claude",
    dryRunPlan: ["fetch-hosted-content", "register-claude"],
    homeIsolation: "fresh-empty-temporary-home",
    installCommand:
      "npm install ./registry-package.tgz --ignore-scripts --no-audit --no-fund --package-lock=false",
    versionCommand: "sift-q --version",
    versionOutput: `sift-q ${VERSION}`,
    writesObserved: 0,
  };
}

function metadata(
  path,
  tarballUrl = `${CANONICAL_REGISTRY}@sift-wiki/q/-/q-${VERSION}.tgz`,
) {
  const bytes = readFileSync(path);
  return {
    name: "@sift-wiki/q",
    version: VERSION,
    dist: {
      integrity: integrity(bytes),
      shasum: sha1(bytes),
      tarball: tarballUrl,
    },
  };
}

function inputs(
  root,
  selectedTarballPath,
  registryTarballPath = selectedTarballPath,
) {
  const metadataPath = join(root, "registry.json");
  writeFileSync(metadataPath, JSON.stringify(metadata(registryTarballPath)));
  return {
    selectedTarballPath,
    registryTarballPath,
    registryMetadataPath: metadataPath,
    sourceSha: SOURCE_SHA,
    treeSha: TREE_SHA,
    candidateRunId: 42,
    candidateRunAttempt: 2,
    candidateReceiptDigest: RECEIPT_DIGEST,
    latestBefore: "1.2.2",
    latestAfter: "1.2.2",
    version: VERSION,
    nextTagVersion: VERSION,
    canary: validCanary(),
    outputPath: join(root, "transition.json"),
    promotionBindingPath: join(root, "binding.json"),
    now: () => new Date("2026-08-21T22:00:00.000Z"),
  };
}

function signedReceipt(binding, privateKey, overrides = {}) {
  const body = {
    schemaVersion: SIGNED_LATEST_PROMOTION_SCHEMA,
    algorithm: "Ed25519",
    keyId: "owner-promotion-test-key",
    authorizationId: "authorization-0001",
    authorizedAt: "2026-08-21T21:55:00.000Z",
    expiresAt: "2026-08-21T22:05:00.000Z",
    binding,
    ...overrides,
  };
  return {
    ...body,
    signature: signMessage(
      null,
      Buffer.from(canonicalJson(body)),
      privateKey,
    ).toString("base64"),
  };
}

const VERIFY_NOW = () => new Date("2026-08-21T22:00:00.000Z");

test("records exact registry bytes, a clean CLI canary, and an unsigned promotion binding", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const args = inputs(root, tarball);
    args.canary = runRegistryCanary(tarball, VERSION);
    const result = recordRegistryTransition(args);
    assert.equal(result.evidence.schemaVersion, NEXT_TRANSITION_SCHEMA);
    assert.equal(
      result.evidence.authority,
      "unsigned-non-authoritative-transition-evidence",
    );
    assert.equal(result.evidence.registry.distTag, "next");
    assert.equal(result.evidence.registry.latestBefore, "1.2.2");
    assert.equal(result.evidence.registry.latestAfter, "1.2.2");
    assert.deepEqual(result.evidence.canary.dryRunPlan, [
      "fetch-hosted-content",
      "register-claude",
    ]);
    assert.equal(result.evidence.canary.writesObserved, 0);
    assert.equal(result.binding.schemaVersion, LATEST_PROMOTION_BINDING_SCHEMA);
    assert.equal(result.binding.fromDistTag, "next");
    assert.equal(result.binding.toDistTag, "latest");
    assert.equal(
      result.binding.transitionEvidenceDigest,
      result.transitionEvidenceDigest,
    );
    assert.equal(statSync(join(root, "transition.json")).mode & 0o777, 0o600);
    assert.equal(statSync(join(root, "binding.json")).mode & 0o777, 0o600);
    assert.equal(
      readFileSync(join(root, "transition.json"), "utf8"),
      canonicalJson(result.evidence),
    );
    assert.equal(
      readFileSync(join(root, "binding.json"), "utf8"),
      canonicalJson(result.binding),
    );
    assert.match(canonicalJson(result.evidence), /unsigned-non-authoritative/);
    validatePromotionBinding(result.binding, result.evidence);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the clean canary refuses a CLI that writes into HOME while reporting no steps", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root, { writeHome: true });
    assert.throws(
      () => runRegistryCanary(tarball, VERSION),
      /registry canary wrote HOME or XDG surfaces/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("refuses changed registry bytes before executing the registry canary", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const selected = makePackage(root);
    const changed = makePackage(root, { versionOutput: "tampered" });
    assert.throws(
      () => recordRegistryTransition(inputs(root, selected, changed)),
      /registry tarball bytes differ from selected candidate/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("refuses a latest move or any noncanonical registry tarball URL", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const moved = inputs(root, tarball);
    moved.latestAfter = VERSION;
    assert.throws(
      () => recordRegistryTransition(moved),
      /latest changed during next publication/,
    );

    const unsafe = inputs(root, tarball);
    writeFileSync(
      unsafe.registryMetadataPath,
      JSON.stringify(
        metadata(tarball, `https://registry.example.invalid/q-${VERSION}.tgz`),
      ),
    );
    assert.throws(
      () => recordRegistryTransition(unsafe),
      /registry tarball URL is not canonical/,
    );

    for (const tarballUrl of [
      `https://registry.npmjs.org:444/@sift-wiki/q/-/q-${VERSION}.tgz`,
      `https://user@registry.npmjs.org/@sift-wiki/q/-/q-${VERSION}.tgz`,
      `https://registry.npmjs.org/@sift-wiki/q/-/q-${VERSION}.tgz?changed=1`,
      `https://registry.npmjs.org/@sift-wiki/q/-/q-${VERSION}.tgz#changed`,
    ]) {
      const variant = inputs(root, tarball);
      writeFileSync(
        variant.registryMetadataPath,
        JSON.stringify(metadata(tarball, tarballUrl)),
      );
      assert.throws(
        () => recordRegistryTransition(variant),
        /registry tarball URL is not canonical/,
      );
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("refuses a substituted next tag or registry digest metadata", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const substitutedTag = inputs(root, tarball);
    substitutedTag.nextTagVersion = "1.2.2";
    assert.throws(
      () => recordRegistryTransition(substitutedTag),
      /next tag does not select the candidate version/,
    );

    const wrongDigest = inputs(root, tarball);
    const value = metadata(tarball);
    value.dist.shasum = "f".repeat(40);
    writeFileSync(wrongDigest.registryMetadataPath, JSON.stringify(value));
    assert.throws(
      () => recordRegistryTransition(wrongDigest),
      /registry shasum differs from registry bytes/,
    );

    const malformedIntegrity = inputs(root, tarball);
    const malformedValue = metadata(tarball);
    malformedValue.dist.integrity = "sha512-X";
    writeFileSync(
      malformedIntegrity.registryMetadataPath,
      JSON.stringify(malformedValue),
    );
    assert.throws(
      () => recordRegistryTransition(malformedIntegrity),
      /registry integrity is invalid/,
    );

    const wrongIntegrity = inputs(root, tarball);
    const wrongIntegrityValue = metadata(tarball);
    wrongIntegrityValue.dist.integrity = `sha512-${"A".repeat(86)}==`;
    writeFileSync(
      wrongIntegrity.registryMetadataPath,
      JSON.stringify(wrongIntegrityValue),
    );
    assert.throws(
      () => recordRegistryTransition(wrongIntegrity),
      /registry integrity differs from registry bytes/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("refuses a stable candidate that does not advance latest", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const value = inputs(root, tarball);
    value.latestBefore = "1.3.0";
    value.latestAfter = "1.3.0";
    assert.throws(
      () => recordRegistryTransition(value),
      /candidate version does not advance latest/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("strict evidence and promotion binding reject added or substituted fields", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const { evidence } = recordRegistryTransition(inputs(root, tarball));
    assert.throws(
      () =>
        validateNextTransitionEvidence({
          ...evidence,
          signature: "self-signed",
        }),
      /transition evidence fields differ/,
    );
    assert.throws(
      () =>
        validateNextTransitionEvidence({
          ...evidence,
          authority: "owner-authorized",
        }),
      /transition authority differs/,
    );
    const binding = promotionBindingFor(evidence);
    assert.throws(
      () =>
        validatePromotionBinding({ ...binding, version: "1.2.4" }, evidence),
      /promotion binding differs from transition evidence/,
    );
    assert.throws(
      () =>
        validatePromotionBinding({ ...binding, signer: "untrusted" }, evidence),
      /promotion binding fields differ/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("promotion authority requires a fresh Ed25519 authorization and exact live tag preconditions", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const { evidence, binding } = recordRegistryTransition(
      inputs(root, tarball),
    );
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const keyId = "owner-promotion-test-key";
    const trustPolicy = {
      schemaVersion: LATEST_PROMOTION_TRUST_SCHEMA,
      keys: [
        {
          algorithm: "Ed25519",
          keyId,
          publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
        },
      ],
    };
    const receipt = signedReceipt(binding, privateKey);
    assert.deepEqual(
      verifySignedPromotionReceipt({
        receipt,
        trustPolicy,
        evidence,
        currentLatest: "1.2.2",
        currentNext: VERSION,
        now: VERIFY_NOW,
      }),
      { authorizationId: "authorization-0001", binding },
    );
    assert.throws(
      () =>
        verifySignedPromotionReceipt({
          receipt: { ...receipt, signature: "" },
          trustPolicy,
          evidence,
          currentLatest: "1.2.2",
          currentNext: VERSION,
          now: VERIFY_NOW,
        }),
      /signed promotion receipt signature is invalid/,
    );
    assert.throws(
      () =>
        verifySignedPromotionReceipt({
          receipt,
          trustPolicy: { ...trustPolicy, keys: [] },
          evidence,
          currentLatest: "1.2.2",
          currentNext: VERSION,
          now: VERIFY_NOW,
        }),
      /promotion trust policy identity differs/,
    );
    const substituted = { ...binding, version: "1.2.4" };
    const substitutedReceipt = signedReceipt(substituted, privateKey);
    assert.throws(
      () =>
        verifySignedPromotionReceipt({
          receipt: substitutedReceipt,
          trustPolicy,
          evidence,
          currentLatest: "1.2.2",
          currentNext: VERSION,
          now: VERIFY_NOW,
        }),
      /promotion binding differs from transition evidence/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("promotion authority rejects future, expired, overlong, and stale-tag replay", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const { evidence, binding } = recordRegistryTransition(
      inputs(root, tarball),
    );
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const trustPolicy = {
      schemaVersion: LATEST_PROMOTION_TRUST_SCHEMA,
      keys: [
        {
          algorithm: "Ed25519",
          keyId: "owner-promotion-test-key",
          publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
        },
      ],
    };
    const verify = (receipt, overrides = {}) =>
      verifySignedPromotionReceipt({
        receipt,
        trustPolicy,
        evidence,
        currentLatest: "1.2.2",
        currentNext: VERSION,
        now: VERIFY_NOW,
        ...overrides,
      });
    assert.throws(
      () =>
        verify(
          signedReceipt(binding, privateKey, {
            authorizedAt: "2026-08-21T22:01:00.000Z",
            expiresAt: "2026-08-21T22:05:00.000Z",
          }),
        ),
      /future-dated/,
    );
    assert.throws(
      () =>
        verify(
          signedReceipt(binding, privateKey, {
            authorizedAt: "2026-08-21T21:40:00.000Z",
            expiresAt: "2026-08-21T21:55:00.000Z",
          }),
        ),
      /expired/,
    );
    assert.throws(
      () =>
        verify(
          signedReceipt(binding, privateKey, {
            authorizedAt: "2026-08-21T21:45:00.000Z",
            expiresAt: "2026-08-21T22:01:00.000Z",
          }),
        ),
      /window is too long/,
    );
    const valid = signedReceipt(binding, privateKey);
    assert.throws(
      () => verify(valid, { currentLatest: VERSION }),
      /current latest differs/,
    );
    assert.throws(
      () => verify(valid, { currentNext: "1.2.4" }),
      /current next differs/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("promotion trust rejects duplicate key material and key-id substitution", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const { evidence, binding } = recordRegistryTransition(
      inputs(root, tarball),
    );
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
    const receipt = signedReceipt(binding, privateKey);
    const base = {
      receipt,
      evidence,
      currentLatest: "1.2.2",
      currentNext: VERSION,
      now: VERIFY_NOW,
    };
    assert.throws(
      () =>
        verifySignedPromotionReceipt({
          ...base,
          trustPolicy: {
            schemaVersion: LATEST_PROMOTION_TRUST_SCHEMA,
            keys: [
              { algorithm: "Ed25519", keyId: receipt.keyId, publicKeyPem },
              { algorithm: "Ed25519", keyId: "owner-key-alias", publicKeyPem },
            ],
          },
        }),
      /key material is duplicated/,
    );
    const substituted = signedReceipt(binding, privateKey, {
      keyId: "untrusted-owner-key",
    });
    assert.throws(
      () =>
        verifySignedPromotionReceipt({
          ...base,
          receipt: substituted,
          trustPolicy: {
            schemaVersion: LATEST_PROMOTION_TRUST_SCHEMA,
            keys: [
              {
                algorithm: "Ed25519",
                keyId: "owner-promotion-test-key",
                publicKeyPem,
              },
            ],
          },
        }),
      /signer is not trusted/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("read-only promotion verification binds owner, exact tags, release main, and registry bytes", () => {
  const root = mkdtempSync(join(tmpdir(), "sift-q-registry-transition-"));
  try {
    const tarball = makePackage(root);
    const { evidence, binding } = recordRegistryTransition(
      inputs(root, tarball),
    );
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const receipt = signedReceipt(binding, privateKey);
    const trustPolicy = {
      schemaVersion: LATEST_PROMOTION_TRUST_SCHEMA,
      keys: [
        {
          algorithm: "Ed25519",
          keyId: receipt.keyId,
          publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
        },
      ],
    };
    const base = {
      receipt,
      trustPolicy,
      evidence,
      currentLatest: VERSION,
      currentNext: VERSION,
      registryMetadata: metadata(tarball),
      registryTarballPath: tarball,
      actor: "Unobtainiumrock",
      triggeringActor: "Unobtainiumrock",
      releaseRepository: "Sift-wiki/sift-q-release",
      releaseSha: "4".repeat(40),
      workflowRunId: 101,
      workflowRunAttempt: 1,
      transitionRunId: 99,
      outputPath: join(root, "promotion-result.json"),
      now: VERIFY_NOW,
    };
    const verified = verifyCompletedPromotion(base);
    assert.equal(
      verified.result.schemaVersion,
      LATEST_PROMOTION_RESULT_SCHEMA,
    );
    assert.equal(
      verified.result.authority,
      "read-only-post-promotion-verification",
    );
    assert.equal(verified.result.registry.next, VERSION);
    assert.equal(verified.result.registry.latest, VERSION);
    assert.equal(verified.result.release.sha, "4".repeat(40));
    assert.equal(verified.result.actor, "Unobtainiumrock");
    assert.equal(verified.result.triggeringActor, "Unobtainiumrock");
    assert.match(verified.receiptDigest, /^sha256:[0-9a-f]{64}$/);

    for (const actor of ["goodnight000", "siftwiki", "unknown"])
      assert.throws(
        () =>
          verifyCompletedPromotion({
            ...base,
            actor,
            outputPath: join(root, `actor-${actor}.json`),
          }),
        /actor is not a production owner/,
      );
    for (const triggeringActor of ["goodnight000", "siftwiki", "unknown"])
      assert.throws(
        () =>
          verifyCompletedPromotion({
            ...base,
            triggeringActor,
            outputPath: join(root, `triggering-actor-${triggeringActor}.json`),
          }),
        /triggering actor is not a production owner/,
      );
    assert.throws(
      () =>
        verifyCompletedPromotion({
          ...base,
          currentLatest: "1.2.2",
          outputPath: join(root, "latest-replay.json"),
        }),
      /latest does not select the signed promoted version/,
    );
    assert.throws(
      () =>
        verifyCompletedPromotion({
          ...base,
          currentNext: "1.2.4",
          outputPath: join(root, "next-drift.json"),
        }),
      /current next differs from the signed promotion precondition/,
    );
    const substitutedMetadata = metadata(tarball);
    substitutedMetadata.dist.shasum = "f".repeat(40);
    assert.throws(
      () =>
        verifyCompletedPromotion({
          ...base,
          registryMetadata: substitutedMetadata,
          outputPath: join(root, "digest-drift.json"),
        }),
      /promoted registry digest metadata differs/,
    );
    assert.throws(
      () =>
        verifyCompletedPromotion({
          ...base,
          releaseSha: "not-main",
          outputPath: join(root, "release-drift.json"),
        }),
      /release identity differs/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
