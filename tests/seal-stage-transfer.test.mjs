import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  SEALED_TRANSFER_SCHEMA,
  openEnvelope,
  sealDirectory,
} from "../scripts/seal-stage-transfer.mjs";

const keys = generateKeyPairSync("rsa", { modulusLength: 3072 });
const publicKeyPem = keys.publicKey.export({ format: "pem", type: "spki" });
const privateKeyPem = keys.privateKey.export({ format: "pem", type: "pkcs8" });

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "sealed-stage-transfer-"));
  const input = join(root, "input");
  mkdirSync(input);
  writeFileSync(
    join(input, "npm-package.tgz"),
    "unpublished-exact-tarball-bytes",
  );
  writeFileSync(join(input, "verified-candidate.json"), '{"version":"1.2.3"}');
  return { input, root };
}

test("public artifact envelope contains ciphertext only and round-trips exact bytes", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  const envelope = sealDirectory({
    directory: value.input,
    expectedFiles: "npm-package.tgz,verified-candidate.json",
    publicKeyPem,
  });
  assert.equal(envelope.schemaVersion, SEALED_TRANSFER_SCHEMA);
  const publicBytes = JSON.stringify(envelope);
  assert.doesNotMatch(
    publicBytes,
    /unpublished-exact-tarball-bytes|npm-package|verified-candidate|1\.2\.3/,
  );
  const output = join(value.root, "output");
  assert.deepEqual(
    openEnvelope({
      envelope,
      expectedFiles: "npm-package.tgz,verified-candidate.json",
      privateKeyPem,
      outputDirectory: output,
    }),
    { files: ["npm-package.tgz", "verified-candidate.json"] },
  );
  assert.deepEqual(
    readFileSync(join(output, "npm-package.tgz")),
    readFileSync(join(value.input, "npm-package.tgz")),
  );
  assert.deepEqual(
    readFileSync(join(output, "verified-candidate.json")),
    readFileSync(join(value.input, "verified-candidate.json")),
  );
});

test("tampering with ciphertext fails authenticated decryption", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  const envelope = sealDirectory({
    directory: value.input,
    expectedFiles: "npm-package.tgz,verified-candidate.json",
    publicKeyPem,
  });
  const bytes = Buffer.from(envelope.ciphertext, "base64");
  bytes[0] ^= 1;
  envelope.ciphertext = bytes.toString("base64");
  assert.throws(
    () =>
      openEnvelope({
        envelope,
        expectedFiles: "npm-package.tgz,verified-candidate.json",
        privateKeyPem,
        outputDirectory: join(value.root, "output"),
      }),
    /authentication failed/,
  );
});

test("wrong production private key cannot open the public artifact", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  const envelope = sealDirectory({
    directory: value.input,
    expectedFiles: "npm-package.tgz,verified-candidate.json",
    publicKeyPem,
  });
  const wrong = generateKeyPairSync("rsa", {
    modulusLength: 3072,
  }).privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  assert.throws(() =>
    openEnvelope({
      envelope,
      expectedFiles: "npm-package.tgz,verified-candidate.json",
      privateKeyPem: wrong,
      outputDirectory: join(value.root, "output"),
    }),
  );
});

test("sealing refuses extra files and symlinks", (t) => {
  const value = fixture();
  t.after(() => rmSync(value.root, { force: true, recursive: true }));
  writeFileSync(join(value.input, "extra"), "extra");
  assert.throws(
    () =>
      sealDirectory({
        directory: value.input,
        expectedFiles: "npm-package.tgz,verified-candidate.json",
        publicKeyPem,
      }),
    /file set differs/,
  );
  rmSync(join(value.input, "extra"));
  rmSync(join(value.input, "verified-candidate.json"));
  symlinkSync(
    join(value.input, "npm-package.tgz"),
    join(value.input, "verified-candidate.json"),
  );
  assert.throws(
    () =>
      sealDirectory({
        directory: value.input,
        expectedFiles: "npm-package.tgz,verified-candidate.json",
        publicKeyPem,
      }),
    /symlink/,
  );
});
