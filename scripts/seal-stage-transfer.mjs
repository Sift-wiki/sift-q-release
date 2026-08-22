#!/usr/bin/env node
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const SEALED_TRANSFER_SCHEMA = "sift-q-sealed-stage-transfer/v1";
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys, label) {
  invariant(
    value && typeof value === "object" && !Array.isArray(value),
    `${label} is invalid`,
  );
  invariant(
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort()),
    `${label} fields differ`,
  );
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function expectedNames(value) {
  const names = value.split(",").sort();
  invariant(
    names.length > 0 &&
      names.every(
        (name) =>
          /^[A-Za-z0-9._/-]+$/.test(name) &&
          !name.startsWith("/") &&
          !name.includes(".."),
      ) &&
      new Set(names).size === names.length,
    "expected transfer file set is invalid",
  );
  return names;
}

function directoryFiles(directory) {
  const root = resolve(directory);
  const names = [];
  function visit(relative = "") {
    for (const entry of readdirSync(join(root, relative), {
      withFileTypes: true,
    }).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      invariant(!entry.isSymbolicLink(), `transfer file ${name} is a symlink`);
      if (entry.isDirectory()) visit(name);
      else {
        invariant(entry.isFile(), `transfer file ${name} has unsupported type`);
        names.push(name);
      }
    }
  }
  visit();
  return names.sort();
}

function assertRsaKey(key, label) {
  invariant(key.asymmetricKeyType === "rsa", `${label} is not RSA`);
  invariant(
    (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 3072,
    `${label} is too small`,
  );
  return key;
}

export function sealDirectory({ directory, expectedFiles, publicKeyPem }) {
  const root = resolve(directory);
  const expected = expectedNames(expectedFiles);
  const actual = directoryFiles(root);
  invariant(
    JSON.stringify(actual) === JSON.stringify(expected),
    "transfer input file set differs",
  );
  const files = actual.map((name) => {
    const path = join(root, name);
    const stat = lstatSync(path);
    invariant(
      stat.size > 0 && stat.size <= MAX_FILE_BYTES,
      `transfer file ${name} size differs`,
    );
    const bytes = readFileSync(path);
    return {
      bytes: bytes.length,
      data: bytes.toString("base64"),
      digest: sha256(bytes),
      name,
    };
  });
  const payload = Buffer.from(canonicalJson({ files }));
  invariant(
    payload.length <= MAX_PAYLOAD_BYTES,
    "transfer payload is too large",
  );
  const publicKey = assertRsaKey(
    createPublicKey(publicKeyPem),
    "transfer public key",
  );
  const contentKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", contentKey, iv);
  cipher.setAAD(Buffer.from(SEALED_TRANSFER_SCHEMA));
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const authenticationTag = cipher.getAuthTag();
  const encryptedKey = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
      oaepLabel: Buffer.from(SEALED_TRANSFER_SCHEMA),
    },
    contentKey,
  );
  return {
    schemaVersion: SEALED_TRANSFER_SCHEMA,
    algorithm: "RSA-OAEP-3072+/SHA-256+AES-256-GCM",
    authenticationTag: authenticationTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    encryptedKey: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
  };
}

export function openEnvelope({
  envelope,
  expectedFiles,
  privateKeyPem,
  outputDirectory,
}) {
  exactKeys(
    envelope,
    [
      "algorithm",
      "authenticationTag",
      "ciphertext",
      "encryptedKey",
      "iv",
      "schemaVersion",
    ],
    "sealed transfer",
  );
  invariant(
    envelope.schemaVersion === SEALED_TRANSFER_SCHEMA &&
      envelope.algorithm === "RSA-OAEP-3072+/SHA-256+AES-256-GCM",
    "sealed transfer identity differs",
  );
  const privateKey = assertRsaKey(
    createPrivateKey(privateKeyPem),
    "transfer private key",
  );
  const contentKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
      oaepLabel: Buffer.from(SEALED_TRANSFER_SCHEMA),
    },
    Buffer.from(envelope.encryptedKey, "base64"),
  );
  invariant(contentKey.length === 32, "sealed transfer content key differs");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    contentKey,
    Buffer.from(envelope.iv, "base64"),
  );
  decipher.setAAD(Buffer.from(SEALED_TRANSFER_SCHEMA));
  decipher.setAuthTag(Buffer.from(envelope.authenticationTag, "base64"));
  let payload;
  try {
    payload = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);
  } catch {
    throw new Error("sealed transfer authentication failed");
  }
  invariant(
    payload.length > 0 && payload.length <= MAX_PAYLOAD_BYTES,
    "sealed transfer payload differs",
  );
  const decoded = JSON.parse(payload.toString("utf8"));
  exactKeys(decoded, ["files"], "sealed transfer payload");
  invariant(Array.isArray(decoded.files), "sealed transfer files are invalid");
  const expected = expectedNames(expectedFiles);
  invariant(
    JSON.stringify(decoded.files.map((file) => file.name)) ===
      JSON.stringify(expected),
    "sealed transfer file set differs",
  );
  const root = resolve(outputDirectory);
  mkdirSync(root, { mode: 0o700, recursive: false });
  for (const file of decoded.files) {
    exactKeys(
      file,
      ["bytes", "data", "digest", "name"],
      "sealed transfer file",
    );
    const bytes = Buffer.from(file.data, "base64");
    invariant(
      Number.isSafeInteger(file.bytes) &&
        file.bytes > 0 &&
        file.bytes <= MAX_FILE_BYTES &&
        bytes.length === file.bytes &&
        sha256(bytes) === file.digest,
      `sealed transfer file ${file.name} differs`,
    );
    const destination = join(root, file.name);
    mkdirSync(resolve(destination, ".."), { mode: 0o700, recursive: true });
    writeFileSync(destination, bytes, { flag: "wx", mode: 0o600 });
  }
  return { files: expected };
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    invariant(
      key?.startsWith("--") && argv[index + 1],
      "transfer arguments are invalid",
    );
    invariant(!values.has(key), `duplicate argument ${key}`);
    values.set(key, argv[index + 1]);
  }
  return values;
}

function required(values, key) {
  const value = values.get(key);
  invariant(value, `missing ${key}`);
  return value;
}

function main(argv) {
  const [command, ...rest] = argv;
  const values = parseArguments(rest);
  if (command === "seal") {
    const result = sealDirectory({
      directory: required(values, "--directory"),
      expectedFiles: required(values, "--expected-files"),
      publicKeyPem: readFileSync(required(values, "--public-key"), "utf8"),
    });
    writeFileSync(required(values, "--output"), canonicalJson(result), {
      flag: "wx",
      mode: 0o600,
    });
    return;
  }
  if (command === "open") {
    openEnvelope({
      envelope: JSON.parse(
        readFileSync(required(values, "--envelope"), "utf8"),
      ),
      expectedFiles: required(values, "--expected-files"),
      privateKeyPem: readFileSync(required(values, "--private-key"), "utf8"),
      outputDirectory: required(values, "--directory"),
    });
    return;
  }
  throw new Error(`unknown command ${command ?? ""}`);
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `sealed stage transfer refused: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
