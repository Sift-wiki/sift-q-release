#!/usr/bin/env node
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
} from "node:crypto";
import {
  closeSync,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  SIGNED_LATEST_PROMOTION_SCHEMA,
  canonicalJson,
  validatePromotionBinding,
  verifySignedPromotionReceipt,
} from "./verify-registry-transition.mjs";

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function jsonFile(path, label) {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch {
    throw new Error(`${label} is unreadable or invalid JSON`);
  }
}

function trustedKeyId(privateKey, trustPolicy) {
  const publicDer = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  invariant(
    Array.isArray(trustPolicy?.keys),
    "promotion trust policy is invalid",
  );
  const matches = trustPolicy.keys.filter((entry) => {
    try {
      return createPublicKey(entry.publicKeyPem)
        .export({ format: "der", type: "spki" })
        .equals(publicDer);
    } catch {
      return false;
    }
  });
  invariant(
    matches.length === 1,
    "private signing key is not exactly one trusted promotion key",
  );
  return matches[0].keyId;
}

export function createPromotionAuthorization({
  evidence,
  binding,
  trustPolicy,
  privateKeyBytes,
  currentLatest,
  currentNext,
  authorizationId = `npm-latest-${randomUUID()}`,
  authorizedAt = new Date(),
  ttlSeconds = 600,
}) {
  invariant(
    Number.isInteger(ttlSeconds) && ttlSeconds >= 60 && ttlSeconds <= 900,
    "authorization TTL must be 60..900 seconds",
  );
  invariant(
    authorizedAt instanceof Date && Number.isFinite(authorizedAt.getTime()),
    "authorization time is invalid",
  );
  validatePromotionBinding(binding, evidence);
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyBytes);
  } catch {
    throw new Error("private signing key is invalid");
  }
  invariant(
    privateKey.asymmetricKeyType === "ed25519",
    "private signing key is not Ed25519",
  );
  const keyId = trustedKeyId(privateKey, trustPolicy);
  const body = {
    schemaVersion: SIGNED_LATEST_PROMOTION_SCHEMA,
    algorithm: "Ed25519",
    keyId,
    authorizationId,
    authorizedAt: authorizedAt.toISOString(),
    expiresAt: new Date(
      authorizedAt.getTime() + ttlSeconds * 1000,
    ).toISOString(),
    binding,
  };
  const receipt = {
    ...body,
    signature: sign(
      null,
      Buffer.from(canonicalJson(body)),
      privateKey,
    ).toString("base64"),
  };
  verifySignedPromotionReceipt({
    receipt,
    trustPolicy,
    evidence,
    currentLatest,
    currentNext,
    now: () => authorizedAt,
  });
  return receipt;
}

function privateKeyFrom(values) {
  const path = values.get("--private-key");
  const fdValue = values.get("--private-key-fd");
  invariant(
    (path === undefined) !== (fdValue === undefined),
    "provide exactly one of --private-key or --private-key-fd",
  );
  if (path !== undefined) {
    const resolved = resolve(path);
    const stat = lstatSync(resolved);
    invariant(
      stat.isFile() && !stat.isSymbolicLink(),
      "private key path is not a regular file",
    );
    invariant(
      (stat.mode & 0o077) === 0,
      "private key file must not be group/world accessible",
    );
    return readFileSync(resolved);
  }
  invariant(/^(0|[1-9][0-9]*)$/.test(fdValue), "private key FD is invalid");
  return readFileSync(Number(fdValue));
}

function argumentsOf(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    invariant(
      key?.startsWith("--") && argv[index + 1] !== undefined,
      "invalid signer arguments",
    );
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

function writeExclusive(path, value) {
  const fd = openSync(resolve(path), "wx", 0o600);
  try {
    writeFileSync(fd, `${canonicalJson(value)}\n`, "utf8");
  } finally {
    closeSync(fd);
  }
}

function main(argv) {
  const values = argumentsOf(argv);
  const evidence = jsonFile(
    required(values, "--evidence"),
    "transition evidence",
  );
  const binding = jsonFile(required(values, "--binding"), "promotion binding");
  const trustPolicy = jsonFile(
    required(values, "--trust-policy"),
    "promotion trust policy",
  );
  const ttlSeconds = Number(values.get("--ttl-seconds") ?? "600");
  const receipt = createPromotionAuthorization({
    evidence,
    binding,
    trustPolicy,
    privateKeyBytes: privateKeyFrom(values),
    currentLatest: required(values, "--current-latest"),
    currentNext: required(values, "--current-next"),
    authorizationId:
      values.get("--authorization-id") ?? `npm-latest-${randomUUID()}`,
    ttlSeconds,
  });
  writeExclusive(required(values, "--output"), receipt);
  process.stdout.write(
    `${JSON.stringify({ authorizationId: receipt.authorizationId, expiresAt: receipt.expiresAt, signedPromotionReceiptBase64: Buffer.from(canonicalJson(receipt)).toString("base64") })}\n`,
  );
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `promotion authorization refused: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
