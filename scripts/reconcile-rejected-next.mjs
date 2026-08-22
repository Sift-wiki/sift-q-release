#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  PACKAGE_NAME,
  canonicalJson,
  validateMaintainers,
} from "./npm-provider-state.mjs";

const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const ALLOWED_ACTORS = new Set(["jxiao1024", "unobtainiumrock"]);
const CANONICAL_REGISTRY = "https://registry.npmjs.org/";
const PINNED_NPM_VERSION = "11.19.0";

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function versionsOf(value) {
  const versions = typeof value === "string" ? [value] : value;
  invariant(
    Array.isArray(versions) &&
      versions.every((item) => STABLE_VERSION.test(item)),
    "npm versions response is invalid",
  );
  return versions;
}

export function planRejectedNextReset({
  rejectedVersion,
  maintainers,
  distTags,
  versions,
}) {
  invariant(
    STABLE_VERSION.test(rejectedVersion),
    "rejected version is invalid",
  );
  const ownerNames = validateMaintainers(maintainers);
  invariant(
    distTags !== null &&
      typeof distTags === "object" &&
      !Array.isArray(distTags),
    "npm dist-tags response is invalid",
  );
  invariant(
    STABLE_VERSION.test(distTags.latest ?? ""),
    "npm latest tag is invalid",
  );
  invariant(
    distTags.next === rejectedVersion,
    "next does not identify the rejected candidate",
  );
  invariant(
    distTags.latest !== rejectedVersion,
    "rejected candidate is already latest and cannot be reconciled as next-only",
  );
  invariant(
    versionsOf(versions).includes(rejectedVersion),
    "rejected candidate version is not published",
  );
  return {
    packageName: PACKAGE_NAME,
    rejectedVersion,
    resetNextTo: distTags.latest,
    latest: distTags.latest,
    maintainers: ownerNames,
  };
}

export function verifyRejectedNextReset({ plan, maintainers, distTags }) {
  const ownerNames = validateMaintainers(maintainers);
  invariant(
    canonicalJson(ownerNames) === canonicalJson(plan.maintainers),
    "npm maintainer authority changed during next reconciliation",
  );
  invariant(
    distTags?.latest === plan.latest,
    "latest changed during next reconciliation",
  );
  invariant(
    distTags?.next === plan.resetNextTo,
    "next was not reset to the settled latest version",
  );
  return { ...plan, nextAfter: distTags.next };
}

function npmRun(runtime, args, options = {}) {
  return spawnSync(process.execPath, [runtime.cliPath, ...args], {
    ...options,
    env: runtime.env,
  });
}

function npmJson(runtime, args, label) {
  const result = npmRun(runtime, args, {
    encoding: "utf8",
  });
  invariant(result.status === 0, `cannot read ${label} from npm`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} response is not JSON`);
  }
}

function npmText(runtime, args, label) {
  const result = npmRun(runtime, args, {
    encoding: "utf8",
  });
  invariant(result.status === 0, `cannot read ${label} from npm`);
  return result.stdout.trim();
}

function providerInputs(runtime) {
  return {
    maintainers: npmJson(
      runtime,
      ["view", PACKAGE_NAME, "maintainers", "--json"],
      "npm maintainers",
    ),
    distTags: npmJson(
      runtime,
      ["view", PACKAGE_NAME, "dist-tags", "--json"],
      "npm dist-tags",
    ),
    versions: npmJson(
      runtime,
      ["view", PACKAGE_NAME, "versions", "--json"],
      "npm versions",
    ),
  };
}

function argumentsOf(argv) {
  const [command, ...rest] = argv;
  const values = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    invariant(
      key?.startsWith("--") && rest[index + 1] !== undefined,
      "invalid rejected-next arguments",
    );
    invariant(!values.has(key), `duplicate argument ${key}`);
    values.set(key, rest[index + 1]);
  }
  return { command, values };
}

function required(values, key) {
  const value = values.get(key);
  invariant(value !== undefined && value !== "", `missing ${key}`);
  return value;
}

function regularProtectedPath(value, label) {
  invariant(isAbsolute(value), `${label} path is not absolute`);
  invariant(
    !lstatSync(value).isSymbolicLink(),
    `${label} must not be a symlink`,
  );
  const path = realpathSync(value);
  const stat = lstatSync(path);
  invariant(stat.isFile() && !stat.isSymbolicLink(), `${label} is not a file`);
  return { path, stat };
}

function npmRuntimeOf(values) {
  const cli = regularProtectedPath(required(values, "--npm-cli-js"), "npm CLI");
  const userconfig = regularProtectedPath(
    required(values, "--npm-userconfig"),
    "npm userconfig",
  );
  invariant(
    (userconfig.stat.mode & 0o077) === 0,
    "npm userconfig must not be group/world accessible",
  );
  invariant(
    (cli.stat.mode & 0o022) === 0,
    "npm CLI must not be group/world writable",
  );
  const runtime = {
    cliPath: cli.path,
    cliDigest: `sha256:${createHash("sha256").update(readFileSync(cli.path)).digest("hex")}`,
    userconfigPath: userconfig.path,
    env: {
      NPM_CONFIG_USERCONFIG: userconfig.path,
      NPM_CONFIG_GLOBALCONFIG: "/dev/null",
      NPM_CONFIG_REGISTRY: CANONICAL_REGISTRY,
      "npm_config_@sift-wiki:registry": CANONICAL_REGISTRY,
      NPM_CONFIG_AUDIT: "false",
      NPM_CONFIG_FUND: "false",
      NPM_CONFIG_IGNORE_SCRIPTS: "true",
    },
  };
  invariant(
    npmText(runtime, ["--version"], "npm version") === PINNED_NPM_VERSION,
    `npm version is not pinned ${PINNED_NPM_VERSION}`,
  );
  invariant(
    npmText(runtime, ["config", "get", "registry"], "npm registry") ===
      CANONICAL_REGISTRY,
    "effective npm registry is not canonical",
  );
  invariant(
    npmText(
      runtime,
      ["config", "get", "@sift-wiki:registry"],
      "scoped npm registry",
    ) === CANONICAL_REGISTRY,
    "effective @sift-wiki registry is not canonical",
  );
  return runtime;
}

function reserveReceipt(path) {
  const resolved = resolve(path);
  return { fd: openSync(resolved, "wx", 0o600), path: resolved };
}

function writeReceipt(reservation, value) {
  writeFileSync(reservation.fd, `${canonicalJson(value)}\n`, "utf8");
}

function main(argv) {
  const { command, values } = argumentsOf(argv);
  const rejectedVersion = required(values, "--rejected-version");
  if (command === "status") {
    const runtime = npmRuntimeOf(values);
    const plan = planRejectedNextReset({
      rejectedVersion,
      ...providerInputs(runtime),
    });
    process.stdout.write(`${canonicalJson(plan)}\n`);
    return;
  }
  invariant(
    command === "reset",
    `unknown rejected-next command ${command ?? ""}`,
  );
  invariant(
    required(values, "--confirm") === "RESET-REJECTED-NEXT-TO-LATEST",
    "reset confirmation phrase differs",
  );
  const reason = required(values, "--reason").trim();
  invariant(
    reason.length >= 20 && reason.length <= 500,
    "reset reason must be 20..500 characters",
  );
  const reservation = reserveReceipt(required(values, "--receipt-output"));
  let mutationApplied = false;
  let receiptWritten = false;
  try {
    const runtime = npmRuntimeOf(values);
    const plan = planRejectedNextReset({
      rejectedVersion,
      ...providerInputs(runtime),
    });
    const actor = npmText(runtime, ["whoami"], "authenticated npm actor");
    invariant(
      ALLOWED_ACTORS.has(actor),
      "authenticated npm actor is not Nicholas or Charles",
    );
    const rechecked = planRejectedNextReset({
      rejectedVersion,
      ...providerInputs(runtime),
    });
    invariant(
      canonicalJson(rechecked) === canonicalJson(plan),
      "npm provider state changed before next reconciliation",
    );
    const mutation = npmRun(
      runtime,
      ["dist-tag", "add", `${PACKAGE_NAME}@${plan.resetNextTo}`, "next"],
      {
        stdio: "inherit",
      },
    );
    invariant(mutation.status === 0, "npm next reconciliation failed");
    mutationApplied = true;
    const verified = verifyRejectedNextReset({
      plan,
      ...providerInputs(runtime),
    });
    const receipt = {
      schemaVersion: "sift-q-npm-rejected-next-reconciliation/v1",
      authority: "interactive-npm-owner-2fa",
      actor,
      reason,
      observedAt: new Date().toISOString(),
      npmClient: {
        cliPath: runtime.cliPath,
        cliDigest: runtime.cliDigest,
        nodePath: process.execPath,
        nodeVersion: process.version,
        version: PINNED_NPM_VERSION,
      },
      registry: CANONICAL_REGISTRY,
      ...verified,
    };
    writeReceipt(reservation, receipt);
    receiptWritten = true;
    process.stdout.write(`${canonicalJson(receipt)}\n`);
  } finally {
    closeSync(reservation.fd);
    if (!mutationApplied && !receiptWritten) unlinkSync(reservation.path);
  }
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `rejected-next reconciliation refused: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
