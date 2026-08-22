#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { closeSync, openSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  PACKAGE_NAME,
  canonicalJson,
  validateMaintainers,
} from "./npm-provider-state.mjs";

const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const ALLOWED_ACTORS = new Set(["jxiao1024", "unobtainiumrock"]);

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

function npmJson(args, label) {
  const result = spawnSync("npm", args, {
    encoding: "utf8",
    env: { ...process.env, NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/" },
  });
  invariant(result.status === 0, `cannot read ${label} from npm`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} response is not JSON`);
  }
}

function npmText(args, label) {
  const result = spawnSync("npm", args, {
    encoding: "utf8",
    env: { ...process.env, NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/" },
  });
  invariant(result.status === 0, `cannot read ${label} from npm`);
  return result.stdout.trim();
}

function providerInputs() {
  return {
    maintainers: npmJson(
      ["view", PACKAGE_NAME, "maintainers", "--json"],
      "npm maintainers",
    ),
    distTags: npmJson(
      ["view", PACKAGE_NAME, "dist-tags", "--json"],
      "npm dist-tags",
    ),
    versions: npmJson(
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

function writeReceipt(path, value) {
  const fd = openSync(resolve(path), "wx", 0o600);
  try {
    writeFileSync(fd, `${canonicalJson(value)}\n`, "utf8");
  } finally {
    closeSync(fd);
  }
}

function main(argv) {
  const { command, values } = argumentsOf(argv);
  const rejectedVersion = required(values, "--rejected-version");
  const plan = planRejectedNextReset({ rejectedVersion, ...providerInputs() });
  if (command === "status") {
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
  const actor = npmText(["whoami"], "authenticated npm actor");
  invariant(
    ALLOWED_ACTORS.has(actor),
    "authenticated npm actor is not Nicholas or Charles",
  );
  const rechecked = planRejectedNextReset({
    rejectedVersion,
    ...providerInputs(),
  });
  invariant(
    canonicalJson(rechecked) === canonicalJson(plan),
    "npm provider state changed before next reconciliation",
  );
  const mutation = spawnSync(
    "npm",
    ["dist-tag", "add", `${PACKAGE_NAME}@${plan.resetNextTo}`, "next"],
    {
      stdio: "inherit",
      env: {
        ...process.env,
        NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
      },
    },
  );
  invariant(mutation.status === 0, "npm next reconciliation failed");
  const verified = verifyRejectedNextReset({ plan, ...providerInputs() });
  const receipt = {
    schemaVersion: "sift-q-npm-rejected-next-reconciliation/v1",
    authority: "interactive-npm-owner-2fa",
    actor,
    reason,
    observedAt: new Date().toISOString(),
    ...verified,
  };
  writeReceipt(required(values, "--receipt-output"), receipt);
  process.stdout.write(`${canonicalJson(receipt)}\n`);
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
