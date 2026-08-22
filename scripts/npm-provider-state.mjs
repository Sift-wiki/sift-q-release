#!/usr/bin/env node
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export const PACKAGE_NAME = "@sift-wiki/q";
export const EXPECTED_MAINTAINERS = Object.freeze([
  "jxiao1024",
  "unobtainiumrock",
]);

const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const MAINTAINER_NAME = /^[a-z0-9][a-z0-9._-]*$/;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function parseJson(encoded, label) {
  try {
    return JSON.parse(encoded);
  } catch {
    throw new Error(`${label} is not JSON`);
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

export function maintainerNames(value) {
  invariant(Array.isArray(value), "npm maintainers response is invalid");
  const names = value.map((entry) => {
    if (typeof entry === "string") {
      const match = /^([^\s<]+)(?:\s+<[^<>\r\n]+>)?$/.exec(entry);
      invariant(match !== null, "npm maintainer entry is invalid");
      return match[1];
    }
    invariant(
      entry !== null &&
        typeof entry === "object" &&
        !Array.isArray(entry) &&
        typeof entry.name === "string",
      "npm maintainer entry is invalid",
    );
    return entry.name;
  });
  invariant(
    names.every((name) => MAINTAINER_NAME.test(name)),
    "npm maintainer name is invalid",
  );
  invariant(
    new Set(names).size === names.length,
    "npm maintainer set contains duplicates",
  );
  return names.sort();
}

export function validateMaintainers(value) {
  const actual = maintainerNames(value);
  invariant(
    canonicalJson(actual) === canonicalJson(EXPECTED_MAINTAINERS),
    `npm maintainer authority differs: expected ${EXPECTED_MAINTAINERS.join(",")}; got ${actual.join(",")}`,
  );
  return actual;
}

function validateTags(value) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    "npm dist-tags response is invalid",
  );
  invariant(
    STABLE_VERSION.test(value.latest ?? ""),
    "npm latest tag is invalid",
  );
  if (Object.hasOwn(value, "next")) {
    invariant(STABLE_VERSION.test(value.next ?? ""), "npm next tag is invalid");
  }
  return value;
}

export function providerPreflight({ candidate, maintainers, distTags }) {
  invariant(STABLE_VERSION.test(candidate), "candidate version is invalid");
  const ownerNames = validateMaintainers(maintainers);
  const tags = validateTags(distTags);
  invariant(
    !Object.hasOwn(tags, "next") || tags.next === tags.latest,
    "next identifies an in-flight candidate distinct from latest",
  );
  const state = {
    maintainers: ownerNames,
    latest: tags.latest,
    nextBefore: tags.next ?? null,
  };
  return {
    ...state,
    digest: `sha256:${createHash("sha256").update(canonicalJson(state)).digest("hex")}`,
  };
}

export function verifyImmediatePrepublish({
  before,
  candidate,
  maintainers,
  distTags,
}) {
  const current = providerPreflight({ candidate, maintainers, distTags });
  invariant(
    canonicalJson(current) === canonicalJson(before),
    "npm provider state changed before publish",
  );
  return current;
}

export function verifyImmediatePostpublish({
  before,
  candidate,
  maintainers,
  distTags,
}) {
  const ownerNames = validateMaintainers(maintainers);
  const tags = validateTags(distTags);
  invariant(
    tags.latest === before.latest,
    "latest changed during next publication",
  );
  invariant(
    tags.next === candidate,
    "next does not identify the published candidate",
  );
  invariant(
    canonicalJson(ownerNames) === canonicalJson(before.maintainers),
    "npm maintainer authority changed during next publication",
  );
  return { maintainers: ownerNames, latest: tags.latest, next: tags.next };
}

function argumentsOf(argv) {
  const [command, ...rest] = argv;
  const values = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    invariant(
      key?.startsWith("--") && rest[index + 1] !== undefined,
      "invalid provider-state arguments",
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

function main(argv) {
  const { command, values } = argumentsOf(argv);
  const maintainers = parseJson(
    required(values, "--maintainers-json"),
    "npm maintainers response",
  );
  if (command === "maintainers") {
    process.stdout.write(
      `${canonicalJson(validateMaintainers(maintainers))}\n`,
    );
    return;
  }
  const candidate = required(values, "--candidate");
  const distTags = parseJson(
    required(values, "--dist-tags-json"),
    "npm dist-tags response",
  );
  let result;
  if (command === "preflight") {
    result = providerPreflight({ candidate, maintainers, distTags });
  } else if (command === "prepublish") {
    result = verifyImmediatePrepublish({
      before: parseJson(
        required(values, "--before-json"),
        "provider preflight",
      ),
      candidate,
      maintainers,
      distTags,
    });
  } else if (command === "postpublish") {
    result = verifyImmediatePostpublish({
      before: parseJson(
        required(values, "--before-json"),
        "provider preflight",
      ),
      candidate,
      maintainers,
      distTags,
    });
  } else {
    throw new Error(`unknown provider-state command ${command ?? ""}`);
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `npm provider state refused: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
