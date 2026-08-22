import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  planRejectedNextReset,
  verifyRejectedNextReset,
} from "../scripts/reconcile-rejected-next.mjs";

const maintainers = [
  "unobtainiumrock <unobtainiumrock@gmail.com>",
  "jxiao1024 <jxiao1024@gmail.com>",
];

test("plans a rejected next reset only to the unchanged settled latest", () => {
  const plan = planRejectedNextReset({
    rejectedVersion: "0.11.0",
    maintainers,
    distTags: { latest: "0.10.0", next: "0.11.0" },
    versions: ["0.10.0", "0.11.0"],
  });
  assert.deepEqual(plan, {
    packageName: "@sift-wiki/q",
    rejectedVersion: "0.11.0",
    resetNextTo: "0.10.0",
    latest: "0.10.0",
    maintainers: ["jxiao1024", "unobtainiumrock"],
  });
  assert.equal(
    verifyRejectedNextReset({
      plan,
      maintainers,
      distTags: { latest: "0.10.0", next: "0.10.0" },
    }).nextAfter,
    "0.10.0",
  );
});

for (const [label, mutation, expected] of [
  [
    "different next",
    { latest: "0.10.0", next: "0.12.0" },
    /next does not identify/,
  ],
  ["already latest", { latest: "0.11.0", next: "0.11.0" }, /already latest/],
]) {
  test(`refuses ${label}`, () => {
    assert.throws(
      () =>
        planRejectedNextReset({
          rejectedVersion: "0.11.0",
          maintainers,
          distTags: mutation,
          versions: ["0.10.0", "0.11.0", "0.12.0"],
        }),
      expected,
    );
  });
}

test("the reset CLI has one governed mutation and never removes next", () => {
  const source = readFileSync(
    new URL("../scripts/reconcile-rejected-next.mjs", import.meta.url),
    "utf8",
  );
  assert.equal((source.match(/"dist-tag", "add"/g) ?? []).length, 1);
  assert.doesNotMatch(source, /spawnSync\("npm"/);
  assert.doesNotMatch(source, /"dist-tag", "rm"/);
  assert.match(source, /PINNED_NPM_VERSION = "11\.19\.0"/);
  assert.match(source, /npm_config_@sift-wiki:registry/);
  assert.match(source, /NPM_CONFIG_USERCONFIG/);
  assert.match(source, /npm userconfig must not be group\/world accessible/);
  assert.match(source, /npm CLI must not be group\/world writable/);
  assert.match(source, /RESET-REJECTED-NEXT-TO-LATEST/);
  assert.match(source, /authenticated npm actor is not Nicholas or Charles/);
  assert.match(source, /npm provider state changed before next reconciliation/);
  assert.match(source, /interactive-npm-owner-2fa/);
});

function resetWithReceiptArgs(receiptArgs) {
  const directory = mkdtempSync(join(tmpdir(), "sift-q-rejected-next-"));
  const npmLog = join(directory, "npm-calls.log");
  const fakeNpm = join(directory, "npm");
  writeFileSync(
    fakeNpm,
    `#!/bin/sh\nprintf '%s\\n' "$*" >>"$NPM_CALL_LOG"\nexit 99\n`,
  );
  chmodSync(fakeNpm, 0o700);
  const result = spawnSync(
    process.execPath,
    [
      new URL("../scripts/reconcile-rejected-next.mjs", import.meta.url)
        .pathname,
      "reset",
      "--rejected-version",
      "0.11.0",
      "--confirm",
      "RESET-REJECTED-NEXT-TO-LATEST",
      "--reason",
      "the exact registry canary rejected this candidate",
      ...receiptArgs,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        NPM_CALL_LOG: npmLog,
        PATH: `${directory}:${process.env.PATH}`,
      },
    },
  );
  return {
    ...result,
    npmCalls: existsSync(npmLog) ? readFileSync(npmLog, "utf8") : "",
  };
}

test("missing receipt output refuses before any npm mutation", () => {
  const result = resetWithReceiptArgs([]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing --receipt-output/);
  assert.equal(result.npmCalls, "");
});

test("an existing receipt output refuses before any npm mutation", () => {
  const directory = mkdtempSync(join(tmpdir(), "sift-q-existing-receipt-"));
  const receipt = join(directory, "receipt.json");
  writeFileSync(receipt, "preserve me\n", { mode: 0o600 });
  const result = resetWithReceiptArgs(["--receipt-output", receipt]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /EEXIST/);
  assert.equal(result.npmCalls, "");
  assert.equal(readFileSync(receipt, "utf8"), "preserve me\n");
});

test("an unavailable receipt output refuses before any npm mutation", () => {
  const receipt = `/proc/1/sift-q-rejected-next-${process.pid}.json`;
  const result = resetWithReceiptArgs(["--receipt-output", receipt]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /EACCES|ENOENT|EROFS/);
  assert.equal(result.npmCalls, "");
});

test("reset uses only the pinned npm client, canonical registry, and owner auth file", () => {
  const directory = mkdtempSync(join(tmpdir(), "sift-q-pinned-npm-"));
  const cli = join(directory, "npm-cli.mjs");
  const state = join(directory, "state.json");
  const calls = join(directory, "calls.jsonl");
  const userconfig = join(directory, "owner.npmrc");
  const receipt = join(directory, "receipt.json");
  writeFileSync(state, `${JSON.stringify({ next: "0.11.0" })}\n`);
  writeFileSync(userconfig, "//registry.npmjs.org/:_authToken=test-only\n", {
    mode: 0o600,
  });
  writeFileSync(
    cli,
    `import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
const stateFile = ${JSON.stringify(state)};
const callsFile = ${JSON.stringify(calls)};
const args = process.argv.slice(2);
appendFileSync(callsFile, JSON.stringify({ args, env: process.env }) + "\\n");
const value = JSON.parse(readFileSync(stateFile, "utf8"));
if (args[0] === "--version") console.log("11.19.0");
else if (args.join(" ") === "config get registry") console.log("https://registry.npmjs.org/");
else if (args.join(" ") === "config get @sift-wiki:registry") console.log("https://registry.npmjs.org/");
else if (args[0] === "whoami") console.log("unobtainiumrock");
else if (args.join(" ") === "view @sift-wiki/q maintainers --json") console.log(JSON.stringify(["unobtainiumrock <unobtainiumrock@gmail.com>", "jxiao1024 <jxiao1024@gmail.com>"]));
else if (args.join(" ") === "view @sift-wiki/q dist-tags --json") console.log(JSON.stringify({ latest: "0.10.0", next: value.next }));
else if (args.join(" ") === "view @sift-wiki/q versions --json") console.log(JSON.stringify(["0.10.0", "0.11.0"]));
else if (args.join(" ") === "dist-tag add @sift-wiki/q@0.10.0 next") writeFileSync(stateFile, JSON.stringify({ next: "0.10.0" }));
else process.exitCode = 97;
`,
    { mode: 0o700 },
  );
  const result = spawnSync(
    process.execPath,
    [
      new URL("../scripts/reconcile-rejected-next.mjs", import.meta.url)
        .pathname,
      "reset",
      "--rejected-version",
      "0.11.0",
      "--npm-cli-js",
      cli,
      "--npm-userconfig",
      userconfig,
      "--confirm",
      "RESET-REJECTED-NEXT-TO-LATEST",
      "--reason",
      "the exact registry canary rejected this candidate",
      "--receipt-output",
      receipt,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        HOME: "/malicious/home",
        NPM_CONFIG_REGISTRY: "https://malicious.invalid/",
        NODE_OPTIONS: "",
      },
    },
  );
  assert.equal(result.status, 0, result.stderr);
  const recorded = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(
    recorded.some(({ args }) => args[0] === "dist-tag"),
    true,
  );
  for (const call of recorded) {
    assert.equal(call.env.NPM_CONFIG_REGISTRY, "https://registry.npmjs.org/");
    assert.equal(
      call.env["npm_config_@sift-wiki:registry"],
      "https://registry.npmjs.org/",
    );
    assert.equal(call.env.NPM_CONFIG_USERCONFIG, userconfig);
    assert.equal(call.env.NPM_CONFIG_GLOBALCONFIG, "/dev/null");
    assert.equal(call.env.HOME, undefined);
    assert.equal(call.env.PATH, undefined);
  }
  const recordedReceipt = JSON.parse(readFileSync(receipt, "utf8"));
  assert.equal(recordedReceipt.registry, "https://registry.npmjs.org/");
  assert.equal(recordedReceipt.npmClient.version, "11.19.0");
  assert.equal(recordedReceipt.npmClient.cliPath, cli);
  assert.match(recordedReceipt.npmClient.cliDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(recordedReceipt.npmClient.nodeVersion, process.version);
  assert.equal(recordedReceipt.nextAfter, "0.10.0");
});
