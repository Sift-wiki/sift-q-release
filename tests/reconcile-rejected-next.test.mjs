import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
  assert.doesNotMatch(source, /"dist-tag", "rm"/);
  assert.match(source, /RESET-REJECTED-NEXT-TO-LATEST/);
  assert.match(source, /authenticated npm actor is not Nicholas or Charles/);
  assert.match(source, /npm provider state changed before next reconciliation/);
  assert.match(source, /interactive-npm-owner-2fa/);
});
