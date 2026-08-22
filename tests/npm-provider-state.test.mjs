import assert from "node:assert/strict";
import test from "node:test";
import {
  EXPECTED_MAINTAINERS,
  providerPreflight,
  verifyImmediatePostpublish,
  verifyImmediatePrepublish,
} from "../scripts/npm-provider-state.mjs";

const maintainers = [
  "unobtainiumrock <unobtainiumrock@gmail.com>",
  "jxiao1024 <jxiao1024@gmail.com>",
];

test("accepts only the exact Nicholas and Charles npm maintainer set", () => {
  const result = providerPreflight({
    candidate: "0.11.0",
    maintainers,
    distTags: { latest: "0.10.0" },
  });
  assert.deepEqual(result.maintainers, [...EXPECTED_MAINTAINERS]);
  assert.equal(result.latest, "0.10.0");
  assert.equal(result.nextBefore, null);
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/);
});

for (const unauthorized of [
  "goodnight00 <startsifting@gmail.com>",
  "unobtainiumrock_three <unobtainiumrock@proton.me>",
]) {
  test(`refuses additional provider maintainer ${unauthorized.split(" ")[0]}`, () => {
    assert.throws(
      () =>
        providerPreflight({
          candidate: "0.11.0",
          maintainers: [...maintainers, unauthorized],
          distTags: { latest: "0.10.0" },
        }),
      /npm maintainer authority differs/,
    );
  });
}

test("refuses a pre-existing next candidate distinct from latest", () => {
  assert.throws(
    () =>
      providerPreflight({
        candidate: "0.11.0",
        maintainers,
        distTags: { latest: "0.10.0", next: "0.10.1" },
      }),
    /in-flight candidate/,
  );
});

test("prepublish recheck refuses any owner or tag drift", () => {
  const before = providerPreflight({
    candidate: "0.11.0",
    maintainers,
    distTags: { latest: "0.10.0" },
  });
  assert.deepEqual(
    verifyImmediatePrepublish({
      before,
      candidate: "0.11.0",
      maintainers,
      distTags: { latest: "0.10.0" },
    }),
    before,
  );
  assert.throws(
    () =>
      verifyImmediatePrepublish({
        before,
        candidate: "0.11.0",
        maintainers,
        distTags: { latest: "0.10.1" },
      }),
    /provider state changed/,
  );
});

test("postpublish requires next to be the candidate while latest and owners remain unchanged", () => {
  const before = providerPreflight({
    candidate: "0.11.0",
    maintainers,
    distTags: { latest: "0.10.0" },
  });
  assert.deepEqual(
    verifyImmediatePostpublish({
      before,
      candidate: "0.11.0",
      maintainers,
      distTags: { latest: "0.10.0", next: "0.11.0" },
    }),
    {
      maintainers: [...EXPECTED_MAINTAINERS],
      latest: "0.10.0",
      next: "0.11.0",
    },
  );
  assert.throws(
    () =>
      verifyImmediatePostpublish({
        before,
        candidate: "0.11.0",
        maintainers,
        distTags: { latest: "0.10.1", next: "0.11.0" },
      }),
    /latest changed/,
  );
});
