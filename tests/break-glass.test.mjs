// Pins the two defects the first drills of ops/break-glass.sh exposed, so they
// cannot come back: (1) `open` must send an explicit empty reviewers list —
// GitHub's PUT only replaces the keys it receives, so omitting `reviewers`
// silently leaves the rule in place; (2) both directions must verify the live
// state afterwards and fail loudly, never report success from the request.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const sh = readFileSync(
  new URL("../ops/break-glass.sh", import.meta.url),
  "utf8",
);
const fn = (name) =>
  sh.slice(
    sh.indexOf(`${name}() {`),
    sh.indexOf("\n}\n", sh.indexOf(`${name}() {`)),
  );

test("open sends an explicit empty reviewers list (a silent no-op otherwise)", () => {
  assert.match(fn("open_glass"), /"reviewers":\[\]/);
});

test("open verifies the rule is gone and fails loudly if not", () => {
  const f = fn("open_glass");
  assert.match(f, /required_reviewers/);
  assert.match(f, /ERROR: the reviewer rule is still present/);
  assert.match(f, /record open-FAILED/);
});

test("the canonical reviewer list and README contain only the two production owners", () => {
  assert.match(sh, /REVIEWERS=\(Unobtainiumrock orange-juice-1024\)/);
  assert.doesNotMatch(sh, /goodnight000|siftwiki/);
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  assert.match(readme, /Unobtainiumrock.*orange-juice-1024/s);
  assert.match(
    readme,
    /Tianjun\n\s+\(`goodnight000`\) may review code, but production and npm runtime authority is\n\s+restricted to Nicholas and Charles/,
  );
});

test("open snapshots live reviewers for evidence but close restores only the canonical owners", () => {
  assert.match(fn("open_glass"), /live=\$\(live_reviewers\)/);
  assert.match(fn("open_glass"), />"\$SNAPSHOT"/);
  const r = fn("restore_set");
  assert.match(r, /RESTORE=\("\$\{REVIEWERS\[@\]\}"\)/);
  assert.doesNotMatch(r, /read -r -a RESTORE/);
  assert.match(r, /restoring only the owner-approved set/);
  const c = fn("close_glass");
  assert.match(c, /^\s*restore_set$/m);
  assert.match(c, /WANT="\$\{RESTORE\[\*\]\}"/);
  assert.doesNotMatch(
    c,
    /REVIEWERS\[/,
    "close reads the canonical set through restore_set",
  );
  assert.match(fn("reviewer_payload"), /"\$\{RESTORE\[@\]\}"/);
});

test("close restores the reviewers with no self-review and no admin bypass, and verifies it", () => {
  const p = fn("reviewer_payload");
  assert.match(p, /"prevent_self_review":true/);
  assert.match(p, /"can_admins_bypass":false/);
  const c = fn("close_glass");
  assert.match(c, /prevent_self_review"\) is True/);
  assert.match(c, /can_admins_bypass"\) is False/);
  assert.match(c, /record close-FAILED/);
});

test("neither direction touches the main-only branch policy or enables admin bypass", () => {
  for (const name of ["open_glass", "reviewer_payload"]) {
    assert.match(fn(name), /"custom_branch_policies":true/);
    assert.match(fn(name), /"can_admins_bypass":false/);
  }
  assert.doesNotMatch(sh, /can_admins_bypass":\s*true/);
  assert.doesNotMatch(
    sh,
    /deployment-branch-policies/,
    "the script never edits branch policies",
  );
});

test("open requires a recorded reason", () => {
  assert.match(fn("open_glass"), /open needs a REASON/);
  assert.match(fn("open_glass"), /record open "\$reason"/);
});
