#!/usr/bin/env bash
# Break glass for the @sift-wiki/q publish lane.
#
# The `production` environment on this repo requires a reviewer other than the
# dispatcher for every run (two-person rule, can_admins_bypass=false). When no
# second reviewer is reachable and a release cannot wait, an admin can lift the
# reviewer requirement for ONE window and re-arm it afterwards. Every other
# control stays: main-only branch policy, the kill switch, the guard, OIDC,
# the SHA-pinned workflow behind reviewed pull requests. Only the second human
# is removed, only while the glass is open.
#
#   ops/break-glass.sh status      show the current reviewer rule
#   ops/break-glass.sh open REASON lift the reviewer rule (REASON is recorded)
#   ops/break-glass.sh close       restore the two production owners + no self-review
#
# Both mutations are GitHub-audit-logged under the caller's account. A closed
# glass is the default state; `close` is idempotent and safe to run any time.
set -euo pipefail

REPO="Sift-wiki/sift-q-release"
ENV_NAME="production"
# The canonical reviewer set. Keep in sync with README.md "Break glass". This
# is the authority boundary: `open` snapshots the live reviewer set for audit,
# but `close` always restores this owner-approved set. A stale or unauthorized
# live reviewer must never become release authority merely by appearing in a
# snapshot.
REVIEWERS=(Unobtainiumrock orange-juice-1024)
LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/sift-q-release"
SNAPSHOT="$LOG_DIR/reviewers.snapshot"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need gh; need python3

env_json() { gh api "repos/$REPO/environments/$ENV_NAME"; }

show() {
  env_json | python3 -c '
import json,sys
d=json.load(sys.stdin)
rr=[r for r in d.get("protection_rules",[]) if r["type"]=="required_reviewers"]
if rr:
    r=rr[0]
    print("glass:   CLOSED (reviewer rule present)")
    print("reviewers:", ", ".join(x["reviewer"]["login"] for x in r["reviewers"]))
    print("prevent_self_review:", r.get("prevent_self_review"))
else:
    print("glass:   OPEN  (no reviewer rule — re-arm with: ops/break-glass.sh close)")
print("can_admins_bypass:", d.get("can_admins_bypass"))
bp=d.get("deployment_branch_policy") or {}
print("branch policy:", "custom" if bp.get("custom_branch_policies") else bp)
'
  local live; live=$(live_reviewers)
  if [[ -n "$live" ]] && ! same_set "$live" "${REVIEWERS[*]}"; then
    echo "WARNING: live reviewers {$live} differ from this script's canonical list {${REVIEWERS[*]}}; update REVIEWERS and README.md." >&2
  fi
}

record() {
  mkdir -p "$LOG_DIR"
  printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(gh api user --jq .login)" "$1" "${2:-}" >>"$LOG_DIR/break-glass.log"
}

# Set equality in python: shell `sort` is locale-aware and case handling
# differs from python's sorted(), which bit the first version of `status`.
same_set() { python3 -c 'import sys; sys.exit(0 if set(sys.argv[1].split())==set(sys.argv[2].split()) else 1)' "$1" "$2"; }

live_reviewers() {
  env_json | python3 -c '
import json,sys
d=json.load(sys.stdin)
rr=[r for r in d.get("protection_rules",[]) if r["type"]=="required_reviewers"]
print(" ".join(sorted(x["reviewer"]["login"] for x in rr[0]["reviewers"])) if rr else "")'
}

# `close` always restores the canonical owner-approved set. The snapshot is
# evidence only; warn when it differs so authority drift remains visible.
restore_set() {
  RESTORE=("${REVIEWERS[@]}")
  if [[ -s "$SNAPSHOT" ]]; then
    local snapshot
    snapshot=$(<"$SNAPSHOT")
    if ! same_set "$snapshot" "${REVIEWERS[*]}"; then
      echo "WARNING: snapshot {$snapshot} differs from owner-approved reviewers {${REVIEWERS[*]}}; restoring only the owner-approved set." >&2
    fi
  fi
}

reviewer_payload() {
  local ids=() u
  for u in "${RESTORE[@]}"; do ids+=("{\"type\":\"User\",\"id\":$(gh api "users/$u" --jq .id)}"); done
  local joined; joined=$(IFS=,; echo "${ids[*]}")
  printf '{"prevent_self_review":true,"reviewers":[%s],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true},"can_admins_bypass":false}' "$joined"
}

open_glass() {
  local reason="${1:-}"
  [[ -n "$reason" ]] || { echo "open needs a REASON (it is recorded): ops/break-glass.sh open 'hotfix 0.10.1, orange-juice-1024 unreachable'" >&2; exit 2; }
  echo "Lifting the reviewer rule on $REPO/$ENV_NAME. Branch policy, kill switch, guard, and OIDC stay in force."
  # Snapshot the LIVE reviewer set so close restores what was actually there.
  mkdir -p "$LOG_DIR"
  local live; live=$(live_reviewers)
  if [[ -n "$live" ]]; then
    printf '%s\n' "$live" >"$SNAPSHOT"
    echo "snapshot of live reviewers: $live"
  else
    echo "note: no reviewer rule is present now; close will restore the canonical list."
  fi
  # GitHub's PUT only replaces the keys it receives: omitting `reviewers`
  # leaves the existing rule in place (verified in the first drill). An
  # explicit empty list is what removes it.
  gh api -X PUT "repos/$REPO/environments/$ENV_NAME" --input - >/dev/null <<'JSON'
{"reviewers":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true},"can_admins_bypass":false}
JSON
  # Fail loudly if the rule survived; a silent no-op is the worst outcome.
  if env_json | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(r["type"]=="required_reviewers" for r in d.get("protection_rules",[])) else 1)'; then
    echo "ERROR: the reviewer rule is still present after open; nothing was lifted." >&2
    record open-FAILED "$reason"
    exit 1
  fi
  record open "$reason"
  show
  echo
  echo "GLASS IS OPEN. Dispatch, publish, then run: ops/break-glass.sh close"
}

close_glass() {
  restore_set
  echo "Restoring reviewers (${RESTORE[*]}), prevent_self_review=true, can_admins_bypass=false."
  reviewer_payload | gh api -X PUT "repos/$REPO/environments/$ENV_NAME" --input - >/dev/null
  # Verify in one place (python), comparing as sets: shell `sort` is
  # locale-aware and would disagree with any other ordering.
  if ! env_json | WANT="${RESTORE[*]}" python3 -c '
import json,os,sys
d=json.load(sys.stdin)
rr=[r for r in d.get("protection_rules",[]) if r["type"]=="required_reviewers"]
ok = bool(rr) and rr[0].get("prevent_self_review") is True and d.get("can_admins_bypass") is False \
     and {x["reviewer"]["login"] for x in rr[0]["reviewers"]} == set(os.environ["WANT"].split())
sys.exit(0 if ok else 1)'; then
    echo "ERROR: after close the reviewer rule does not match {${RESTORE[*]}} + prevent_self_review + no admin bypass." >&2
    record close-FAILED
    exit 1
  fi
  rm -f "$SNAPSHOT"
  record close
  show
}

case "${1:-}" in
  status) show ;;
  open) open_glass "${2:-}" ;;
  close) close_glass ;;
  *) usage ;;
esac
