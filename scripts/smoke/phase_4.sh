#!/usr/bin/env bash
# Phase 4 smoke, against the compose stack (make up):
#   1. Alice (support) asks for a transfer: KS_DENIED, reason default-deny. Her tool list has 15
#      tools: 13 of acme's (the two high-risk ones are hidden from her) and the 2 that Keystone
#      offers every caller.
#   2. Olivia (an operator) transfers 900: the audit shows require_approval with the reason
#      approve-transfer-over-500. Nobody decides, so the call is held for approvals.wait_seconds
#      (10 s here) and then answered KS_APPROVAL_PENDING with an id, and nothing moves. (Before
#      Phase 6 the approval stub refused it with KS_DENIED at once.)
#   3. Olivia transfers 100: it is dispatched.
#   4. A policy file is broken on the host and reloaded as root: 422, and the version in force does
#      not change. The file is put back and a reload succeeds with the same version.
#
# The compose stack mounts ./policies into the Keystone container, so an edit on the host is what
# Keystone reads. The script puts the file back however it ends.
set -u

cd "$(dirname "$0")/../.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"

export KEYSTONE_URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
BASE=${KEYSTONE_URL%/mcp}
BANK_BASE="http://localhost:${BANK_PORT:-8103}"
POLICY_FILE=policies/default/access/base.cedar
BACKUP=$(mktemp)
failed=0

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }

cp "$POLICY_FILE" "$BACKUP"
restore() { cp "$BACKUP" "$POLICY_FILE"; rm -f "$BACKUP"; }
trap restore EXIT

# Run the probe as one user through one agent, with a token of its own.
probe_as() {
  local user=$1 agent=$2 token
  shift 2
  token=$(bash scripts/get_token.sh "$user" "$agent") || { echo "cannot get a token for $user" >&2; return 2; }
  KEYSTONE_TOKEN=$token uv run python scripts/smoke/mcp_probe.py "$@"
}

# audit_entry CALL_ID prints the record of a call as `effect reasons` (scripts/smoke/audit_lib.sh).
# shellcheck source=scripts/smoke/audit_lib.sh
. scripts/smoke/audit_lib.sh

call_id_of() { sed -n 's/.* call_id=\([0-9A-Z]\{26\}\).*/\1/p' <<<"$1" | head -1; }

# POST the reload as root. Prints the status, then the body, then the version in force.
ADMIN_TOKEN=$(bash scripts/get_token.sh root keystone-cli) \
  || { echo "cannot get a token for root. Is the stack up (make up)?" >&2; exit 1; }
reload() {
  local body status
  body=$(mktemp)
  status=$(curl -sS --max-time 30 -o "$body" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE}/admin/api/v1/policies/reload")
  echo "$status $(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))))' "$body")"
  rm -f "$body"
}
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1].split(" ", 1)[1])[sys.argv[2]])' "$1" "$2"; }
status_of() { echo "${1%% *}"; }

curl -fsS --max-time 5 -X POST "${BANK_BASE}/_reset" >/dev/null \
  || { echo "cannot reset the bank server on ${BANK_BASE}. Is the stack up (make up)?" >&2; exit 1; }
SMALL='{"from_account": "CHK-001", "to": "SAV-002", "amount": 100}'
BIG='{"from_account": "CHK-001", "to": "SAV-002", "amount": 900}'

step "1. alice cannot transfer"
refused=$(probe_as alice support-agent call bank__transfer "$SMALL")
echo "$refused"
grep -q 'code=KS_DENIED' <<<"$refused" || fail "alice's transfer was not KS_DENIED"
grep -q 'denied by policy: default-deny' <<<"$refused" || fail "the reason is not default-deny"
entry=$(audit_entry "$(call_id_of "$refused")")
echo "audit: $entry"
[ "$entry" = "deny default-deny" ] || fail "the audit shows '$entry', not 'deny default-deny'"
alice_tools=$(probe_as alice support-agent list)
echo "$alice_tools" | sed -n '1p'
grep -qx 'tools: 15' <<<"$alice_tools" || fail "alice should see 15 tools"
grep -qxE 'bank__transfer|mail__send_email' <<<"$alice_tools" && fail "alice sees a high-risk tool"

step "2. olivia transfers 900 and the audit asks for approval"
asked=$(probe_as olivia ops-agent call bank__transfer "$BIG")
echo "$asked"
entry=$(audit_entry "$(call_id_of "$asked")")
echo "audit: $entry"
[ "$entry" = "require_approval approve-transfer-over-500" ] \
  || fail "the audit shows '$entry', not 'require_approval approve-transfer-over-500'"
grep -q 'code=KS_APPROVAL_PENDING' <<<"$asked" || fail "the held transfer was not answered KS_APPROVAL_PENDING"

step "3. olivia transfers 100"
sent=$(probe_as olivia ops-agent call bank__transfer "$SMALL")
echo "$sent"
grep -q '^error=false' <<<"$sent" || fail "olivia's transfer of 100 was not dispatched"
entry=$(audit_entry "$(call_id_of "$sent")")
echo "audit: $entry"
[ "$entry" = "allow operators-high" ] || fail "the audit shows '$entry', not 'allow operators-high'"
transfers=$(curl -fsS --max-time 10 "${BANK_BASE}/_state" \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["transfers"]))')
echo "transfers at the bank: $transfers"
[ "$transfers" = "1" ] || fail "the bank holds $transfers transfers, not 1"

step "4. a broken policy is refused and the version stays"
settled=$(reload)
echo "reload: $settled"
[ "$(status_of "$settled")" = 200 ] || fail "a reload of the untouched files did not give 200"
version=$(field "$settled" version)

printf '\npermit (principal, action\n' >>"$POLICY_FILE"
# Docker Desktop shows a host edit to the container within a moment; ask until it does.
refused_reload=""
for _ in $(seq 1 20); do
  refused_reload=$(reload)
  [ "$(status_of "$refused_reload")" = 422 ] && break
  sleep 0.5
done
echo "reload: $(echo "$refused_reload" | cut -c1-200)"
[ "$(status_of "$refused_reload")" = 422 ] || fail "a broken file did not give 422"
[ "$(field "$refused_reload" version)" = "$version" ] || fail "the version in force changed"
via_cli=$(KEYSTONE_ADMIN_TOKEN=$ADMIN_TOKEN uv run keystone policy reload --url "$BASE" 2>&1)
cli_status=$?
echo "$via_cli"
[ "$cli_status" -eq 1 ] || fail "keystone policy reload exited $cli_status, not 1"
grep -q 'stays in force' <<<"$via_cli" || fail "the CLI did not say the old set stays in force"
still=$(probe_as alice support-agent call bank__transfer "$SMALL")
grep -q 'denied by policy: default-deny' <<<"$still" || fail "the old rules are not in force"

cp "$BACKUP" "$POLICY_FILE"
restored=""
for _ in $(seq 1 20); do
  restored=$(reload)
  [ "$(status_of "$restored")" = 200 ] && break
  sleep 0.5
done
echo "reload: $restored"
[ "$(status_of "$restored")" = 200 ] || fail "the restored file was not accepted"
[ "$(field "$restored" version)" = "$version" ] || fail "the restored file has another version"

echo
if [ "$failed" -eq 0 ]; then
  echo "phase 4 smoke: ok (alice denied by default-deny, 900 asks for approval, 100 goes through, a broken policy is refused with version ${version:0:12} kept)"
fi
[ "$failed" -eq 0 ]
