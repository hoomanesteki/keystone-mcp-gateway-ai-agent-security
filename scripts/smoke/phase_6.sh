#!/usr/bin/env bash
# Phase 6 smoke, against the compose stack (make up). The API only, no browser. The agents are
# olivia's (an operator, through ops-agent) and the approver is lena (the approver role, through
# keystone-cli), who decides through the admin API as the console would.
#   1. An agent starts a transfer of 900 in the background. Lena finds the request (tool, amount,
#      requester, reason approve-transfer-over-500), approves it, and the agent's transcript shows
#      the transfer completed. The bank holds it. A second decision on the request is a 409, and
#      olivia, who has no approver role, is refused with 403.
#   2. Another agent starts a transfer of 700. Lena rejects it with a note, and the agent's
#      transcript shows KS_APPROVAL_REJECTED and the note. The bank holds no second transfer.
#   3. A third agent starts a transfer of 600 and nobody decides: after the wait the agent is
#      told KS_APPROVAL_PENDING with an id. Lena then approves it, and the agent's await completes
#      the transfer.
#   4. The audit log has the transfers that ran, the rejection, the pending answer and the await
#      (decision source virtual), and the pending gauge matches what the API lists as pending.
#
# Keystone holds a call for approvals.wait_seconds (10 in deploy/keystone.compose.yaml), so step 3
# takes about that long. The bank is reset first. The requests of other runs that are still
# waiting are left alone: the script looks for the ones that appear after it starts an agent.
set -u

cd "$(dirname "$0")/../.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"

export KEYSTONE_URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
BASE=${KEYSTONE_URL%/mcp}
BANK_BASE="http://localhost:${BANK_PORT:-8103}"
SCRIPTS=examples/agents/scripts
WORK=$(mktemp -d)
failed=0
agent_pids=()

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }
cleanup() {
  for pid in "${agent_pids[@]:-}"; do kill "$pid" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# shellcheck source=scripts/smoke/audit_lib.sh
. scripts/smoke/audit_lib.sh
# shellcheck source=scripts/smoke/approvals_lib.sh
. scripts/smoke/approvals_lib.sh

OLIVIA_TOKEN=$(bash scripts/get_token.sh olivia ops-agent) \
  || { echo "cannot get a token for olivia. Is the stack up (make up)?" >&2; exit 1; }

# Run a script as olivia's agent in the background. Its transcript goes to $WORK/<name>.txt, its
# process id to AGENT_PID, and the requests already waiting to WAITING.
start_agent() {
  local name=$1 script=$2
  WAITING=$(approvals_pending_ids)
  KEYSTONE_TOKEN=$OLIVIA_TOKEN uv run python -m examples.agents.scripted_agent \
    --url "$KEYSTONE_URL" --script "${SCRIPTS}/${script}" --format text >"${WORK}/${name}.txt" 2>&1 &
  AGENT_PID=$!
  agent_pids+=("$AGENT_PID")
}

# Wait for an agent to end, at most $2 seconds, and leave its exit status in AGENT_STATUS. It runs in
# this shell and not in a command substitution, because `wait` only knows this shell's children.
agent_wait() {
  local pid=$1 deadline=$((SECONDS + $2))
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      kill "$pid" 2>/dev/null
      AGENT_STATUS="timed out"
      return 1
    fi
    sleep 0.5
  done
  wait "$pid"
  AGENT_STATUS=$?
}

bank_transfers() {
  curl -fsS --max-time 10 "${BANK_BASE}/_state" \
    | python3 -c 'import json,sys; print(",".join(str(t["amount"]) for t in json.load(sys.stdin)["transfers"]))'
}
status_of() { echo "${1%% *}"; }

curl -fsS --max-time 5 -X POST "${BANK_BASE}/_reset" >/dev/null \
  || { echo "cannot reset the bank on ${BANK_BASE}. Is the stack up (make up)?" >&2; exit 1; }
first_seq=$(audit_last_seq) || { echo "cannot read the audit log. Is the stack up (make up)?" >&2; exit 1; }

step "1. lena approves a transfer of 900 and the agent's call completes"
start_agent approve approval_demo.yaml
agent=$AGENT_PID
request=$(approvals_find 900 "$WAITING") || { fail "no request for 900 appeared"; request=""; }
if [ -n "$request" ]; then
  detail=$(approvals_api GET "/approvals/${request}")
  [ "$(status_of "$detail")" = 200 ] || fail "GET /approvals/{id} answered $(status_of "$detail")"
  echo "request ${request}: $(json_field "$detail" tool) $(json_field "$detail" arguments.amount)" \
    "by $(json_field "$detail" requested_by_user) through $(json_field "$detail" requested_by_agent)," \
    "reasons $(json_field "$detail" reasons), risk $(json_field "$detail" risk)"
  [ "$(json_field "$detail" reasons)" = "['approve-transfer-over-500']" ] || fail "the reason is not approve-transfer-over-500"
  [ "$(json_field "$detail" requested_by_user)" = olivia ] || fail "the requester is not olivia"
  [ "$(json_field "$detail" status)" = pending ] || fail "the request is not pending"

  # Olivia holds no approver role: the API refuses her decision.
  refused=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${OLIVIA_TOKEN}" -H 'Content-Type: application/json' \
    -d '{"approve": true}' "${BASE}/admin/api/v1/approvals/${request}/decision")
  echo "olivia deciding her own request: ${refused}"
  [ "$refused" = 403 ] || fail "olivia's decision answered ${refused}, not 403"

  decided=$(approvals_decide "$request" true "smoke: invoice 4471")
  echo "lena approves: $(status_of "$decided") $(json_field "$decided" status)"
  [ "$(status_of "$decided")" = 200 ] || fail "the approval answered $(status_of "$decided")"
  again=$(approvals_decide "$request" false "too late")
  echo "a second decision: $(status_of "$again")"
  [ "$(status_of "$again")" = 409 ] || fail "a second decision answered $(status_of "$again"), not 409"
fi
agent_wait "$agent" 60
cat "${WORK}/approve.txt"
[ "$AGENT_STATUS" = 0 ] || fail "the agent exited with ${AGENT_STATUS}"
grep -qE '^1\. ok   bank__transfer' "${WORK}/approve.txt" || fail "the agent's transfer did not succeed"
grep -q '"status": "completed"' "${WORK}/approve.txt" || fail "the transcript does not show the transfer completed"
transfers=$(bank_transfers)
echo "transfers at the bank: ${transfers}"
[ "$transfers" = "900.0" ] || fail "the bank holds '${transfers}', not 900.0"

step "2. lena rejects a transfer of 700 with a note"
start_agent reject approval_reject.yaml
agent=$AGENT_PID
request=$(approvals_find 700 "$WAITING") || { fail "no request for 700 appeared"; request=""; }
if [ -n "$request" ]; then
  decided=$(approvals_decide "$request" false "smoke: not this quarter")
  echo "lena rejects: $(status_of "$decided") $(json_field "$decided" status)"
  [ "$(status_of "$decided")" = 200 ] || fail "the rejection answered $(status_of "$decided")"
fi
agent_wait "$agent" 60
cat "${WORK}/reject.txt"
[ "$AGENT_STATUS" = 0 ] || fail "the agent exited with ${AGENT_STATUS}"
grep -q 'KS_APPROVAL_REJECTED' "${WORK}/reject.txt" || fail "the agent did not get KS_APPROVAL_REJECTED"
grep -q 'not this quarter' "${WORK}/reject.txt" || fail "the agent did not get the note"
transfers=$(bank_transfers)
echo "transfers at the bank: ${transfers}"
[ "$transfers" = "900.0" ] || fail "the bank holds '${transfers}', not just 900.0"

step "3. a request nobody decides is pending, and lena approves it later"
before_pending=$(audit_last_seq)
start_agent pending approval_pending.yaml
agent=$AGENT_PID
request=$(approvals_find 600 "$WAITING") || { fail "no request for 600 appeared"; request=""; }
# The agent is told KS_APPROVAL_PENDING when its wait ends, and the audit log has the record then.
told=""
for _ in $(seq 1 60); do
  told=$(audit_api '/audit?tool=bank__transfer&limit=20' | python3 -c '
import json, sys

seq = int(sys.argv[1])
for item in json.load(sys.stdin)["items"]:
    if item["seq"] > seq and item["reject_code"] == "KS_APPROVAL_PENDING":
        print(item["seq"])
        break
' "$before_pending")
  [ -n "$told" ] && break
  sleep 1
done
[ -n "$told" ] || fail "the audit log has no KS_APPROVAL_PENDING after the wait"
echo "the agent was told KS_APPROVAL_PENDING (audit record ${told})"
if [ -n "$request" ]; then
  still=$(approvals_api GET "/approvals/${request}")
  [ "$(json_field "$still" status)" = pending ] || fail "the request is not still pending"
  decided=$(approvals_decide "$request" true "smoke: approved late")
  echo "lena approves: $(status_of "$decided") $(json_field "$decided" status)"
  [ "$(status_of "$decided")" = 200 ] || fail "the late approval answered $(status_of "$decided")"
fi
agent_wait "$agent" 90
cat "${WORK}/pending.txt"
[ "$AGENT_STATUS" = 0 ] || fail "the agent exited with ${AGENT_STATUS}"
grep -q 'KS_APPROVAL_PENDING' "${WORK}/pending.txt" || fail "the transcript does not show KS_APPROVAL_PENDING"
grep -qE '^2\. ok   keystone__await_approval' "${WORK}/pending.txt" || fail "the await did not succeed"
grep -q '"status": "completed"' "${WORK}/pending.txt" || fail "the await did not return the transfer"
transfers=$(bank_transfers)
echo "transfers at the bank: ${transfers}"
[ "$transfers" = "900.0,600.0" ] || fail "the bank holds '${transfers}', not 900.0,600.0"

step "4. the audit log and the gauge"
audit_wait_for_added "$first_seq" 5 15
summary=$(audit_api '/audit?limit=200' | python3 -c '
import json, sys

seq = int(sys.argv[1])
rows = [i for i in json.load(sys.stdin)["items"] if i["seq"] > seq]
transfers = [i for i in rows if i["tool_name"] == "bank__transfer"]
awaits = [i for i in rows if i["tool_name"] == "keystone__await_approval"]
ran = [i for i in transfers if i["outcome"] == "ok" and i["dispatched"]]
print(
    "ran=%d effect=%s rejected=%d pending=%d awaits_virtual=%s"
    % (
        len(ran),
        ",".join(sorted({i["effect"] for i in ran})),
        sum(1 for i in transfers if i["reject_code"] == "KS_APPROVAL_REJECTED"),
        sum(1 for i in transfers if i["reject_code"] == "KS_APPROVAL_PENDING"),
        bool(awaits) and all(i["decision_source"] == "virtual" and i["effect"] == "allow" for i in awaits),
    )
)
' "$first_seq")
echo "$summary"
[ "$summary" = "ran=2 effect=require_approval rejected=1 pending=1 awaits_virtual=True" ] \
  || fail "the audit log shows '${summary}'"
# The gauge counts what the API lists as pending. Requests of earlier runs may still be waiting (they
# expire after 15 minutes), so the two are compared, and a fresh stack makes both 0.
gauge=$(curl -fsS --max-time 10 "${BASE}/metrics" | sed -n 's/^keystone_approvals_pending{tenant="acme"} //p')
waiting=$(approvals_pending_ids | wc -w | tr -d ' ')
echo "keystone_approvals_pending{tenant=acme}: ${gauge}, pending in the API: ${waiting}"
[ "${gauge%.*}" = "$waiting" ] || fail "the pending gauge reads '${gauge}', the API lists ${waiting}"

echo
if [ "$failed" -eq 0 ]; then
  echo "phase 6 smoke: ok (900 approved and completed, 700 rejected with its note, 600 pending then approved and awaited, 409 on a second decision, 403 for a non-approver)"
fi
[ "$failed" -eq 0 ]
