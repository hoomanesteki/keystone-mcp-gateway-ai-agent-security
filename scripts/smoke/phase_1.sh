#!/usr/bin/env bash
# Phase 1 smoke, and the body of `make demo`: reset the demo upstreams, run the scripted agent
# through Keystone, print its transcript and check that every step passed and that the audit
# log holds one record per tool call.
#
#   KEYSTONE_URL    MCP endpoint (default http://localhost:8080/mcp)
#   KEYSTONE_TOKEN  bearer token, read by the agent. Default: olivia, an operator, through
#                   ops-agent, because the script sends mail and reads a balance (KS-304)
set -u

cd "$(dirname "$0")/../.."
[ -f .env ] && set -a && . ./.env && set +a

URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
SCRIPT=examples/agents/scripts/demo_p1.yaml
failed=0

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }

if [ -z "${KEYSTONE_TOKEN:-}" ]; then
  KEYSTONE_TOKEN=$(bash scripts/get_token.sh olivia ops-agent) \
    || { echo "cannot get a token for olivia. Is the stack up (make up)?" >&2; exit 1; }
  export KEYSTONE_TOKEN
fi

for port in "${MAIL_PORT:-8101}" "${FILES_PORT:-8102}" "${BANK_PORT:-8103}" "${ECHO_PORT:-8104}"; do
  curl -fsS --max-time 5 -X POST "http://localhost:${port}/_reset" >/dev/null \
    || { echo "cannot reset the upstream on :${port}. Is the stack up (make up)?" >&2; exit 1; }
done

# The audit log holds every call since the database was created, so count what is new.
# shellcheck source=scripts/smoke/audit_lib.sh
. scripts/smoke/audit_lib.sh
before=$(audit_last_seq) || { echo "cannot read the audit log. Is the stack up (make up)?" >&2; exit 1; }

transcript=$(uv run python -m examples.agents.scripted_agent \
  --url "$URL" --script "$SCRIPT" --format text 2>&1)
agent_status=$?
echo "$transcript"

calls=$(grep -cE '^[0-9]+\. ok   [a-z_]+__' <<<"$transcript")
steps=$(grep -cE '^[0-9]+\. ok  ' <<<"$transcript")
audit_wait_for_added "$before" "$calls" 10
audited=$(audit_added_since "$before") || { echo "cannot read the audit log" >&2; exit 1; }

[ "$agent_status" -eq 0 ] || fail "the scripted agent exited with ${agent_status}"
grep -qE '^[0-9]+\. FAIL' <<<"$transcript" && fail "a step failed"
[ "$steps" -eq 4 ] || fail "expected 4 successful steps, saw ${steps}"
for tool in bank__get_balance mail__send_email mail__read_email; do
  grep -qE "^[0-9]+\. ok   ${tool} " <<<"$transcript" || fail "no successful ${tool}"
done
[ "$calls" -eq 3 ] || fail "expected 3 successful tool calls, saw ${calls}"
[ "$audited" -eq "$calls" ] || fail "audit holds ${audited} new records for ${calls} calls"

echo
echo "audit records added: ${audited}, tool calls made: ${calls}, steps ok: ${steps} of 4"
[ "$failed" -eq 0 ]
