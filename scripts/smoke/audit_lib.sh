# Read the audit log from a smoke script. Source it from the repository root:
#
#   . scripts/smoke/audit_lib.sh
#
#   audit_last_seq            the newest seq in the log, or 0 when it is empty
#   audit_added_since N       how many records have a seq above N (looks at the newest 200)
#   audit_wait_for_added N K [S]
#                             wait up to S seconds (default 10) until K records are above N: the
#                             writer batches for up to 50 ms, so a record follows its call by a moment
#   audit_entry CALL_ID       "<effect> <reasons, comma separated>" of one call's record, waiting
#                             for it the same way; "none" when the call made no decision
#
# They ask the admin API (GET /admin/api/v1/audit) as root, an admin of tenant acme, so they see
# the records of acme. KEYSTONE_URL names the MCP endpoint, as in the other smoke scripts.

AUDIT_BASE=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
AUDIT_BASE=${AUDIT_BASE%/mcp}
AUDIT_TOKEN=""
AUDIT_TOKEN_AT=-1000

# The JSON the admin API answers to GET <path>. A token lives five minutes; one is reused for four.
audit_api() {
  if [ -z "$AUDIT_TOKEN" ] || [ $((SECONDS - AUDIT_TOKEN_AT)) -gt 240 ]; then
    AUDIT_TOKEN=$(bash scripts/get_token.sh root keystone-cli) || return 1
    AUDIT_TOKEN_AT=$SECONDS
  fi
  curl -fsS --max-time 10 -H "Authorization: Bearer ${AUDIT_TOKEN}" "${AUDIT_BASE}/admin/api/v1$1"
}

audit_last_seq() {
  audit_api '/audit?limit=1' | python3 -c '
import json, sys

items = json.load(sys.stdin)["items"]
print(items[0]["seq"] if items else 0)
'
}

audit_added_since() {
  audit_api '/audit?limit=200' | python3 -c '
import json, sys

print(sum(1 for item in json.load(sys.stdin)["items"] if item["seq"] > int(sys.argv[1])))
' "$1"
}

audit_wait_for_added() {
  local after=$1 want=$2 deadline=$((SECONDS + ${3:-10})) have
  while :; do
    have=$(audit_added_since "$after") || return 1
    [ "$have" -ge "$want" ] && return 0
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}

audit_entry() {
  local call_id=$1 deadline=$((SECONDS + 10)) entry
  [[ $call_id =~ ^[0-9A-Z]{26}$ ]] || return 2
  while :; do
    entry=$(audit_api "/audit?call_id=${call_id}" | python3 -c '
import json, sys

items = json.load(sys.stdin)["items"]
if items:
    print(items[0]["effect"] or "none", ",".join(items[0]["reasons"]))
') || return 1
    if [ -n "$entry" ]; then
      echo "${entry% }"
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}
