# Play the approver from a smoke script. Source it from the repository root:
#
#   . scripts/smoke/approvals_lib.sh
#
#   approvals_api METHOD PATH [JSON]
#                           call the admin API as lena and print "<http status> <body>"
#   approvals_pending_ids   the ids of the requests waiting now, space separated
#   approvals_find AMOUNT [SKIP]
#                           the id of a pending request for a bank__transfer of this amount that is
#                           not among the ids in SKIP (what approvals_pending_ids printed before the
#                           agent started), waiting up to 30 s for it to appear; fails when none does
#   approvals_decide ID true|false NOTE
#                           approve (true) or reject (false) a request as lena: "<status> <body>"
#   json_field "<status> <body>" a.b.c
#                           the value at that path in the body of an answer of approvals_api
#
# Lena is a user of the local realm with the approver role (not an admin). Her token comes from
# scripts/get_token.sh through keystone-cli. KEYSTONE_URL names the MCP endpoint, as in the other
# smoke scripts.

APPROVALS_BASE=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
APPROVALS_BASE=${APPROVALS_BASE%/mcp}
APPROVER_TOKEN=""
APPROVER_TOKEN_AT=-1000

approver_token() {
  # A token lives five minutes; one is reused for four.
  if [ -z "$APPROVER_TOKEN" ] || [ $((SECONDS - APPROVER_TOKEN_AT)) -gt 240 ]; then
    APPROVER_TOKEN=$(bash scripts/get_token.sh lena keystone-cli) || return 1
    APPROVER_TOKEN_AT=$SECONDS
  fi
}

approvals_api() {
  local method=$1 path=$2 body=${3:-} out status
  approver_token || { echo "000 cannot get a token for lena"; return 1; }
  out=$(mktemp)
  if [ -n "$body" ]; then
    status=$(curl -sS --max-time 20 -o "$out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer ${APPROVER_TOKEN}" -H 'Content-Type: application/json' \
      -d "$body" "${APPROVALS_BASE}/admin/api/v1${path}")
  else
    status=$(curl -sS --max-time 20 -o "$out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer ${APPROVER_TOKEN}" "${APPROVALS_BASE}/admin/api/v1${path}")
  fi
  echo "${status} $(cat "$out")"
  rm -f "$out"
}

approvals_pending_ids() {
  local found
  found=$(approvals_api GET '/approvals?status=pending')
  python3 -c '
import json, sys

status, _, body = sys.argv[1].partition(" ")
print(" ".join(item["id"] for item in json.loads(body)) if status == "200" else "")
' "$found"
}

approvals_find() {
  local amount=$1 skip=${2:-} deadline=$((SECONDS + 30)) found id
  while :; do
    found=$(approvals_api GET '/approvals?status=pending')
    id=$(python3 -c '
import json, sys

status, _, body = sys.argv[1].partition(" ")
skip = set(sys.argv[3].split())
if status == "200":
    for item in json.loads(body):
        if (
            item["tool"] == "bank__transfer"
            and item["arguments"].get("amount") == float(sys.argv[2])
            and item["id"] not in skip
        ):
            print(item["id"])
            break
' "$found" "$amount" "$skip")
    if [ -n "$id" ]; then
      echo "$id"
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.5
  done
}

approvals_decide() {
  local id=$1 approve=$2 note=$3
  approvals_api POST "/approvals/${id}/decision" \
    "$(python3 -c 'import json,sys; print(json.dumps({"approve": sys.argv[1] == "true", "note": sys.argv[2]}))' "$approve" "$note")"
}

json_field() {
  python3 -c '
import json, sys

value = json.loads(sys.argv[1].partition(" ")[2])
for key in sys.argv[2].split("."):
    value = value[key]
print(value)
' "$1" "$2"
}
