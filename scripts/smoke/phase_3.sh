#!/usr/bin/env bash
# Phase 3 smoke, against the compose stack (make up):
#   1. Keycloak gives tokens to alice (acme) and bob (globex).
#   2. A request without a token gets 401 and a pointer to the sign-in metadata.
#   3. Alice lists acme's 15 tools and none of globex's.
#   4. Bob lists globex's 3 tools and none of acme's, and calling bank__get_balance by name gives
#      KS_TOOL_NOT_FOUND.
#   5. After calls that work, fail and are refused, the mail server says it received the API key
#      that Keystone added, and none of the demo keys, nor the master key, is in Keystone's logs.
set -u

cd "$(dirname "$0")/../.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"
COMPOSE="docker compose -f deploy/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"

export KEYSTONE_URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
BASE=${KEYSTONE_URL%/mcp}
MAIL_BASE="http://localhost:${MAIL_PORT:-8101}"
failed=0

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }

# Run the probe as one user through one agent, with a token of its own.
probe_as() {
  local user=$1 agent=$2 token
  shift 2
  token=$(bash scripts/get_token.sh "$user" "$agent") || { echo "cannot get a token for $user" >&2; return 2; }
  KEYSTONE_TOKEN=$token uv run python scripts/smoke/mcp_probe.py "$@"
}

# What a token says about its holder, read from its payload (it is not checked here).
describe() {
  python3 -c '
import base64, json, sys

payload = sys.argv[1].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
print("sub=%s tenant=%s azp=%s" % (claims["sub"], claims["tenant"], claims["azp"]))
' "$1"
}

step "1. tokens for alice and bob"
for pair in "alice support-agent" "bob support-agent"; do
  read -r user agent <<<"$pair"
  token=$(bash scripts/get_token.sh "$user" "$agent") || { fail "no token for $user"; continue; }
  echo "$user through $agent: $(describe "$token")"
done

step "2. no token, no entry"
reply=$(curl -s -i --max-time 10 -X POST "$KEYSTONE_URL" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}')
echo "$reply" | sed -n '1p;/^[Ww][Ww][Ww]-[Aa]uthenticate/p'
grep -q '^HTTP/1.1 401' <<<"$reply" || fail "a request without a token did not get 401"
grep -qi "^www-authenticate: Bearer resource_metadata=\"${BASE}/.well-known/oauth-protected-resource\"" <<<"$reply" \
  || fail "the 401 does not point at the sign-in metadata"
curl -fsS --max-time 10 "${BASE}/.well-known/oauth-protected-resource" || fail "no sign-in metadata"
echo

step "3. alice lists acme's tools"
alice_tools=$(probe_as alice support-agent list)
echo "$alice_tools" | sed -n '1p'
grep -qx 'tools: 15' <<<"$alice_tools" || fail "alice should see 15 tools"
for tool in bank__get_balance mail__read_email files__read_file echostd__echo; do
  grep -qx "$tool" <<<"$alice_tools" || fail "alice does not see $tool"
done
grep -q '^files_globex__' <<<"$alice_tools" && fail "alice sees a globex tool"

step "4. bob lists globex's tools and cannot call acme's"
bob_tools=$(probe_as bob support-agent list)
echo "$bob_tools"
grep -qx 'tools: 3' <<<"$bob_tools" || fail "bob should see 3 tools"
[ "$(grep -c '^files_globex__' <<<"$bob_tools")" -eq 3 ] || fail "bob should see the three globex tools"
grep -qE '^(bank|mail|echo|echostd|files)__' <<<"$bob_tools" && fail "bob sees an acme tool"
refused=$(probe_as bob support-agent call bank__get_balance '{"account": "CHK-001"}')
echo "$refused"
grep -q 'code=KS_TOOL_NOT_FOUND' <<<"$refused" || fail "bob's call to bank__get_balance was not KS_TOOL_NOT_FOUND"

step "5. the upstream got its key, and the logs hold none"
curl -fsS --max-time 10 -X POST "${MAIL_BASE}/_reset" >/dev/null || fail "cannot reset the mail server"
worked=$(probe_as alice support-agent call mail__list_emails '{"folder": "inbox"}')
failing=$(probe_as alice support-agent call echo__fail '{"message": "on purpose"}')
nothing=$(probe_as alice support-agent call echo__nothing '{}')
invalid=$(probe_as alice support-agent call echo__echo '{"payload": 7}')
echo "$worked" | sed -n '1p'; echo "$failing" | sed -n '1p'; echo "$nothing" | sed -n '1p'; echo "$invalid" | sed -n '1p'
grep -q '^error=false' <<<"$worked" || fail "alice's mail call did not work"
grep -q 'code=KS_TOOL_NOT_FOUND' <<<"$nothing" || fail "an unknown tool was not refused as not found"
grep -q 'code=KS_INVALID_ARGUMENTS' <<<"$invalid" || fail "invalid arguments were not refused"
state=$(curl -fsS --max-time 10 "${MAIL_BASE}/_state") || fail "cannot read the mail server's state"
grep -q '"api_key_received":[[:space:]]*true' <<<"$state" || fail "the mail server did not receive the API key"
echo "mail server: api_key_received=true"

logs=$($COMPOSE logs --no-color keystone 2>&1)
grep -q startup_sync <<<"$logs" || fail "the Keystone log is empty, so a search of it proves nothing"
hits=0
for name in MAIL_API_KEY FILES_API_KEY BANK_API_KEY ECHO_API_KEY FILES_GLOBEX_API_KEY KEYSTONE_MASTER_KEYS; do
  value=${!name:-}
  [ -n "$value" ] || { fail "$name is not set, so it cannot be searched for"; continue; }
  count=$(grep -cF -- "$value" <<<"$logs")
  hits=$((hits + count))
  echo "$name: $count occurrences in the Keystone container logs"
done
[ "$hits" -eq 0 ] || fail "$hits occurrences of a secret in the Keystone logs"

echo
if [ "$failed" -eq 0 ]; then
  echo "phase 3 smoke: ok (401 without a token, two tenants kept apart, no key in the logs)"
fi
[ "$failed" -eq 0 ]
