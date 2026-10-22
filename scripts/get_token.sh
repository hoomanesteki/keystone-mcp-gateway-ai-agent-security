#!/usr/bin/env bash
# Print an access token for a user of the local Keycloak realm, using the password grant.
# Development only: the clients that allow this grant exist for the demo and the smoke scripts.
#
#   scripts/get_token.sh <user> <client>
#   scripts/get_token.sh alice support-agent
#
# The password is read from <USER>_PASSWORD and the client secret from <CLIENT>_SECRET (dashes
# become underscores), taken from the environment, .env or .env.example in that order. The values
# go to curl on its standard input, so they never appear in a process list.
#
#   KEYCLOAK_URL   base address of Keycloak (default http://localhost:${KEYCLOAK_PORT:-8180})
#
# Exit codes: 0 a token was printed, 1 Keycloak refused or could not be reached, 2 usage.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"

if [ $# -ne 2 ]; then
  echo "usage: scripts/get_token.sh <user> <client>" >&2
  exit 2
fi
user=$1
client=$2
for value in "$user" "$client"; do
  [[ $value =~ ^[a-z][a-z0-9-]*$ ]] || { echo "invalid name: $value" >&2; exit 2; }
done

variable() { printf '%s_%s' "$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')" "$2"; }
password_variable=$(variable "$user" PASSWORD)
secret_variable=$(variable "$client" SECRET)
password=${!password_variable:-}
secret=${!secret_variable:-}
[ -n "$password" ] || { echo "no password for $user: set $password_variable" >&2; exit 2; }
[ -n "$secret" ] || { echo "no secret for $client: set $secret_variable" >&2; exit 2; }
for value in "$password" "$secret"; do
  case $value in
    *'"'* | *'\'* | *$'\n'*) echo "a password or secret holds a character this script cannot send" >&2; exit 2 ;;
  esac
done

base=${KEYCLOAK_URL:-http://localhost:${KEYCLOAK_PORT:-8180}}
response=$(curl -sS --max-time 15 -K - "${base}/realms/keystone/protocol/openid-connect/token" <<EOF
data-urlencode = "grant_type=password"
data-urlencode = "client_id=${client}"
data-urlencode = "client_secret=${secret}"
data-urlencode = "username=${user}"
data-urlencode = "password=${password}"
EOF
) || { echo "cannot reach Keycloak at ${base}" >&2; exit 1; }

printf '%s' "$response" | python3 -c '
import json
import sys

try:
    body = json.load(sys.stdin)
except ValueError:
    sys.exit("Keycloak sent an answer that is not JSON")
token = body.get("access_token")
if not token:
    sys.exit("no token: " + str(body.get("error_description") or body.get("error") or "unknown"))
print(token)
'
