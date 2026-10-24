#!/usr/bin/env bash
# Phase 2 smoke, against the compose stack (make up):
#   1. Keystone lists 20 tools: three each from mail, files, bank and echo over HTTP, one from the
#      web server (since Phase 7), three from the stdio echo upstream `echostd`, which Keystone
#      starts itself, the two of the sandbox (since Phase 8), and the two that Keystone offers every
#      caller (keystone__await_approval and keystone__whoami, since Phase 6).
#   2. The echo description changes upstream. After a registry sync the tool is quarantined,
#      hidden, and refused with KS_QUARANTINED; approve-change brings it back.
#   3. The bank server stops. Once Keystone has marked it down, a call to it fails at once.
#
# The health probes normally run every 30 s and need three failures, which is about 90 s. This
# script restarts Keystone with a probe every SMOKE_HEALTH_INTERVAL_S seconds (default 2), and
# puts the default back when it ends. It leaves the stack as it found it.
set -u

cd "$(dirname "$0")/../.."
COMPOSE="docker compose -f deploy/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"
[ -f .env ] && set -a && . ./.env && set +a

export KEYSTONE_URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
BASE=${KEYSTONE_URL%/mcp}
ECHO_BASE="http://localhost:${ECHO_PORT:-8104}"
INTERVAL=${SMOKE_HEALTH_INTERVAL_S:-2}
# Every probe signs in as olivia (an operator, through ops-agent) with a token of its own, because
# a token lives five minutes and this script runs for about one.
probe() {
  local token
  token=$(bash scripts/get_token.sh olivia ops-agent) || { echo "cannot get a token" >&2; return 2; }
  KEYSTONE_TOKEN=$token uv run python scripts/smoke/mcp_probe.py "$@"
}
failed=0
bank_stopped=0

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }
keystone() { $COMPOSE exec -T keystone keystone "$@"; }

# Poll a command until it succeeds, for at most $1 seconds.
wait_for() {
  local seconds=$1 deadline=$((SECONDS + $1))
  shift
  while ! "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 1
  done
}

upstream_status() {
  curl -fsS --max-time 5 "${BASE}/readyz" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['upstreams'].get('$1', ''))"
}
status_is() { [ "$(upstream_status "$1")" = "$2" ]; }
tool_count() { probe list | sed -n 's/^tools: //p'; }
has_tool() { probe list | grep -qx "$1"; }
lacks_tool() { ! has_tool "$1"; }

# Put the echo server and its pinned description back to the original, whatever state an earlier
# run left. A tool held for review is released with approve-change.
restore_echo() {
  curl -fsS --max-time 5 -X POST "${ECHO_BASE}/_reset" >/dev/null || return 1
  keystone registry sync --upstream echo >/dev/null 2>&1
  if keystone tool list --status quarantined 2>/dev/null | grep -q '^echo__echo '; then
    keystone tool approve-change echo__echo --note "smoke: restore" >/dev/null 2>&1
  fi
  wait_for 20 has_tool echo__echo
}

cleanup() {
  if [ "$bank_stopped" -eq 1 ]; then
    $COMPOSE start bank-mcp >/dev/null 2>&1
    wait_for 60 status_is bank up
  fi
  restore_echo
  # Back to the default probe interval.
  KEYSTONE_HEALTH_INTERVAL_S= $COMPOSE up -d --force-recreate --wait keystone >/dev/null 2>&1
}
trap cleanup EXIT

step "restart Keystone with a ${INTERVAL} s health probe"
KEYSTONE_HEALTH_INTERVAL_S=$INTERVAL $COMPOSE up -d --force-recreate --wait keystone >/dev/null \
  || { echo "cannot restart keystone. Is the stack up (make up)?" >&2; exit 1; }
wait_for 60 curl -fsS --max-time 5 "${BASE}/readyz" \
  || { echo "Keystone does not answer on ${BASE}" >&2; exit 1; }
restore_echo || { echo "cannot reach the echo server on ${ECHO_BASE}" >&2; exit 1; }

step "1. list the tools"
wait_for 60 status_is echostd up || fail "echostd is not up: $(upstream_status echostd)"
count=$(tool_count)
echo "tools: ${count}"
[ "$count" = "20" ] || fail "expected 20 tools, saw ${count}"
for tool in echostd__echo mail__send_email files__read_file bank__transfer echo__sleep; do
  has_tool "$tool" || fail "no ${tool} in the list"
done
out=$(probe call echostd__echo '{"payload": "over stdio"}')
echo "$out"
grep -q '^error=false' <<<"$out" || fail "echostd__echo did not answer"

step "2. a changed description is held"
curl -fsS --max-time 5 -X POST "${ECHO_BASE}/_mutate" >/dev/null || fail "cannot mutate the echo server"
sync_out=$(keystone registry sync --upstream echo)
echo "$sync_out"
grep -q 'changed: echo__echo (quarantined)' <<<"$sync_out" || fail "the sync did not quarantine echo__echo"
wait_for 20 lacks_tool echo__echo || fail "echo__echo is still in the list"
out=$(probe call echo__echo '{"payload": "x"}')
echo "$out"
grep -q 'code=KS_QUARANTINED' <<<"$out" || fail "a call to echo__echo was not refused with KS_QUARANTINED"
show=$(keystone tool show echo__echo)
grep -q '^ *+Also keeps a copy' <<<"$show" || fail "tool show does not print the diff"
fingerprint=$(sed -n 's/.*fingerprint \([0-9a-f]\{12\}\).*/\1/p' <<<"$show" | head -1)
keystone tool approve-change echo__echo --expect "$fingerprint" --note "smoke" \
  || fail "approve-change failed"
wait_for 20 has_tool echo__echo || fail "echo__echo did not come back after approve-change"
out=$(probe call echo__echo '{"payload": "x"}')
grep -q '^error=false' <<<"$out" || fail "echo__echo does not work after approve-change"

step "3. a stopped upstream fails fast"
$COMPOSE stop bank-mcp >/dev/null && bank_stopped=1
# Three failed probes, ${INTERVAL} s apart, plus a margin. The default settings need about 90 s.
wait_for $((INTERVAL * 3 + 30)) status_is bank down || fail "bank is '$(upstream_status bank)', not down"
# Three calls, and the fastest counts. The bound is about the refusal happening before any
# connection attempt, not about a cold cache: the first call after the stack has been busy pays
# for JWT, session and registry reads that the next ones find warm.
ms=99999
for _ in 1 2 3; do
  out=$(probe call bank__get_balance '{"account": "CHK-001"}')
  echo "$out"
  grep -q 'code=KS_UPSTREAM_ERROR' <<<"$out" || fail "the call to a down bank was not refused"
  grep -q 'upstream bank is down' <<<"$out" || fail "the refusal does not say the upstream is down"
  this=$(sed -n 's/.* ms=\([0-9.]*\).*/\1/p' <<<"$out" | head -1)
  ms=$(awk -v a="$ms" -v b="${this:-99999}" 'BEGIN { print (b < a) ? b : a }')
done
awk -v ms="$ms" 'BEGIN { exit !(ms < 50) }' || fail "the fastest refusal took ${ms} ms, not under 50"
mail=$(probe call mail__list_emails '{"folder": "inbox"}')
grep -q '^error=false' <<<"$mail" || fail "mail stopped working while bank was down"

echo
if [ "$failed" -eq 0 ]; then
  echo "phase 2 smoke: ok (20 tools, quarantine and approval, a down upstream refused in ${ms} ms)"
fi
[ "$failed" -eq 0 ]
