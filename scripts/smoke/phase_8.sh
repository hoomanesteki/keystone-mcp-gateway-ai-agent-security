#!/usr/bin/env bash
# Phase 8 smoke, against the compose stack (make up). The model is the fake one (the compose
# service fake-llm, examples/fake_llm), so no key and no network are needed. A request with a prompt
# of four words and a reply of twelve costs $0.000192 at the fake prices.
#   1. The sandbox: olivia (an operator) runs Python and gets 42 back; alice (support) is refused
#      with default-deny and does not see the tools.
#   2. Budgets: lena has three cents a day and echostd__echo costs a cent. Her fourth call is
#      KS_BUDGET_EXCEEDED, the console's API shows $0.03 of $0.03, and the ledger has three rows.
#   3. The LLM proxy, as olivia: a whole Anthropic answer is booked at 4 tokens in, 12 out and
#      $0.000192; a stream reaches the caller byte for byte as the fake sends it and is booked the
#      same; an OpenAI stream is asked to report its usage; a model with no price is a 400 and the
#      fake sees nothing; lena, whose day is spent, is refused with 402 before the fake sees the
#      request; a provider that repeats the key it was given is answered with it taken out, and the
#      key is in no response, no Keystone log and no span. keystone_llm_tokens_total counts the tokens.
#   4. Rate limits: Keystone is restarted with a burst of 5 calls for one user, olivia makes 12
#      calls in one session, 5 pass and the rest are KS_RATE_LIMITED with a retry_after_s, and
#      after that long a call passes again.
#
# It clears the day's spend of the demo tenant first (the ledger rows, the counters in Redis and
# the buckets), so that it can run twice in a day. That is a statement on the development database
# as its owner; the application's own role cannot delete from the ledger. When it ends, Keystone is
# restarted with the default limits, whatever happened. Run it with `make up` first.
set -u

cd "$(dirname "$0")/../.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"
COMPOSE="docker compose -f deploy/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"

export KEYSTONE_URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
BASE=${KEYSTONE_URL%/mcp}
FAKE="http://localhost:${FAKE_LLM_PORT:-8199}"
JAEGER="http://localhost:${JAEGER_UI_PORT:-16686}"
BURST=5
REFILL=0.5
WORK=$(mktemp -d)
failed=0
restarted=0

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }
sql() { $COMPOSE exec -T postgres psql -U keystone -d keystone -At -c "$1"; }
token() { bash scripts/get_token.sh "$1" "$2"; }
probe() {
  local user=$1 agent=$2 bearer
  shift 2
  bearer=$(bash scripts/get_token.sh "$user" "$agent") || { echo "cannot get a token for ${user}" >&2; return 2; }
  KEYSTONE_TOKEN=$bearer uv run python scripts/smoke/mcp_probe.py "$@"
}
wait_for() {
  local seconds=$1 deadline=$((SECONDS + $1))
  shift
  while ! "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 1
  done
}
# Forget the day's spend and the rate limit buckets, in Postgres and in Redis.
clear_spend() {
  sql "DELETE FROM spend_ledger WHERE tenant_id = 'acme'" >/dev/null || return 1
  $COMPOSE exec -T redis sh -c \
    "for p in 'ks:spend:*' 'ks:rl:*'; do redis-cli --scan --pattern \"\$p\" | xargs -r redis-cli del >/dev/null; done"
}
cleanup() {
  rm -rf "$WORK"
  if [ "$restarted" -eq 1 ]; then
    KEYSTONE_RATE_LIMIT_USER_CAPACITY= KEYSTONE_RATE_LIMIT_USER_REFILL= \
      $COMPOSE up -d --force-recreate --wait keystone >/dev/null 2>&1
    clear_spend >/dev/null 2>&1
  fi
}
trap cleanup EXIT

# shellcheck source=scripts/smoke/audit_lib.sh
. scripts/smoke/audit_lib.sh

FAKE_KEY=${FAKE_LLM_API_KEY:-}
[ -n "$FAKE_KEY" ] || { echo "FAKE_LLM_API_KEY is not set (see .env.example)" >&2; exit 1; }
curl -fsS --max-time 5 "${FAKE}/healthz" >/dev/null \
  || { echo "the fake model API does not answer on ${FAKE}. Is the stack up (make up)?" >&2; exit 1; }
clear_spend || { echo "cannot clear the spend. Is the stack up (make up)?" >&2; exit 1; }
curl -fsS --max-time 5 -X POST "${FAKE}/_reset" >/dev/null

# One request to the proxy. Prints the HTTP status; the body is in $out, the headers in $out.headers.
llm() {
  local token=$1 path=$2 data=$3 out=$4
  shift 4
  curl -sS --max-time 60 -o "$out" -D "${out}.headers" -w '%{http_code}' "$@" \
    -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
    -d "$data" "${BASE}${path}"
}
request_id() { grep -i '^x-keystone-request-id:' "$1.headers" | tr -d '\r' | awk '{print $2}'; }
ledger_row() { sql "SELECT model, input_tokens, output_tokens, cost_usd FROM spend_ledger WHERE kind = 'llm' AND ref = '$1'"; }
fake_requests() { curl -fsS --max-time 5 "${FAKE}/_state" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["requests"]))'; }
fake_last_body() { curl -fsS --max-time 5 "${FAKE}/_state" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["requests"][-1]["body"]))'; }
json_at() {  # json_at FILE a.b.c
  python3 -c '
import json, sys
value = json.load(open(sys.argv[1]))
for part in sys.argv[2].split("."):
    value = value[int(part)] if part.isdigit() else value[part]
print(value)
' "$1" "$2"
}
token_count() {  # token_count DIRECTION MODEL
  curl -fsS --max-time 10 "${BASE}/metrics" \
    | awk -v d="$1" -v m="$2" '$0 ~ "^keystone_llm_tokens_total\\{" && $0 ~ "direction=\"" d "\"" && $0 ~ "model=\"" m "\"" { print $2 }' \
    | head -1
}
PROMPT='hello there general kenobi'
ANTHROPIC_BODY="{\"model\": \"fake-model\", \"max_tokens\": 16, \"messages\": [{\"role\": \"user\", \"content\": \"${PROMPT}\"}]}"
ANTHROPIC_STREAM_BODY="{\"model\": \"fake-model\", \"max_tokens\": 16, \"stream\": true, \"messages\": [{\"role\": \"user\", \"content\": \"${PROMPT}\"}]}"
OPENAI_STREAM_BODY="{\"model\": \"fake-model\", \"max_tokens\": 16, \"stream\": true, \"messages\": [{\"role\": \"user\", \"content\": \"${PROMPT}\"}]}"

step "1. the sandbox"
out=$(probe olivia ops-agent call sandbox__run_python '{"code": "print(6 * 7)"}')
echo "olivia: ${out}"
grep -q '^error=false' <<<"$out" || fail "olivia's script did not run"
grep -q '"stdout": "42\\n"' <<<"$out" || fail "the script did not print 42"
out=$(probe alice support-agent call sandbox__run_python '{"code": "print(6 * 7)"}')
echo "alice: ${out}"
grep -q 'code=KS_DENIED' <<<"$out" || fail "alice's call was not KS_DENIED"
grep -q 'default-deny' <<<"$out" || fail "the refusal does not name default-deny"
if probe alice support-agent list | grep -q '^sandbox__'; then fail "alice sees the sandbox tools"; fi

step "2. a budget stops lena's fourth call"
for n in 1 2 3; do
  out=$(probe lena ops-agent call echostd__echo '{"payload": "budget"}')
  grep -q '^error=false' <<<"$out" || fail "lena's call ${n} was refused: ${out}"
done
out=$(probe lena ops-agent call echostd__echo '{"payload": "budget"}')
echo "the fourth: ${out}"
grep -q 'code=KS_BUDGET_EXCEEDED' <<<"$out" || fail "lena's fourth call was not KS_BUDGET_EXCEEDED"
grep -q 'budget of \$0.03 a day' <<<"$out" || fail "the refusal does not say the budget"
budgets=$(audit_api '/budgets')
echo "$budgets" | python3 -c '
import json, sys

lena = [b for b in json.load(sys.stdin) if b["scope"] == "user" and b["scope_id"] == "lena"][0]
print("lena: spent %s of %s, resets %s" % (lena["spent_usd"], lena["limit_usd"], lena["resets_at"]))
assert float(lena["spent_usd"]) == 0.03 and float(lena["limit_usd"]) == 0.03, lena
' || fail "the budgets API does not show \$0.03 of \$0.03 for lena"
rows=$(sql "SELECT count(*) FROM spend_ledger WHERE kind = 'tool' AND user_id = 'lena'")
echo "ledger rows for lena's tool calls: ${rows}"
[ "$rows" = 3 ] || fail "the ledger has ${rows} tool rows for lena, not 3"

step "3. the LLM proxy"
OLIVIA=$(token olivia ops-agent) || { echo "cannot get a token for olivia" >&2; exit 1; }
LENA=$(token lena ops-agent) || { echo "cannot get a token for lena" >&2; exit 1; }
input_before=$(token_count input fake-model)
output_before=$(token_count output fake-model)

echo "-- a whole Anthropic answer"
out=$WORK/whole
status=$(llm "$OLIVIA" /llm/anthropic/v1/messages "$ANTHROPIC_BODY" "$out" -H 'anthropic-version: 2023-06-01')
echo "status ${status}, usage $(json_at "$out" usage.input_tokens) in / $(json_at "$out" usage.output_tokens) out"
[ "$status" = 200 ] || fail "the whole answer was ${status}"
id=$(request_id "$out")
row=$(ledger_row "$id")
echo "ledger: ${row}"
[ "$row" = "fake-model|4|12|0.000192000" ] || fail "the ledger row is '${row}', not fake-model|4|12|0.000192000"

echo "-- an Anthropic stream"
out=$WORK/stream
status=$(llm "$OLIVIA" /llm/anthropic/v1/messages "$ANTHROPIC_STREAM_BODY" "$out" -N -H 'anthropic-version: 2023-06-01')
curl -sS --max-time 30 -o "$WORK/stream.direct" -H "x-api-key: ${FAKE_KEY}" -H 'Content-Type: application/json' \
  -d "$ANTHROPIC_STREAM_BODY" "${FAKE}/v1/messages"
echo "status ${status}, $(wc -c <"$out" | tr -d ' ') bytes through Keystone, $(wc -c <"$WORK/stream.direct" | tr -d ' ') direct"
[ "$status" = 200 ] || fail "the stream was ${status}"
cmp -s "$out" "$WORK/stream.direct" || fail "the stream through Keystone differs from the fake's own"
row=$(ledger_row "$(request_id "$out")")
echo "ledger: ${row}"
[ "$row" = "fake-model|4|12|0.000192000" ] || fail "the stream's ledger row is '${row}'"

echo "-- an OpenAI stream"
out=$WORK/openai
status=$(llm "$OLIVIA" /llm/openai/v1/chat/completions "$OPENAI_STREAM_BODY" "$out" -N)
echo "status ${status}; the fake was sent: $(fake_last_body | python3 -c 'import json,sys; print(json.load(sys.stdin).get("stream_options"))')"
[ "$status" = 200 ] || fail "the OpenAI stream was ${status}"
[ "$(fake_last_body | python3 -c 'import json,sys; print(json.load(sys.stdin).get("stream_options"))')" = "{'include_usage': True}" ] \
  || fail "the fake was not asked for the usage of the stream"
tail -c 20 "$out" | grep -q '\[DONE\]' || fail "the OpenAI stream does not end with [DONE]"
row=$(ledger_row "$(request_id "$out")")
echo "ledger: ${row}"
[ "$row" = "fake-model|4|12|0.000192000" ] || fail "the OpenAI stream's ledger row is '${row}'"

echo "-- a model with no price"
seen=$(fake_requests)
out=$WORK/unpriced
status=$(llm "$OLIVIA" /llm/anthropic/v1/messages "${ANTHROPIC_BODY/fake-model/mystery-model}" "$out")
echo "status ${status} $(json_at "$out" error.code)"
[ "$status" = 400 ] || fail "an unpriced model was ${status}, not 400"
[ "$(json_at "$out" error.code)" = KS_MODEL_NOT_PRICED ] || fail "the code is not KS_MODEL_NOT_PRICED"
[ "$(fake_requests)" = "$seen" ] || fail "the fake saw the unpriced request"

echo "-- lena, whose day is spent"
out=$WORK/over
status=$(llm "$LENA" /llm/anthropic/v1/messages "$ANTHROPIC_BODY" "$out")
echo "status ${status} $(json_at "$out" error.code), spent $(json_at "$out" error.spent_usd) of $(json_at "$out" error.limit_usd), estimate $(json_at "$out" error.estimate_usd)"
[ "$status" = 402 ] || fail "lena's request was ${status}, not 402"
[ "$(json_at "$out" error.code)" = KS_BUDGET_EXCEEDED ] || fail "the code is not KS_BUDGET_EXCEEDED"
[ "$(fake_requests)" = "$seen" ] || fail "the fake saw the request that was over budget"

echo "-- a provider that repeats the key"
out=$WORK/echo
status=$(llm "$OLIVIA" /llm/anthropic/v1/messages "${ANTHROPIC_BODY/fake-model/fake-error-echo-key}" "$out")
echo "status ${status}: $(cat "$out")"
[ "$status" = 401 ] || fail "the provider's refusal was ${status}, not 401"
grep -q '\[redacted\]' "$out" || fail "the key was not taken out of the provider's answer"
leaks=0
grep -qF "$FAKE_KEY" "$out" "${out}.headers" "$WORK/whole" "$WORK/whole.headers" "$WORK/stream" "$WORK/openai" && leaks=1
$COMPOSE logs keystone 2>&1 | grep -qF "$FAKE_KEY" && leaks=1
spans=""
for _ in $(seq 1 15); do
  start=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
  end=$(date -u -v+1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour' +%Y-%m-%dT%H:%M:%SZ)
  spans=$(curl -fsS --max-time 10 -G "${JAEGER}/api/v3/traces" \
    --data-urlencode "query.service_name=keystone" \
    --data-urlencode "query.operation_name=keystone.llm_call" \
    --data-urlencode "query.start_time_min=${start}" \
    --data-urlencode "query.start_time_max=${end}" \
    --data-urlencode "query.num_traces=20")
  grep -q 'gen_ai.usage.output_tokens' <<<"$spans" && break
  sleep 1
done
grep -q 'gen_ai.usage.output_tokens' <<<"$spans" || fail "Jaeger has no keystone.llm_call span with token counts"
grep -qF "$FAKE_KEY" <<<"$spans" && leaks=1
echo "the key in a response, a header, the Keystone logs or a span: $([ "$leaks" = 0 ] && echo no || echo YES)"
[ "$leaks" = 0 ] || fail "the provider key was found in a response, a log or a span"

echo "-- the tokens are counted"
input_after=$(token_count input fake-model)
output_after=$(token_count output fake-model)
echo "keystone_llm_tokens_total fake-model: input ${input_before:-0} -> ${input_after:-none}, output ${output_before:-0} -> ${output_after:-none}"
python3 - "${input_before:-0}" "${input_after:-0}" "${output_before:-0}" "${output_after:-0}" <<'PY' || fail "keystone_llm_tokens_total did not grow by 12 in and 36 out"
import sys

before_in, after_in, before_out, after_out = map(float, sys.argv[1:])
assert after_in - before_in == 12 and after_out - before_out == 36, sys.argv[1:]
PY
total=$(sql "SELECT sum(cost_usd) FROM spend_ledger WHERE kind = 'llm'")
echo "the ledger holds ${total} of model spend"
[ "$total" = "0.000576000" ] || fail "the model spend is ${total}, not 0.000576"

step "4. a burst of calls meets the rate limit"
echo "restarting Keystone with ${BURST} calls at once and ${REFILL} more each second for one user"
restarted=1
KEYSTONE_RATE_LIMIT_USER_CAPACITY=$BURST KEYSTONE_RATE_LIMIT_USER_REFILL=$REFILL \
  $COMPOSE up -d --force-recreate --wait keystone >/dev/null \
  || { echo "cannot restart keystone. Is the stack up (make up)?" >&2; exit 1; }
wait_for 60 curl -fsS --max-time 5 "${BASE}/readyz" || { echo "Keystone does not answer on ${BASE}" >&2; exit 1; }
clear_spend >/dev/null
burst=$(probe olivia ops-agent burst keystone__whoami '{}' 12)
echo "$burst"
passed=$(grep -c ' error=false ' <<<"$burst")
limited=$(grep -c 'code=KS_RATE_LIMITED' <<<"$burst")
echo "passed: ${passed}, limited: ${limited}"
[ "$passed" -ge "$BURST" ] && [ "$passed" -le $((BURST + 2)) ] || fail "${passed} calls passed, expected ${BURST} (or a refill more)"
[ "$limited" -ge 5 ] || fail "only ${limited} calls were rate limited"
retry=$(grep 'code=KS_RATE_LIMITED' <<<"$burst" | head -1 | sed -n 's/.*retry_after_s=\([0-9.]*\).*/\1/p')
echo "the first refusal said to retry in ${retry:-?} s"
python3 -c 'import sys; assert 0 < float(sys.argv[1]) <= 10' "${retry:-0}" || fail "retry_after_s is missing or not between 0 and 10"
sleep "$(python3 -c 'import math, sys; print(math.ceil(float(sys.argv[1])) + 1)' "${retry:-2}")"
out=$(probe olivia ops-agent call keystone__whoami '{}')
echo "after waiting: ${out%%$'\n'*}"
grep -q '^error=false' <<<"$out" || fail "a call after the wait was still refused"

echo
if [ "$failed" -eq 0 ]; then
  echo "phase 8 smoke: ok (sandbox 42, lena stopped at \$0.03, model calls booked at \$0.000192 and counted in tokens, a stream byte for byte, no price 400, over budget 402, the provider key nowhere, ${limited} of 12 calls rate limited)"
fi
[ "$failed" -eq 0 ]
