#!/usr/bin/env bash
# Phase 5 smoke, against the compose stack (make up):
#   1. Run the demo (scripts/smoke/phase_1.sh): the scripted agent makes tool calls as olivia.
#   2. Jaeger holds a trace for a call with more than 9 spans, and none of its spans names the user or
#      an argument value.
#   3. /metrics has keystone_tool_calls_total, with no label for a user, and Prometheus scrapes it.
#   4. `keystone audit verify` says OK.
#   5. A record is edited as the Postgres superuser: verify exits 2 and names the seq.
#   6. The record is put back: verify says OK again, and the same number of records.
#
# The tamper in step 5 is undone however the script ends. A fresh `make reset && make up` starts
# with an empty log, which verifies as `OK, 0 records`.
set -u

cd "$(dirname "$0")/../.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"
COMPOSE="docker compose -f deploy/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"

export KEYSTONE_URL=${KEYSTONE_URL:-http://localhost:${KEYSTONE_PORT:-8080}/mcp}
BASE=${KEYSTONE_URL%/mcp}
JAEGER="http://localhost:${JAEGER_UI_PORT:-16686}"
PROMETHEUS="http://localhost:${PROMETHEUS_PORT:-9090}"
GRAFANA="http://localhost:${GRAFANA_PORT:-3000}"
failed=0
tampered=""

fail() { echo "FAILED: $1" >&2; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }
keystone() { $COMPOSE exec -T keystone keystone "$@"; }
# The development login of the compose Grafana goes to curl on its standard input, not into a
# process list.
grafana_get() {
  curl -fsS --max-time 10 -K - "${GRAFANA}$1" <<'CONFIG'
user = "admin:admin"
CONFIG
}
sql() { $COMPOSE exec -T postgres psql -U keystone -d keystone -At -c "$1"; }

# Put a tampered record back, however the script ends.
restore() {
  if [ -n "$tampered" ]; then
    sql "UPDATE audit_events SET tool_name = '${tampered#*:}' WHERE seq = ${tampered%%:*}" >/dev/null
    tampered=""
  fi
}
trap restore EXIT

step "1. run the demo"
demo=$(bash scripts/smoke/phase_1.sh 2>&1)
demo_status=$?
echo "$demo" | tail -4
[ "$demo_status" -eq 0 ] || fail "the demo exited with ${demo_status}"

step "2. a trace with every stage"
# Jaeger v2 answers the OTLP JSON of /api/v3. Spans leave Keystone within about a second. The words
# are the user and two argument values of the demo; none of them may be in any span.
read -r -d '' TRACE_CHECK <<'PY'
import collections
import json
import sys

by_trace = collections.defaultdict(list)
for line in sys.stdin:
    if not line.strip():
        continue
    for resource in json.loads(line)["result"]["resourceSpans"]:
        for scope in resource["scopeSpans"]:
            for span in scope["spans"]:
                by_trace[span["traceId"]].append(span)
if not by_trace:
    sys.exit(1)
trace_id, spans = max(by_trace.items(), key=lambda item: len(item[1]))
names = sorted({span["name"] for span in spans})
text = json.dumps(spans)
leaks = [word for word in sys.argv[1:] if word in text]
print("%d spans in trace %s, leaks: %s" % (len(spans), trace_id[:12], ",".join(leaks) or "none"))
if leaks:
    sys.exit(2)
sys.exit(0 if len(spans) > 9 and "keystone.upstream.call" in names else 3)
PY
trace=""
for _ in $(seq 1 20); do
  start=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
  end=$(date -u -v+1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour' +%Y-%m-%dT%H:%M:%SZ)
  trace=$(curl -fsS --max-time 10 -G "${JAEGER}/api/v3/traces" \
    --data-urlencode "query.service_name=keystone" \
    --data-urlencode "query.operation_name=keystone.tool_call" \
    --data-urlencode "query.start_time_min=${start}" \
    --data-urlencode "query.start_time_max=${end}" \
    --data-urlencode "query.num_traces=20" \
    | python3 -c "$TRACE_CHECK" olivia colleague@acme.test CHK-001)
  status=$?
  { [ "$status" -eq 0 ] || [ "$status" -eq 2 ]; } && break
  sleep 1
done
echo "${trace:-no trace found in Jaeger}"
grep -q 'leaks: none' <<<"$trace" || fail "a span names the user or an argument, or Jaeger has no trace"
spans=$(sed -n 's/^\([0-9]*\) spans.*/\1/p' <<<"$trace")
[ "${spans:-0}" -gt 9 ] || fail "no trace with more than 9 spans"

step "3. metrics"
metrics=$(curl -fsS --max-time 10 "${BASE}/metrics") || fail "cannot read ${BASE}/metrics"
calls=$(grep -c '^keystone_tool_calls_total{' <<<"$metrics")
echo "keystone_tool_calls_total: ${calls} series"
[ "$calls" -gt 0 ] || fail "no keystone_tool_calls_total in /metrics"
grep -qE '^keystone[a-z_]*\{[^}]*(user|session)[a-z_]*=' <<<"$metrics" && fail "a metric has a user or session label"
scraped=""
for _ in $(seq 1 15); do
  scraped=$(curl -fsS --max-time 5 -G "${PROMETHEUS}/api/v1/query" \
    --data-urlencode 'query=sum(keystone_tool_calls_total)' \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else "")' 2>/dev/null)
  [ -n "$scraped" ] && break
  sleep 2
done
echo "Prometheus: sum(keystone_tool_calls_total) = ${scraped:-nothing}"
[ -n "$scraped" ] || fail "Prometheus has not scraped keystone_tool_calls_total"
board=$(grafana_get /api/dashboards/uid/keystone-overview \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["meta"]["provisioned"], len(d["dashboard"]["panels"]))' 2>/dev/null)
echo "Grafana dashboard (provisioned, panels): ${board:-missing}"
[ "${board%% *}" = True ] || fail "Grafana does not have the Keystone dashboard"

step "4. the chain verifies"
verified=$(keystone audit verify)
echo "$verified"
grep -qE '^OK, [0-9]+ records?$' <<<"$verified" || fail "verify did not say OK"
records=${verified#OK, }

step "5. an edited record is found"
# Seq 10 if it has a plain tool name, else the newest record that has one, so the name can be put
# back without quoting.
target=$(sql "SELECT seq FROM audit_events WHERE tool_name ~ '^[A-Za-z0-9_-]+\$' ORDER BY (seq = 10) DESC, seq DESC LIMIT 1")
original=$(sql "SELECT tool_name FROM audit_events WHERE seq = ${target:-0}")
[ -n "$target" ] && [ -n "$original" ] || fail "there is no record to edit"
if [ -n "$original" ]; then
  tampered="${target}:${original}"
  sql "UPDATE audit_events SET tool_name = 'x' WHERE seq = ${target}" >/dev/null
  broken=$(keystone audit verify)
  broken_status=$?
  echo "$broken (exit ${broken_status})"
  [ "$broken_status" -eq 2 ] || fail "verify exited ${broken_status}, not 2"
  [ "$broken" = "broken at seq ${target}: hash mismatch" ] || fail "verify did not name seq ${target}"
fi

step "6. the record is put back"
restore
again=$(keystone audit verify)
echo "$again"
[ "${again#OK, }" = "$records" ] || fail "verify says '${again}', not 'OK, ${records}'"

echo
if [ "$failed" -eq 0 ]; then
  echo "phase 5 smoke: ok (${spans} spans in a trace, metrics scraped, chain of ${records} verified, an edit at seq ${target} found and undone)"
fi
[ "$failed" -eq 0 ]
