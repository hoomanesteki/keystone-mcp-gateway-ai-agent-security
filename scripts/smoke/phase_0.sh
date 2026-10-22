#!/usr/bin/env bash
# Phase 0 smoke: every service in the local stack answers its health check.
set -u

cd "$(dirname "$0")/../.."
COMPOSE="docker compose -f deploy/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"
[ -f .env ] && set -a && . ./.env && set +a

rows=()
failed=0

check() {
  local name=$1 endpoint=$2
  shift 2
  local status=healthy
  if ! "$@" >/dev/null 2>&1; then
    status=FAILED
    failed=$((failed + 1))
  fi
  rows+=("$(printf '%-12s %-52s %s' "$name" "$endpoint" "$status")")
}

http_ok() { curl -fsS --max-time 5 "$1"; }

check postgres "pg_isready on :${POSTGRES_PORT:-55432}" \
  $COMPOSE exec -T postgres pg_isready -U keystone -d keystone
check redis "PING on :${REDIS_PORT:-56379}" \
  bash -c "$COMPOSE exec -T redis redis-cli ping | grep -q PONG"
check keycloak "realm keystone on :${KEYCLOAK_PORT:-8180}" \
  http_ok "http://localhost:${KEYCLOAK_PORT:-8180}/realms/keystone/.well-known/openid-configuration"
check jaeger "UI on :${JAEGER_UI_PORT:-16686}" \
  http_ok "http://localhost:${JAEGER_UI_PORT:-16686}/"
check prometheus "/-/healthy on :${PROMETHEUS_PORT:-9090}" \
  http_ok "http://localhost:${PROMETHEUS_PORT:-9090}/-/healthy"
check grafana "/api/health on :${GRAFANA_PORT:-3000}" \
  http_ok "http://localhost:${GRAFANA_PORT:-3000}/api/health"

printf '%-12s %-52s %s\n' SERVICE ENDPOINT STATUS
printf '%s\n' "${rows[@]}"
echo "${#rows[@]} services checked, $failed failed"
[ "$failed" -eq 0 ]
