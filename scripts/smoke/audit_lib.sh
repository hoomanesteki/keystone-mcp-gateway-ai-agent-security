# Read the audit log from a smoke script. Source it from the repository root:
#
#   . scripts/smoke/audit_lib.sh
#
#   audit_last_seq            the highest seq in the log, or 0 when it is empty
#   audit_wait_for_seq N [S]  wait up to S seconds (default 10) for the log to reach seq N: the
#                             writer batches for up to 50 ms, so a record follows its call by
#                             a moment
#   audit_entry CALL_ID       "<effect> <reasons, comma separated>" of one call's record, waiting
#                             for it the same way; "none" when the call made no decision
#
# These ask Postgres through the container, as its owner role. The admin API replaces this in
# KS-507 and the functions keep their names.

AUDIT_COMPOSE="docker compose -f deploy/docker-compose.yml"
[ -f .env ] && AUDIT_COMPOSE="$AUDIT_COMPOSE --env-file .env"

audit_sql() {
  $AUDIT_COMPOSE exec -T postgres psql -U keystone -d keystone -At -F ' ' -c "$1"
}

audit_last_seq() {
  audit_sql 'SELECT COALESCE(MAX(seq), 0) FROM audit_events'
}

audit_wait_for_seq() {
  local want=$1 deadline=$((SECONDS + ${2:-10})) have
  while :; do
    have=$(audit_last_seq) || return 1
    [ "$have" -ge "$want" ] && return 0
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}

audit_entry() {
  local call_id=$1 deadline=$((SECONDS + 10)) row
  [[ $call_id =~ ^[0-9A-Z]{26}$ ]] || return 2
  while :; do
    row=$(audit_sql "SELECT COALESCE(effect, 'none'), array_to_string(reasons, ',') FROM audit_events WHERE call_id = '$call_id'") || return 1
    if [ -n "$row" ]; then
      echo "${row% }"
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}
