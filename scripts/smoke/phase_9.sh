#!/usr/bin/env bash
# Phase 9 smoke, against the compose stack (make up): the last proof that every phase still works
# with the others (docs/PLAN.md, integration checkpoint 9). It runs the smoke scripts of phases 0
# to 8, in order, against the one stack that is up. It runs all of them even when one fails, so that
# a gate says which ones, and it ends with the list.
#
# `make gate PHASE=9` runs this script and not the eight again. Run it by hand with the stack up:
#
#   bash scripts/smoke/phase_9.sh
#
# SMOKE_DIR names another folder with phase_0.sh to phase_8.sh in it. The tests of this script use
# it, with scripts that do nothing but exit.
set -u

cd "$(dirname "$0")/../.."
SMOKE_DIR=${SMOKE_DIR:-scripts/smoke}
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"

if [ -z "${SMOKE_SKIP_STACK_CHECK:-}" ]; then
  curl -fsS --max-time 5 "http://localhost:${KEYSTONE_PORT:-8080}/healthz" >/dev/null \
    || { echo "Keystone does not answer on port ${KEYSTONE_PORT:-8080}. Is the stack up (make up)?" >&2; exit 1; }
fi

failed=()
passed=()
for k in 0 1 2 3 4 5 6 7 8; do
  script="${SMOKE_DIR}/phase_${k}.sh"
  echo "== smoke: phase ${k}"
  if [ ! -f "$script" ]; then
    echo "FAILED: ${script} does not exist" >&2
    failed+=("$k")
    continue
  fi
  started=$SECONDS
  if bash "$script"; then
    passed+=("$k")
    echo "-- phase ${k}: ok ($((SECONDS - started)) s)"
  else
    failed+=("$k")
    echo "-- phase ${k}: FAILED ($((SECONDS - started)) s)" >&2
  fi
done

echo
echo "== smoke: phases 0 to 8 against one stack"
echo "ok:     ${passed[*]:-none}"
if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAILED: ${failed[*]}" >&2
  exit 1
fi
echo "every smoke passed"
