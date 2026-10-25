#!/usr/bin/env bash
# Run the red-team suite against the compose stack in each of the three configs (KS-902).
#
#   scripts/redteam.sh naive                       # 60 scenarios in C0, C1 and C2: no model, no key
#   scripts/redteam.sh naive --configs C2          # one config, or a list: C0,C2
#   scripts/redteam.sh naive --configs C2 --config-ref v0.8.0
#                                                  # C2 with the keystone.compose.yaml of a release
#   scripts/redteam.sh llm --model <model id> --seeds 3 --max-usd 40
#                                                  # a model-driven agent: needs a key, see below
#   scripts/redteam.sh naive --out-dir <folder>    # the files go there and not to eval/results
#
# For each config the script restarts the keystone service of the stack (make up first) with the
# settings of that config (deploy/redteam.override.yml), waits until it answers, runs the runner
# (eval/redteam/runner.py) and writes eval/results/redteam-<agent>-<config>-<date>.jsonl. The
# runner asks the gateway how it is set and stops if that is not the config it was told. When the
# script ends, however it ends, Keystone is restarted with the settings of the stack.
#
#   C0  KEYSTONE_PROFILE=passthrough, the scanner off
#   C1  the policies of the repository without the Rule of Two (policies/**/rule_of_two.cedar), and
#       the scanner off. The copy of policies/ for it is made in .cache/redteam/, never edited in place
#   C2  the stack as it is
#
# Everything after the options of the script goes to the runner (--seeds, --max-usd, --only,
# --limit, --note, --model, --script-hint). A result file is never written over: if a config is run
# twice in a day, move the first file.
#
# The model-driven agent goes through Keystone's LLM proxy. The stack points the proxy at the fake
# model API, which tests the loop and measures nothing about a model; its model is `fake-agent`.
# For a real model:
#
#   ANTHROPIC_API_KEY=<key> REDTEAM_LLM_BASE_URL=https://api.anthropic.com \
#   REDTEAM_LLM_KEY_ENV=ANTHROPIC_API_KEY REDTEAM_PRICING=<pricing.yaml> \
#     scripts/redteam.sh llm --model <model id> --seeds 3 --max-usd 40
#
# The pricing file must price the model (deploy/pricing.compose.yaml has the fake prices and
# pricing.example.yaml shows the shape), or the proxy refuses every request with KS_MODEL_NOT_PRICED.
# The demo tenant has a budget of $25 a day in deploy/keystone.compose.yaml, which a run that costs
# more would meet: raise it first.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/dev_env.sh
. scripts/dev_env.sh
load_dev_env "$PWD"

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
  exit 2
}

agent=${1:-}
case $agent in
  naive | llm) shift ;;
  *) usage ;;
esac

configs="C0,C1,C2"
config_ref=""
variant=""
out_dir=eval/results
runner_args=()
while [ $# -gt 0 ]; do
  case $1 in
    --configs) configs=${2:?--configs needs a list such as C0,C1,C2}; shift 2 ;;
    --config-ref) config_ref=${2:?--config-ref needs a git ref}; shift 2 ;;
    --variant) variant=${2:?--variant needs a name}; shift 2 ;;
    --out-dir) out_dir=${2:?--out-dir needs a folder}; shift 2 ;;
    -h | --help) usage ;;
    *) runner_args+=("$1"); shift ;;
  esac
done

model=""
for ((i = 0; i < ${#runner_args[@]}; i++)); do
  [ "${runner_args[$i]}" = "--model" ] && model=${runner_args[$((i + 1))]:-}
done
if [ "$agent" = "llm" ]; then
  [ -n "$model" ] || { echo "the llm agent needs --model <model id>" >&2; exit 2; }
  if [[ $model != fake-* ]]; then
    [ -n "${ANTHROPIC_API_KEY:-}" ] \
      || { echo "not run: needs an API key (ANTHROPIC_API_KEY is not set)" >&2; exit 2; }
    [ -n "${REDTEAM_LLM_BASE_URL:-}" ] && [ -n "${REDTEAM_PRICING:-}" ] \
      || { echo "a real model needs REDTEAM_LLM_BASE_URL and REDTEAM_PRICING (see the top of this script)" >&2; exit 2; }
    export REDTEAM_LLM_KEY_ENV=${REDTEAM_LLM_KEY_ENV:-ANTHROPIC_API_KEY}
  fi
fi
for config in ${configs//,/ }; do
  case $config in C0 | C1 | C2) ;; *) echo "unknown config: $config" >&2; exit 2 ;; esac
done

COMPOSE="docker compose -f deploy/docker-compose.yml -f deploy/redteam.override.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"

KEYSTONE_BASE="http://localhost:${KEYSTONE_PORT:-8080}"
DATABASE_URL="postgresql+asyncpg://keystone:keystone@localhost:${POSTGRES_PORT:-55432}/keystone"
STATE=.cache/redteam
DATE=$(date -u +%Y-%m-%d)
mkdir -p "$STATE" "$out_dir"

restart() { $COMPOSE up -d --force-recreate --no-deps --wait keystone >/dev/null; }
settings_off() {
  unset REDTEAM_PROFILE REDTEAM_SCANNER REDTEAM_POLICIES REDTEAM_CONFIG
}
cleanup() {
  local status=$?
  settings_off
  unset REDTEAM_PRICING REDTEAM_LLM_BASE_URL REDTEAM_LLM_KEY_ENV ANTHROPIC_API_KEY
  echo "== restoring the stack's own settings" >&2
  restart || echo "could not restart keystone: run make up" >&2
  exit "$status"
}
trap cleanup EXIT

# A copy of policies/ without the policies of the Rule of Two, for C1. It is made again for each
# run, so that it cannot drift from the repository.
policies_without_the_rule_of_two() {
  rm -rf "$STATE/policies-c1"
  mkdir -p "$STATE/policies-c1"
  cp -R policies/. "$STATE/policies-c1/"
  find "$STATE/policies-c1" -name rule_of_two.cedar -delete
}

# Where the config of a release is read from, when --config-ref is given.
if [ -n "$config_ref" ]; then
  git rev-parse --verify --quiet "$config_ref^{commit}" >/dev/null \
    || { echo "unknown git ref: $config_ref" >&2; exit 2; }
  git show "$config_ref:deploy/keystone.compose.yaml" >"$STATE/keystone-$config_ref.yaml"
  : "${variant:=compose config of $config_ref}"
fi

for config in ${configs//,/ }; do
  settings_off
  echo "== $config ($agent)" >&2
  case $config in
    C0) export REDTEAM_PROFILE=passthrough REDTEAM_SCANNER=false ;;
    C1)
      policies_without_the_rule_of_two
      export REDTEAM_SCANNER=false REDTEAM_POLICIES="$PWD/$STATE/policies-c1"
      ;;
    C2) ;;
  esac
  [ -n "$config_ref" ] && export REDTEAM_CONFIG="$PWD/$STATE/keystone-$config_ref.yaml"
  restart

  suffix=""
  if [ -n "$variant" ]; then
    suffix="-$(printf '%s' "$variant" | tr '[:upper:] ' '[:lower:]-' | tr -c 'a-z0-9.\n-' '-')"
  fi
  out="$out_dir/redteam-${agent}-${config}${suffix}-${DATE}.jsonl"
  variant_args=()
  [ -n "$variant" ] && variant_args=(--variant "$variant")
  uv run python -m eval.redteam.runner \
    --config "$config" --agent "$agent" --out "$out" \
    --keystone "$KEYSTONE_BASE" --database-url "$DATABASE_URL" \
    ${variant_args[@]+"${variant_args[@]}"} ${runner_args[@]+"${runner_args[@]}"}
done
echo "== done: the files are in $out_dir/. Next: uv run python -m eval.redteam.report" >&2
