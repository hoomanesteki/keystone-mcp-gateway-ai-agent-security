#!/usr/bin/env bash
# Target M9: a fresh clone reaches the output of `make demo` in 10 minutes or less.
#
#   scripts/fresh_clone_test.sh [repository-url-or-path] [branch]
#
# Clones into a new temporary directory, runs `make demo` there and prints the seconds it took.
# It uses the ports of the compose stack, so stop any stack that is running first. Docker's build
# cache counts: for a number from a cold machine, run `docker builder prune -af` before. The
# stack is left running after the demo; the last line says how to remove it.
set -euo pipefail

repo=${1:-https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security.git}
branch=${2:-main}
limit_s=600

work=$(mktemp -d "${TMPDIR:-/tmp}/keystone-fresh.XXXXXX")
log="$work/demo.log"

echo "cloning $repo ($branch) into $work/keystone"
start=$(date +%s)
git clone --quiet --depth 1 --branch "$branch" "$repo" "$work/keystone"

status=0
(cd "$work/keystone" && make demo) >"$log" 2>&1 || status=$?
elapsed=$(($(date +%s) - start))

tail -n 25 "$log"
echo
echo "make demo exit status: $status"
echo "elapsed seconds: $elapsed (target: $limit_s or less)"
echo "full output: $log"
echo "remove the stack with: (cd $work/keystone && make reset)"

if [ "$status" -ne 0 ]; then
  exit "$status"
fi
if [ "$elapsed" -gt "$limit_s" ]; then
  echo "over the target of $limit_s seconds"
  exit 2
fi
