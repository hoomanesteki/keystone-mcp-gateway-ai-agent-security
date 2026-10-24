#!/usr/bin/env bash
# Protect main and dev: required status checks, no force push, no deletion, and pull requests
# for everyone except repo admins. The maintainer is the only admin and merges story branches
# locally once CI is green on the branch, so admins are not held to the pull request rule.
#
#   scripts/protect_branches.sh [--dry-run]
#
# Needs a signed-in GitHub CLI with admin rights on the repo. --dry-run prints the requests only.
set -euo pipefail

# Keep in step with the job names in .github/workflows/ci.yml (a unit test compares them).
CHECKS=(lint-type unit policy integration console security docker commits docs terraform)
BRANCHES=(main dev)

dry_run=false
case "${1:-}" in
  --dry-run) dry_run=true ;;
  "") ;;
  *) echo "usage: scripts/protect_branches.sh [--dry-run]" >&2; exit 2 ;;
esac

slug=$(git remote get-url origin | sed -E 's#^.*github\.com[:/]##; s#\.git$##')

contexts=$(printf '"%s",' "${CHECKS[@]}")
contexts="[${contexts%,}]"

body=$(cat <<JSON
{
  "required_status_checks": { "strict": true, "contexts": ${contexts} },
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
)

if ! $dry_run && ! gh auth status >/dev/null 2>&1; then
  echo "gh is not signed in. Run 'gh auth login' first." >&2
  exit 1
fi

for branch in "${BRANCHES[@]}"; do
  echo "protecting ${slug}:${branch}"
  if $dry_run; then
    echo "gh api -X PUT repos/${slug}/branches/${branch}/protection --input -"
    echo "$body"
  else
    echo "$body" | gh api -X PUT "repos/${slug}/branches/${branch}/protection" --input - >/dev/null
  fi
done
echo "done"
