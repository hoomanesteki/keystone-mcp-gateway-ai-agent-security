#!/usr/bin/env bash
# Create the GitHub release for a phase tag, using the gate report as the notes.
#
#   scripts/publish_releases.sh <tag> [--dry-run]
#
# Tags: v0.0.1 is phase 0, v0.N.0 is phase N (1 to 8), v1.0.0 is phase 9.
# The tag must already be pushed. Needs a signed-in GitHub CLI.
set -euo pipefail

tag="${1:-}"
dry_run=false
[ "${2:-}" = "--dry-run" ] && dry_run=true
if [ -z "$tag" ] || { [ -n "${2:-}" ] && ! $dry_run; }; then
  echo "usage: scripts/publish_releases.sh <tag> [--dry-run]" >&2
  exit 2
fi

case "$tag" in
  v0.0.1) phase=0 ;;
  v1.0.0) phase=9 ;;
  v0.[1-8].0) phase="${tag#v0.}"; phase="${phase%.0}" ;;
  *) echo "unknown release tag: $tag" >&2; exit 2 ;;
esac

report="docs/gates/phase-${phase}.md"
if [ ! -f "$report" ]; then
  echo "missing $report. Write the gate report before publishing." >&2
  exit 1
fi

# The report starts with "# Phase N gate: <name>".
name=$(sed -n '1s/^# Phase [0-9]* gate: //p' "$report")
title="${tag}: Phase ${phase} ${name}"

if $dry_run; then
  echo "gh release create ${tag} --title \"${title}\" --notes-file ${report} --verify-tag"
  exit 0
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not signed in. Run 'gh auth login' first." >&2
  exit 1
fi
gh release create "$tag" --title "$title" --notes-file "$report" --verify-tag
