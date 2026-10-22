#!/usr/bin/env bash
# Wait for every GitHub Actions run on a commit, then print each job's result and the
# annotations of the jobs that failed. It reads the public API, so a public repo needs no login.
#
#   scripts/ci_wait.sh <sha> [max_seconds=540]
#
# Exit codes: 0 every job succeeded or was skipped, 1 a job failed or no run appeared,
# 2 usage or API error, 3 still running at the time limit (run it again).
#
# Unauthenticated calls are limited to 60 an hour, so it polls at most every 90 seconds and
# sleeps until the limit resets when fewer than 3 calls remain. Set GH_TOKEN to lift the limit.
# CI_WAIT_API_URL, CI_WAIT_POLL_SECONDS and CI_WAIT_APPEAR_SECONDS exist for the unit tests.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: scripts/ci_wait.sh <sha> [max_seconds=540]" >&2
  exit 2
fi

exec python3 - "$@" <<'PY'
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

API = os.environ.get("CI_WAIT_API_URL", "https://api.github.com").rstrip("/")
POLL_SECONDS = float(os.environ.get("CI_WAIT_POLL_SECONDS", "90"))
APPEAR_SECONDS = float(os.environ.get("CI_WAIT_APPEAR_SECONDS", "180"))
MIN_REMAINING = 3
MAX_RATE_SLEEP = 900
MAX_ANNOTATIONS = 30
PASSING = {"success", "skipped", "neutral"}


def log(message: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {message}", flush=True)


class ApiError(Exception):
    pass


class Client:
    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self.remaining: int | None = None
        self.reset: float | None = None

    def _note_limits(self, headers) -> None:
        if headers.get("X-RateLimit-Remaining") is not None:
            self.remaining = int(headers["X-RateLimit-Remaining"])
            self.reset = float(headers.get("X-RateLimit-Reset", "0"))

    def _wait_for_rate_limit(self) -> None:
        if self.remaining is None or self.remaining >= MIN_REMAINING or self.reset is None:
            return
        wait = self.reset - time.time() + 1
        if wait <= 0:
            return
        capped = min(wait, MAX_RATE_SLEEP, max(self.deadline - time.monotonic(), 0))
        log(
            f"rate limit nearly used up ({self.remaining} left), sleeping {capped:.0f} s "
            f"of the {wait:.0f} s until reset (capped by {MAX_RATE_SLEEP} s and the time limit)"
        )
        time.sleep(capped)
        self.remaining = None

    def get(self, path: str):
        self._wait_for_rate_limit()
        request = urllib.request.Request(
            API + path,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "keystone-ci-wait",
            },
        )
        token = os.environ.get("GH_TOKEN")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                self._note_limits(response.headers)
                return json.load(response)
        except urllib.error.HTTPError as err:
            self._note_limits(err.headers)
            raise ApiError(f"HTTP {err.code} {err.reason} for {path}") from err
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise ApiError(f"{type(err).__name__} for {path}: {err}") from err


def repo_slug() -> str:
    override = os.environ.get("CI_WAIT_REPO")
    if override:
        return override
    url = subprocess.run(
        ["git", "remote", "get-url", "origin"], capture_output=True, text=True, check=True
    ).stdout.strip()
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
    if not match:
        raise SystemExit(f"cannot read a GitHub owner/repo from the origin url: {url}")
    return match.group(1)


def print_failure_details(client: Client, slug: str, job: dict) -> None:
    for step in job.get("steps") or []:
        if step.get("conclusion") not in PASSING | {None}:
            print(f"    failed step: {step['name']} ({step['conclusion']})")
    try:
        annotations = client.get(
            f"/repos/{slug}/check-runs/{job['id']}/annotations?per_page={MAX_ANNOTATIONS}"
        )
    except ApiError as err:
        print(f"    could not read annotations: {err}")
        return
    for note in annotations[:MAX_ANNOTATIONS]:
        where = note.get("path") or "-"
        if note.get("start_line"):
            where += f":{note['start_line']}"
        text = (note.get("message") or "").strip().replace("\n", " ")
        print(f"    [{note.get('annotation_level')}] {where}  {text}")
    if not annotations:
        print("    no annotations on this job, read the log: " + job.get("html_url", ""))


def report(client: Client, slug: str, runs: list[dict]) -> int:
    failed = 0
    jobs_seen = 0
    for run in sorted(runs, key=lambda r: r["id"]):
        print(f"{run['name']} ({run['event']}, run {run['id']}): {run['conclusion']}")
        jobs = client.get(f"/repos/{slug}/actions/runs/{run['id']}/jobs?per_page=100")["jobs"]
        for job in jobs:
            jobs_seen += 1
            print(f"  {job['name']:<14} {job['conclusion']}")
            if job["conclusion"] not in PASSING:
                failed += 1
                print_failure_details(client, slug, job)
        if not jobs and run["conclusion"] not in PASSING:
            failed += 1
            print(f"  run ended with no jobs: {run.get('html_url', '')}")
    verdict = "green" if failed == 0 else "failed"
    print(f"{len(runs)} runs, {jobs_seen} jobs, {failed} failed: {verdict}")
    return 0 if failed == 0 else 1


def main() -> int:
    sha = sys.argv[1]
    max_seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 540.0
    slug = repo_slug()
    start = time.monotonic()
    deadline = start + max_seconds
    appear_deadline = start + min(APPEAR_SECONDS, max_seconds)
    client = Client(deadline)
    polled = False
    log(f"waiting for runs of {sha[:10]} in {slug} (limit {max_seconds:.0f} s)")

    while True:
        runs: list[dict] = []
        try:
            runs = client.get(f"/repos/{slug}/actions/runs?head_sha={sha}&per_page=100")[
                "workflow_runs"
            ]
            polled = True
        except ApiError as err:
            log(f"poll failed, will retry: {err}")

        now = time.monotonic()
        if runs:
            pending = [r for r in runs if r["status"] != "completed"]
            names = ", ".join(f"{r['name']}={r['status']}" for r in runs)
            log(f"{len(runs) - len(pending)}/{len(runs)} runs complete ({names})")
            if not pending:
                try:
                    return report(client, slug, runs)
                except ApiError as err:
                    print(f"could not read job results: {err}", file=sys.stderr)
                    return 2
        elif polled and now >= appear_deadline:
            print(f"no workflow runs for {sha} after {min(APPEAR_SECONDS, max_seconds):.0f} s")
            return 1

        if now >= deadline:
            if not polled:
                print("the GitHub API never answered", file=sys.stderr)
                return 2
            print(f"still running after {max_seconds:.0f} s, run this again")
            return 3
        wait = POLL_SECONDS
        if not runs:
            wait = min(wait, max(appear_deadline - now, 0.05))
        time.sleep(min(wait, max(deadline - now, 0.05)))


sys.exit(main())
PY
