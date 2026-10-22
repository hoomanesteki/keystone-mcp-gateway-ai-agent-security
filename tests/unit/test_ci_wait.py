import json
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci_wait.sh"
SHA = "a" * 40
SLUG = "octo/keystone"


class FakeGitHub:
    """Serves canned API responses and records what was asked."""

    def __init__(self) -> None:
        self.routes: dict[str, Callable[[], Any]] = {}
        self.requests: list[tuple[str, str | None]] = []
        self.headers: dict[str, str] = {}

    def handler(self) -> type[BaseHTTPRequestHandler]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = self.path.split("?")[0]
                fake.requests.append((self.path, self.headers.get("Authorization")))
                route = fake.routes.get(path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(route()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                for key, value in fake.headers.items():
                    self.send_header(key, value)
                fake.headers = {}
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        return Handler


@pytest.fixture
def github() -> Iterator[tuple[FakeGitHub, str]]:
    fake = FakeGitHub()
    server = ThreadingHTTPServer(("127.0.0.1", 0), fake.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield fake, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "remote", "add", "origin", f"git@github.com:{SLUG}.git"],
        check=True,
    )
    return tmp_path


def run_script(
    repo: Path, url: str, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    import os

    full_env = {
        **{k: v for k, v in os.environ.items() if k != "GH_TOKEN"},
        "CI_WAIT_API_URL": url,
        "CI_WAIT_POLL_SECONDS": "0.2",
        "CI_WAIT_APPEAR_SECONDS": "0.6",
        **(env or {}),
    }
    return subprocess.run(
        ["bash", str(SCRIPT), SHA, *args],
        cwd=repo,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def run_payload(status: str = "completed", conclusion: str | None = "success") -> dict[str, Any]:
    return {
        "workflow_runs": [
            {"id": 7, "name": "CI", "event": "push", "status": status, "conclusion": conclusion}
        ]
    }


def jobs_payload(*jobs: tuple[int, str, str]) -> dict[str, Any]:
    return {
        "jobs": [
            {"id": job_id, "name": name, "conclusion": conclusion, "steps": []}
            for job_id, name, conclusion in jobs
        ]
    }


RUNS = f"/repos/{SLUG}/actions/runs"


@pytest.mark.phase(0)
def test_all_green_exits_zero_and_lists_jobs(github: tuple[FakeGitHub, str], repo: Path) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: run_payload()
    fake.routes[f"{RUNS}/7/jobs"] = lambda: jobs_payload(
        (1, "lint-type", "success"), (2, "docker", "skipped")
    )

    result = run_script(repo, url)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "lint-type" in result.stdout
    assert "success" in result.stdout
    assert "docker" in result.stdout
    assert "skipped" in result.stdout
    assert "2 jobs, 0 failed: green" in result.stdout
    assert fake.requests[0][0] == f"{RUNS}?head_sha={SHA}&per_page=100"


@pytest.mark.phase(0)
def test_failed_job_prints_annotations_and_exits_one(
    github: tuple[FakeGitHub, str], repo: Path
) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: run_payload(conclusion="failure")
    fake.routes[f"{RUNS}/7/jobs"] = lambda: jobs_payload(
        (1, "unit", "success"), (2, "lint-type", "failure")
    )
    fake.routes[f"/repos/{SLUG}/check-runs/2/annotations"] = lambda: [
        {
            "path": "src/keystone/app.py",
            "start_line": 12,
            "annotation_level": "failure",
            "message": "F401 unused import",
        }
    ]

    result = run_script(repo, url)

    assert result.returncode == 1
    assert "src/keystone/app.py:12" in result.stdout
    assert "F401 unused import" in result.stdout
    assert "1 failed: failed" in result.stdout


@pytest.mark.phase(0)
def test_prints_at_most_thirty_annotations(github: tuple[FakeGitHub, str], repo: Path) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: run_payload(conclusion="failure")
    fake.routes[f"{RUNS}/7/jobs"] = lambda: jobs_payload((2, "unit", "failure"))
    fake.routes[f"/repos/{SLUG}/check-runs/2/annotations"] = lambda: [
        {"path": f"t{i}.py", "start_line": i, "annotation_level": "failure", "message": f"m{i}"}
        for i in range(45)
    ]

    result = run_script(repo, url)

    assert result.stdout.count("[failure]") == 30


@pytest.mark.phase(0)
def test_still_running_at_the_limit_exits_three(github: tuple[FakeGitHub, str], repo: Path) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: run_payload(status="in_progress", conclusion=None)

    result = run_script(repo, url, "1")

    assert result.returncode == 3
    assert "still running" in result.stdout


@pytest.mark.phase(0)
def test_waits_for_runs_that_finish_later(github: tuple[FakeGitHub, str], repo: Path) -> None:
    fake, url = github
    answers = iter([[], run_payload("queued", None), run_payload("in_progress", None)])

    def runs() -> dict[str, Any]:
        item = next(answers, None)
        if item is None:
            return run_payload()
        return item if isinstance(item, dict) else {"workflow_runs": item}

    fake.routes[RUNS] = runs
    fake.routes[f"{RUNS}/7/jobs"] = lambda: jobs_payload((1, "unit", "success"))

    result = run_script(repo, url, "30", env={"CI_WAIT_APPEAR_SECONDS": "30"})

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.phase(0)
def test_no_runs_at_all_exits_one(github: tuple[FakeGitHub, str], repo: Path) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: {"workflow_runs": []}

    result = run_script(repo, url)

    assert result.returncode == 1
    assert "no workflow runs" in result.stdout


@pytest.mark.phase(0)
def test_token_is_sent_only_when_set(github: tuple[FakeGitHub, str], repo: Path) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: run_payload()
    fake.routes[f"{RUNS}/7/jobs"] = lambda: jobs_payload((1, "unit", "success"))

    run_script(repo, url)
    assert {auth for _, auth in fake.requests} == {None}

    fake.requests.clear()
    run_script(repo, url, env={"GH_TOKEN": "t0ken"})
    assert {auth for _, auth in fake.requests} == {"Bearer t0ken"}


@pytest.mark.phase(0)
def test_sleeps_until_reset_when_the_rate_limit_is_nearly_used(
    github: tuple[FakeGitHub, str], repo: Path
) -> None:
    fake, url = github
    fake.routes[RUNS] = lambda: run_payload()
    fake.routes[f"{RUNS}/7/jobs"] = lambda: jobs_payload((1, "unit", "success"))
    # Only the first response carries the headers, so the script sleeps once.
    fake.headers = {
        "X-RateLimit-Remaining": "2",
        "X-RateLimit-Reset": str(int(time.time()) + 1),
    }

    started = time.monotonic()
    result = run_script(repo, url, "30")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "rate limit nearly used up" in result.stdout
    assert "capped" in result.stdout
    assert time.monotonic() - started >= 1.0


@pytest.mark.phase(0)
def test_usage_error_without_a_sha(repo: Path) -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT)], cwd=repo, capture_output=True, text=True, check=False
    )

    assert result.returncode == 2
    assert "usage" in result.stderr
