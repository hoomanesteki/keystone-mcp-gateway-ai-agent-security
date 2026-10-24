"""Run the performance matrix against the compose stack and write what it measured (KS-903).

    python -m eval.perf.matrix                      # 5 targets, 2 payloads, 200 sessions x 20 calls
    python -m eval.perf.matrix --targets direct scanner-off --sizes 1024
    python -m eval.perf.matrix --smoke              # 10 sessions x 5 calls, the stack as it runs

The targets are the echo upstream alone and Keystone in four settings of one build: passthrough
(every slot a stub), full with the scanner off, full with the rules alone, and full with the
classifier. For each Keystone target the matrix restarts the keystone service with
`deploy/perf.override.yml` (4 CPUs, 4 GB, one worker, warning logs, no rate limits worth the name),
checks at `/metrics` that it is what the target says (and that its model has loaded, where it has
one), waits until the machine is idle, and for each payload makes the run: N sessions, M calls each.

Besides the latency of each call it records where the time went. The gateway counts the time every
call spends in each stage of its pipeline (`keystone_tool_call_duration_seconds`), and the matrix
reads those counters just before the timed calls and just after, so the mean time in each stage is
that of the calls that were timed. It also samples the CPU of the keystone container while the
calls are made, and records how busy each process of the generator was, so that a run in which the
generator or the gateway was the limit can be told.

A second run of every target and payload has one session making 200 calls one after the other. At
200 sessions the latency of a call is mostly the wait for the calls ahead of it; with one session
it is the time the gateway and the upstream need, and the two together say which it was.

The result is `eval/results/perf-<date>.json`: the machine, the settings, and for each target and
payload the summary, the stage means, the container's CPU, the generator's CPU and every latency.
`python -m eval.perf.report` writes the performance section of docs/results.md from it. A run
needs the stack up (`make up`) and leaves the keystone service as the stack defines it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from eval.gateway_info import read_info, stage_means_ms, stage_totals
from eval.perf.load import MAX_RUN_S, Spec, payload, run_load
from eval.redteam.suite import REPO

RESULTS = REPO / "eval" / "results"
KEYSTONE = "http://localhost:8080"
ECHO = "http://localhost:8104/mcp"
# The key of the echo upstream (docker-compose.yml, .env.example). Development only.
ECHO_KEY = "dev-echo-key-0e4b9d13"
SIZES = (1024, 8192)
SESSIONS = 200
CALLS = 20
SEQUENTIAL_CALLS = 200
PROCESSES = 4
# The host must be this idle, over two seconds, before a target is measured.
IDLE_PERCENT = 85.0
QUIET_WAIT_S = 600.0
MODEL_WAIT_S = 180.0
MODEL = "protectai-deberta-v2"


@dataclass(frozen=True)
class Target:
    key: str
    label: str
    # The PERF_* variables of deploy/perf.override.yml that make the target.
    settings: Mapping[str, str] = field(default_factory=dict)
    # What the gateway must say at /metrics, or None for the upstream alone.
    info: Mapping[str, str] | None = None

    @property
    def direct(self) -> bool:
        return self.info is None


TARGETS: tuple[Target, ...] = (
    Target("direct", "Direct echo"),
    Target(
        "passthrough",
        "Keystone passthrough",
        {"PERF_PROFILE": "passthrough"},
        {"profile": "passthrough", "scanner": "off", "classifier": "none"},
    ),
    Target(
        "scanner-off",
        "Keystone full, scanner off",
        {"PERF_SCANNER": "false"},
        {"profile": "full", "scanner": "off", "classifier": "none"},
    ),
    Target(
        "rules-only",
        "Keystone full, rules only",
        {"PERF_CLASSIFIER": "none"},
        {"profile": "full", "scanner": "on", "classifier": "none"},
    ),
    Target(
        "classifier",
        "Keystone full, classifier",
        {},
        {"profile": "full", "scanner": "on", "classifier": MODEL},
    ),
)
BY_KEY = {target.key: target for target in TARGETS}
COMPOSE = [
    "docker",
    "compose",
    "-f",
    "deploy/docker-compose.yml",
    "-f",
    "deploy/perf.override.yml",
]


def run(*args: str, env: Mapping[str, str] | None = None, check: bool = True) -> str:
    """Run a command in the repository and return what it printed."""
    done = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        list(args),
        cwd=REPO,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=check,
    )
    return done.stdout.strip()


# -- the machine


def parse_top_idle(text: str) -> float | None:
    """The idle percentage of the last `CPU usage:` line of macOS `top`."""
    found = re.findall(r"CPU usage:.*?([\d.]+)% idle", text)
    return float(found[-1]) if found else None


def idle_percent() -> float | None:
    """How idle the host CPU is over two seconds. macOS reads `top`, Linux reads /proc/stat."""
    if sys.platform == "darwin":
        return parse_top_idle(run("top", "-l", "2", "-n", "0", "-s", "1", check=False))
    try:
        first = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        time.sleep(2)
        second = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    except OSError:
        return None
    total = [int(b) - int(a) for a, b in zip(first, second, strict=False)]
    return 100.0 * total[3] / sum(total) if sum(total) else None


def wait_until_quiet(max_wait_s: float = QUIET_WAIT_S) -> dict[str, Any]:
    """Wait until the host is idle, and say what it was. Gives up after `max_wait_s` and says that
    the machine was not quiet, which the report prints beside the numbers."""
    deadline = time.monotonic() + max_wait_s
    waited = 0.0
    started = time.monotonic()
    while True:
        idle = idle_percent()
        waited = time.monotonic() - started
        if idle is None or idle >= IDLE_PERCENT:
            return {"idle_percent": idle, "waited_s": round(waited, 1), "quiet": True}
        if time.monotonic() >= deadline:
            return {"idle_percent": idle, "waited_s": round(waited, 1), "quiet": False}
        time.sleep(5)


def sysctl(name: str) -> str:
    return run("sysctl", "-n", name, check=False)


def machine_facts() -> dict[str, Any]:
    """CPU model, vCPUs, RAM, Docker, the commit and whether the tree was clean."""
    if sys.platform == "darwin":
        cpu, ram = sysctl("machdep.cpu.brand_string"), int(sysctl("hw.memsize") or 0)
    else:
        info = Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else ""
        found = re.search(r"model name\s*:\s*(.+)", info)
        cpu = found.group(1) if found else platform.processor()
        meminfo = Path("/proc/meminfo").read_text() if Path("/proc/meminfo").exists() else ""
        total = re.search(r"MemTotal:\s*(\d+) kB", meminfo)
        ram = int(total.group(1)) * 1024 if total else 0
    vm = run(
        "docker",
        "info",
        "--format",
        "{{.NCPU}}|{{.MemTotal}}|{{.OperatingSystem}}|{{.Architecture}}",
        check=False,
    ).split("|")
    status = run("git", "status", "--porcelain", "--", ".", ":(exclude)eval/results", check=False)
    return {
        "cpu": cpu,
        "vcpus": os.cpu_count(),
        "ram_bytes": ram,
        "os": platform.platform(),
        "python": platform.python_version(),
        "docker": run("docker", "version", "--format", "{{.Server.Version}}", check=False),
        "docker_vm": {
            "cpus": int(vm[0]) if len(vm) == 4 and vm[0].isdigit() else None,
            "memory_bytes": int(vm[1]) if len(vm) == 4 and vm[1].isdigit() else None,
            "os": vm[2] if len(vm) == 4 else None,
            "architecture": vm[3] if len(vm) == 4 else None,
        },
        "commit": run("git", "rev-parse", "HEAD", check=False),
        "dirty": bool(status),
        "load_average": list(os.getloadavg()),
    }


# -- the stack


def container() -> str:
    found = run(*COMPOSE, "ps", "-q", "keystone", check=False)
    if not found:
        raise RuntimeError("the keystone service is not running; start the stack with `make up`")
    return found


def limits() -> dict[str, Any]:
    """What the keystone container is limited to, from Docker."""
    raw = run(
        "docker",
        "inspect",
        container(),
        "--format",
        "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}",
    )
    nanocpus, memory = (int(part) for part in raw.split())
    return {"cpus": nanocpus / 1e9 if nanocpus else None, "memory_bytes": memory or None}


def configure(target: Target) -> dict[str, Any]:
    """Restart the keystone service as the target says, wait until it answers, and check at
    /metrics that it is what the target needs: its profile, its scanner, its model, and that the
    model has loaded. Returns what the gateway said. The PERF_* variables of the caller's
    environment are dropped, so that only the target's settings apply."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PERF_")}
    subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [*COMPOSE, "up", "-d", "--force-recreate", "--no-deps", "--wait", "keystone"],
        cwd=REPO,
        env={**env, **target.settings},
        capture_output=True,
        text=True,
        check=True,
    )
    return wait_for_gateway(target)


def wait_for_gateway(target: Target, wait_s: float = MODEL_WAIT_S) -> dict[str, Any]:
    deadline = time.monotonic() + wait_s
    while True:
        page = httpx.get(f"{KEYSTONE}/metrics", timeout=10).text
        info, ready = read_info(page)
        if info is None:
            raise RuntimeError("the gateway does not say how it is set at /metrics")
        loaded = ready.get(info["classifier"]) if info["classifier"] != "none" else True
        if loaded or time.monotonic() >= deadline:
            break
        time.sleep(1)
    if target.info is not None and {k: info[k] for k in target.info} != dict(target.info):
        raise RuntimeError(f"this is not {target.key}: the gateway says {info}, not {target.info}")
    if not loaded:
        raise RuntimeError(f"the model {info['classifier']} did not load in {wait_s:.0f} s")
    return {**info, "classifier_ready": loaded}


def restore() -> None:
    """Put the keystone service back as the stack defines it, without this file."""
    run(
        "docker",
        "compose",
        "-f",
        "deploy/docker-compose.yml",
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        "--wait",
        "keystone",
    )


# -- the container's CPU while the calls are made


def parse_stats(line: str) -> tuple[float, float] | None:
    """`(cpu percent, memory in MiB)` from a line of `docker stats`: `12.3% 837MiB / 4GiB`."""
    found = re.match(r"\s*([\d.]+)%\s+([\d.]+)([KMG]i?B)", line)
    if not found:
        return None
    unit = {"KiB": 1 / 1024, "KB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}[
        found.group(3)
    ]
    return float(found.group(1)), float(found.group(2)) * unit


class Sampler:
    """Samples `docker stats` for a container in a thread until it is stopped. Each sample takes
    about two seconds, so a short run has few."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.samples: list[tuple[float, float]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            line = run(
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.CPUPerc}} {{.MemUsage}}",
                self.name,
                check=False,
            )
            parsed = parse_stats(line)
            if parsed is not None:
                self.samples.append(parsed)

    def __enter__(self) -> Sampler:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=15)

    def summary(self) -> dict[str, Any]:
        if not self.samples:
            return {"samples": 0}
        cpu = [c for c, _ in self.samples]
        return {
            "samples": len(self.samples),
            "cpu_percent_mean": sum(cpu) / len(cpu),
            "cpu_percent_max": max(cpu),
            "memory_mib_max": max(m for _, m in self.samples),
        }


# -- what the gateway logged while the calls were made


def count_log_events(text: str) -> dict[str, int]:
    """How often each event was logged at warning level or above, from the JSON lines the gateway
    writes. A line that is not JSON (uvicorn's own) is left out."""
    counts: dict[str, int] = {}
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or entry.get("level") not in (
            "warning",
            "error",
            "critical",
        ):
            continue
        event = str(entry.get("event", "?"))
        if isinstance(entry.get("error"), str):
            event = f"{event} ({entry['error']})"
        counts[event] = counts.get(event, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def log_events(name: str, since: datetime) -> dict[str, int]:
    done = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        ["docker", "logs", "--since", since.isoformat(timespec="seconds"), name],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return count_log_events(done.stdout + done.stderr)


# -- one run


async def measure(
    target: Target, size: int, sessions: int, calls: int, processes: int, sample: bool = True
) -> dict[str, Any]:
    """One run of a target: the warm-up, the timed calls, the stages the gateway counted for them,
    and the CPU of the container while they were made."""
    if target.direct:
        spec = Spec(
            ECHO,
            "echo",
            {"X-Api-Key": os.environ.get("ECHO_API_KEY", ECHO_KEY)},
            sessions,
            calls,
            size,
        )
    else:
        spec = Spec(f"{KEYSTONE}/mcp", "echo__echo", {}, sessions, calls, size, user="olivia")
    counted: dict[str, dict[str, tuple[float, float]]] = {}

    async def read_before() -> None:
        if not target.direct:
            async with httpx.AsyncClient(timeout=30) as http:
                counted["before"] = stage_totals((await http.get(f"{KEYSTONE}/metrics")).text)

    began = datetime.now(UTC)
    name = None if target.direct else container()
    watched = Sampler(name) if sample and name else None
    if watched:
        watched.__enter__()
    try:
        result = await run_load(spec, processes, on_go=read_before)
    finally:
        if watched:
            watched.__exit__()
    stages: dict[str, Any] = {}
    if not target.direct and "before" in counted:
        async with httpx.AsyncClient(timeout=30) as http:
            after = stage_totals((await http.get(f"{KEYSTONE}/metrics")).text)
        stages = stage_means_ms(counted["before"], after)
    return {
        "size": size,
        "sessions": sessions,
        "calls_each": calls,
        "summary": result["summary"],
        "errors": result["errors"],
        "opened": result["opened"],
        "stopped_early": result["stopped_early"],
        "generator": result["generator"],
        "stages": stages,
        "log_events": log_events(name, began) if name else None,
        "container": watched.summary() if watched else None,
        "latencies_ms": result["latencies_ms"],
        "failed_ms": result["failed_ms"],
    }


def token_count(size: int) -> int | None:
    """How many tokens of the scanner's model the payload is, when the extra is installed."""
    try:
        from transformers import AutoTokenizer

        from keystone.defense.classifier import SPECS

        spec = SPECS[MODEL]
        tokenizer = AutoTokenizer.from_pretrained(spec.model_id, revision=spec.revision)
        return len(tokenizer(payload(size), add_special_tokens=False)["input_ids"])
    except Exception:
        return None


def show(key: str, run_: Mapping[str, Any]) -> None:
    """One line for a run, as soon as it is made, so that a run that dies later has told what the
    earlier ones measured."""
    summary = run_["summary"]
    if not summary:
        print(f"{key:12} {run_['size']:5} B  no call was timed: {run_['errors']}", flush=True)
        return
    ms = " ".join(f"p{q} {summary[f'p{q}_ms']:8.1f}" for q in (50, 95, 99))
    print(
        f"{key:12} {run_['size']:5} B  {run_['sessions']:3} x {run_['calls_each']:<3} {ms} ms"
        f"  {summary['throughput']:7.1f}/s  errors {summary['errors']}"
        + ("  (stopped early)" if run_["stopped_early"] else ""),
        flush=True,
    )


async def matrix(
    targets: Sequence[Target],
    sizes: Sequence[int],
    sessions: int,
    calls: int,
    sequential: int,
    processes: int,
    quiet: bool = True,
    restart: bool = True,
    sample: bool = True,
    checkpoint: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Make the runs and return the document. `checkpoint` is called with the document after
    every run, so that a file on disk always holds what has been measured so far, and says
    `complete: false` until the last run is made."""
    started = datetime.now(UTC)
    document: dict[str, Any] = {
        "version": 1,
        "complete": False,
        "date": started.date().isoformat(),
        "started": started.isoformat(timespec="seconds"),
        "machine": machine_facts(),
        "settings": {
            "sessions": sessions,
            "calls_each": calls,
            "sequential_calls": sequential,
            "sizes": list(sizes),
            "processes": processes,
            "max_run_s": MAX_RUN_S,
            "payload_tokens": {str(size): token_count(size) for size in sizes},
            "container": limits() if any(not t.direct for t in targets) and restart else None,
        },
        "targets": {},
    }

    def save() -> None:
        if checkpoint:
            checkpoint(document)

    try:
        for target in targets:
            entry: dict[str, Any] = {
                "label": target.label,
                "gateway": None,
                "runs": [],
                "sequential": [],
            }
            document["targets"][target.key] = entry
            for size in sizes:
                # A fresh gateway for each payload, so that what one run did to the process (a
                # session lost, a queue grown) is not in the next. The run with one session comes
                # first, and warms the process for the one with many.
                if restart and not target.direct:
                    entry["gateway"] = configure(target)
                if sequential:
                    print(f"== {target.key}, {size} bytes, 1 x {sequential}", file=sys.stderr)
                    alone = await measure(target, size, 1, sequential, 1, sample=False)
                    alone["conditions"] = wait_until_quiet() if quiet else None
                    entry["sequential"].append(alone)
                    show(target.key, alone)
                    save()
                print(f"== {target.key}, {size} bytes, {sessions} x {calls}", file=sys.stderr)
                conditions = wait_until_quiet() if quiet else None
                run_ = await measure(target, size, sessions, calls, processes, sample)
                run_["conditions"] = conditions
                entry["runs"].append(run_)
                show(target.key, run_)
                save()
    except BaseException as error:
        document["error"] = f"{type(error).__name__}: {error}"
        save()
        raise
    document["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    document["complete"] = True
    save()
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the performance matrix")
    parser.add_argument("--targets", nargs="*", choices=list(BY_KEY), default=list(BY_KEY))
    parser.add_argument("--sizes", nargs="*", type=int, default=list(SIZES))
    parser.add_argument("--sessions", type=int, default=SESSIONS)
    parser.add_argument("--calls", type=int, default=CALLS)
    parser.add_argument("--sequential", type=int, default=SEQUENTIAL_CALLS)
    parser.add_argument("--processes", type=int, default=PROCESSES)
    parser.add_argument("--smoke", action="store_true", help="10 x 5 against the stack as it runs")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.smoke:
        targets = [BY_KEY["direct"], Target("stack", "Keystone as the stack runs", {}, {})]
        document = asyncio.run(
            matrix(targets, [1024], 10, 5, 0, 1, quiet=False, restart=False, sample=False)
        )
        failures = [
            f"{key}: {run_['errors']}"
            for key, entry in document["targets"].items()
            for run_ in entry["runs"]
            if run_["errors"] or run_["opened"] != run_["sessions"]
        ]
    else:
        targets = [BY_KEY[key] for key in args.targets]
        out = args.out or RESULTS / f"perf-{datetime.now(UTC).date().isoformat()}.json"
        if out.exists():
            print(
                f"refused: {out} exists, and a result file is never written over", file=sys.stderr
            )
            return 2

        def write(partial: dict[str, Any]) -> None:
            out.write_text(json.dumps(partial), encoding="utf-8")

        try:
            asyncio.run(
                matrix(
                    targets,
                    args.sizes,
                    args.sessions,
                    args.calls,
                    args.sequential,
                    args.processes,
                    checkpoint=write,
                )
            )
        finally:
            restore()
        failures = []
        print(f"written to {out}", file=sys.stderr)
    for failure in failures:
        print(f"FAILED {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
