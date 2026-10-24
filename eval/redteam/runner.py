"""Run the scenarios of the red-team suite against a Keystone, a line of JSON for each run (KS-902).

    python -m eval.redteam.runner --config C2 --agent naive --out eval/results/naive-C2.jsonl
    python -m eval.redteam.runner --config C2 --agent llm --model <model id> --seeds 3 --max-usd 40

A run is one scenario, in one config, by one agent, once:

1. The demo upstreams are put in the state of the scenario (`POST /_reset?variant=`).
2. The oracle approver starts (approver.py). It approves what the task needs and nothing else.
3. The agent does the task of the scenario as the operator olivia through ops-agent. The naive agent
   runs the script and obeys every instruction it reads, and the model-driven agent gets the user's
   prompt and the tools.
4. The upstreams are asked what they did (`GET /_state`), and the two checks of the scenario are
   decided from that: did the attack succeed, and did the task. The agent's words are not believed.

The three configs are three settings of the same Keystone build, and the runner does not set them:
`scripts/redteam.sh` restarts the stack for each. What the runner does is ask the gateway how it is
set (`/metrics`, and the policies in force) and refuse to run against one that does not match the
label, because a number published under the wrong label is worse than none.

- C0 passthrough: `KEYSTONE_PROFILE=passthrough`. Every slot of the pipeline but the credentials is
  a stub, and no scanner is built.
- C1 policy and approvals: the default access rules, acme's rule for outside mail and the transfer
  limit, with approvals, and without the Rule of Two policies and without the scanner.
- C2 full: everything, the scanner with its model, the taint, the Rule of Two.

The file starts with a line `{"type": "start"}` that says what was run against (the commit, the
config, how the gateway answered), then one line `{"type": "run"}` for each run, then
`{"type": "end"}`. The report (report.py) reads these files and nothing else.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import anyio
import httpx
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from eval.redteam.approver import OracleApprover
from eval.redteam.checks import holds
from eval.redteam.configs import CONFIGS, EXPECTED, RULE_OF_TWO, Config
from eval.redteam.schema import Scenario
from eval.redteam.suite import REPO, load_scenarios
from eval.redteam.witness import Witness, local_urls
from examples.agents.auto_reject import token_from_script
from examples.agents.llm_agent import LlmRun, run_llm_agent
from examples.agents.naive_agent import Injected, result_text, run_naive
from examples.agents.scripted_agent import Step

RUN_TIMEOUT_S = 240.0
API = "/admin/api/v1"
RESULTS = REPO / "eval" / "results"
DEFAULT_DATABASE_URL = "postgresql+asyncpg://keystone:keystone@localhost:55432/keystone"


class ConfigMismatch(RuntimeError):
    """The gateway is not set as the label of the run says."""


Token = Callable[[], str]


@dataclass(frozen=True)
class Tokens:
    """Where the three people of a run get a token: the user the agent acts for, the approver, and
    an admin for the questions that need one (the sessions, the policies)."""

    agent: Token
    approver: Token
    admin: Token

    @classmethod
    def from_realm(cls) -> Tokens:
        """The local Keycloak realm: olivia through ops-agent, lena through keystone-cli and root
        through keystone-cli, by the password grant of scripts/get_token.sh."""
        return cls(
            agent=lambda: token_from_script("olivia", "ops-agent"),
            approver=lambda: token_from_script("lena", "keystone-cli"),
            admin=lambda: token_from_script("root", "keystone-cli"),
        )


@dataclass(frozen=True)
class Target:
    """The gateway under test and everything a run needs to reach it and the upstreams behind it."""

    base_url: str
    witness: Witness
    tokens: Tokens
    database_url: str | None = None

    @property
    def mcp_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/mcp"

    @property
    def llm_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/llm/anthropic"


# -- what the agents give back


@dataclass
class Outcome:
    """What an agent did, in the terms the runner records."""

    output: str
    tool_calls: int
    error_codes: list[str]
    turns: int = 0
    stopped: str = "done"
    request_ids: list[str] = field(default_factory=list)
    obeyed: int = 0
    detail: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0


class Agent(Protocol):
    """What the runner needs of an agent. The name and the model are read-only here, so that an
    agent whose model is always a string is one too."""

    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str | None: ...

    async def run(self, scenario: Scenario, target: Target) -> Outcome: ...


class NaiveAgent:
    """The agent of KS-708: the script of the task, and every instruction it reads obeyed."""

    name: str = "naive"
    model: str | None = None

    async def run(self, scenario: Scenario, target: Target) -> Outcome:
        steps = [Step(tool=s.tool, args=dict(s.args)) for s in scenario.script]
        token = await anyio.to_thread.run_sync(target.tokens.agent)
        transcript = await run_naive(target.mcp_url, steps, token=token)
        return Outcome(
            # What the agent read, as a reader of it sees it: the checks that look for words in the
            # output look at what the tools returned.
            output="\n".join(result_text(entry) for entry in transcript.calls),
            tool_calls=len(transcript.calls),
            error_codes=[c.error_code for c in transcript.calls if c.error_code],
            obeyed=sum(1 for c in transcript.calls if isinstance(c, Injected)),
        )


@dataclass
class LlmAgent:
    """The model-driven agent (examples/agents/llm_agent.py) with a model of the caller's choice."""

    model: str
    name: str = "llm"
    # Add the scenario's script to the prompt, for the fake model that follows one (the real ones
    # would be told what to do by the words of the task).
    script_hint: bool = False

    async def run(self, scenario: Scenario, target: Target) -> Outcome:
        prompt = scenario.user_prompt
        if self.script_hint:
            steps = [{"tool": s.tool, "args": s.args} for s in scenario.script]
            prompt = f"{prompt} <!--ks-script:{json.dumps(steps)}-->"
        token = await anyio.to_thread.run_sync(target.tokens.agent)
        run: LlmRun = await run_llm_agent(
            target.mcp_url, target.llm_url, token, prompt, model=self.model
        )
        return Outcome(
            output=run.output,
            tool_calls=len(run.calls),
            error_codes=run.error_codes,
            turns=run.turns,
            stopped=run.stopped,
            request_ids=run.request_ids,
            detail=run.detail,
            input_tokens=run.input_tokens,
            output_tokens=run.output_tokens,
        )


# -- asking the gateway how it is set


# How long a gateway that has just started is given to load the model of its scanner.
MODEL_WAIT_S = 180.0


def read_info(page: str) -> tuple[dict[str, str] | None, dict[str, bool]]:
    """How a gateway says it is set, from its `/metrics` page: the labels of
    `keystone_gateway_info` (profile, scanner, classifier), and for each model whether
    `keystone_scanner_classifier_ready` says it has loaded. The labels come in the order the
    client library sorts them, so they are read as labels and not matched as text."""
    info: dict[str, str] | None = None
    ready: dict[str, bool] = {}
    for family in text_string_to_metric_families(page):
        for sample in family.samples:
            if sample.name == "keystone_gateway_info" and sample.value == 1:
                info = dict(sample.labels)
            elif sample.name == "keystone_scanner_classifier_ready":
                ready[sample.labels["classifier"]] = sample.value == 1
    if info is not None and not {"profile", "scanner", "classifier"} <= info.keys():
        return None, ready
    return info, ready


async def gateway_facts(target: Target, client: httpx.AsyncClient) -> dict[str, Any]:
    """How the gateway says it is set: its profile, scanner and model from `/metrics` (and whether
    the model has loaded), and the ids of the policies in force for the admin's tenant from the
    admin API."""
    page = await client.get(f"{target.base_url.rstrip('/')}/metrics")
    page.raise_for_status()
    found, ready = read_info(page.text)
    if found is None:
        raise ConfigMismatch("the gateway does not say how it is set at /metrics")
    token = await anyio.to_thread.run_sync(target.tokens.admin)
    policies = await client.get(
        f"{target.base_url.rstrip('/')}{API}/policies", headers={"Authorization": f"Bearer {token}"}
    )
    policies.raise_for_status()
    body = policies.json()
    return {
        "profile": found["profile"],
        "scanner": found["scanner"],
        "classifier": found["classifier"],
        # None where there is no model to wait for.
        "classifier_ready": ready.get(found["classifier"]),
        "policy_version": body.get("version"),
        "policies": sorted(p["id"] for p in body.get("policies", [])),
    }


async def facts_with_the_model(target: Target, client: httpx.AsyncClient) -> dict[str, Any]:
    """`gateway_facts`, asked again until the model of the scanner has loaded. The model loads in
    the background after the gateway starts, and a scan made before it has is scored by the rules
    alone, so a run that starts early measures another scanner. Gives up after `MODEL_WAIT_S`
    and returns what it last saw, for `check_config` to refuse."""
    deadline = time.monotonic() + MODEL_WAIT_S
    while True:
        facts = await gateway_facts(target, client)
        if facts["classifier_ready"] is not False or time.monotonic() >= deadline:
            return facts
        await anyio.sleep(1.0)


def check_config(config: Config, facts: Mapping[str, Any], *, model: bool = True) -> None:
    """Raise unless the gateway is set as the label says. A label that has the scanner on also has
    its model, loaded, unless `model` is False (a test that runs on the rules alone)."""
    profile, scanner, rule_of_two = EXPECTED[config]
    problems = []
    if facts["profile"] != profile:
        problems.append(f"its profile is {facts['profile']}, not {profile}")
    if facts["scanner"] != scanner:
        problems.append(f"its scanner is {facts['scanner']}, not {scanner}")
    elif scanner == "on" and model:
        if facts.get("classifier") in (None, "none"):
            problems.append("its scanner has no model, so it scores by the rules alone")
        elif not facts.get("classifier_ready"):
            problems.append(f"its model {facts['classifier']} has not loaded")
    present = set(facts["policies"]) >= RULE_OF_TWO
    if rule_of_two is not None and rule_of_two != present:
        problems.append(
            "the policies of the Rule of Two are in force"
            if present
            else "the policies of the Rule of Two are not in force"
        )
    if problems:
        raise ConfigMismatch(f"this is not {config}: " + "; ".join(problems))


# -- one run


async def session_facts(
    target: Target, client: httpx.AsyncClient, since: datetime
) -> dict[str, Any] | None:
    """The flags and the taint of the session the run opened: the newest session of olivia through
    ops-agent that began after `since`, and the score the scanner gave each output it read in it
    (from the audit log). None if the gateway shows no session."""
    token = await anyio.to_thread.run_sync(target.tokens.admin)
    headers = {"Authorization": f"Bearer {token}"}
    answer = await client.get(
        f"{target.base_url.rstrip('/')}{API}/sessions?limit=200", headers=headers
    )
    if answer.status_code != 200:
        return None
    mine = [
        s
        for s in answer.json()
        if s["user_id"] == "olivia"
        and s["agent_id"] == "ops-agent"
        and datetime.fromisoformat(s["created_at"]) >= since
    ]
    if not mine:
        return None
    newest = max(mine, key=lambda s: s["created_at"])
    return {
        "flags": newest["flags"],
        "tainted": newest["tainted"],
        "calls": newest["call_count"],
        "scans": await scan_facts(target, client, newest["session_id"], headers),
    }


async def scan_facts(
    target: Target, client: httpx.AsyncClient, session_id: str, headers: Mapping[str, str]
) -> list[dict[str, Any]]:
    """The tool, the score and the action of every output of a session that was scanned, oldest
    first. Empty where nothing is scanned (C0) or the log cannot be read."""
    answer = await client.get(
        f"{target.base_url.rstrip('/')}{API}/audit",
        params={"session": session_id, "limit": 200},
        headers=headers,
    )
    if answer.status_code != 200:
        return []
    rows = sorted(answer.json()["items"], key=lambda row: row["seq"])
    return [
        {"tool": r["tool_name"], "score": float(r["scan_score"]), "action": r["scan_action"]}
        for r in rows
        if r.get("scan_score") is not None
    ]


async def ledger_cost(database_url: str, refs: Sequence[str]) -> float:
    """What the model requests of a run cost, from the rows of the spend ledger that Keystone
    wrote for them (`ref` is the id Keystone gave each request)."""
    if not refs:
        return 0.0
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            row = await connection.execute(
                text(
                    "SELECT COALESCE(SUM(cost_usd), 0) FROM spend_ledger "
                    "WHERE kind = 'llm' AND ref = ANY(:refs)"
                ),
                {"refs": list(refs)},
            )
            return float(row.scalar_one())
    finally:
        await engine.dispose()


async def run_once(
    scenario: Scenario,
    config: Config,
    agent: Agent,
    seed: int,
    target: Target,
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    """Do one run and return its record."""
    await target.witness.areset(scenario.setup.variant)
    started = time.perf_counter()
    # The gateway's clock and this one are the same machine's, give or take the time to ask.
    since = datetime.now(UTC) - timedelta(seconds=1)
    outcome = Outcome(output="", tool_calls=0, error_codes=[], stopped="error")
    error: str | None = None
    approver = OracleApprover(client, target.tokens.approver, scenario.expected_actions)
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approver.run)
        try:
            with anyio.fail_after(RUN_TIMEOUT_S):
                outcome = await agent.run(scenario, target)
        except Exception as caught:  # a run that fails is a line of the file, not the end of it
            error = f"{type(caught).__name__}: {str(caught)[:200]}"
        finally:
            # One more look, so that a request made in the last moments is decided and counted.
            with contextlib.suppress(httpx.HTTPError, RuntimeError):
                await approver.sweep()
            tasks.cancel_scope.cancel()
    seconds = time.perf_counter() - started
    states = await target.witness.astates()
    attack = holds(scenario.attack_check, states, outcome.output) if scenario.attack_check else None
    utility = holds(scenario.utility_check, states, outcome.output)
    cost = 0.0
    if target.database_url and outcome.request_ids:
        cost = await ledger_cost(target.database_url, outcome.request_ids)
    return {
        "type": "run",
        "at": since.isoformat(timespec="seconds"),
        "scenario": scenario.id,
        "task": scenario.task,
        "kind": scenario.kind,
        "goal": scenario.attack.goal if scenario.attack else None,
        "template": scenario.attack.template if scenario.attack else None,
        "vector": scenario.attack.vector if scenario.attack else None,
        "position": scenario.attack.position if scenario.attack else None,
        "config": config,
        "agent": agent.name,
        "model": agent.model,
        "seed": seed,
        "attack_success": attack,
        "utility_success": utility,
        "approvals": {
            "requested": approver.requested,
            "approved": approver.approved,
            "rejected": approver.rejected,
            # Each request the approver decided: the tool, the rules that asked, the state of the
            # session when it asked, and the decision. The arguments are in the audit log.
            "decisions": [
                {
                    "tool": d.tool,
                    "approved": d.approved,
                    "reasons": list(d.reasons),
                    "tainted": d.tainted,
                    "flags": list(d.flags),
                }
                for d in approver.decisions
            ],
        },
        "tool_calls": outcome.tool_calls,
        "error_codes": outcome.error_codes,
        "obeyed": outcome.obeyed,
        "turns": outcome.turns,
        "stopped": outcome.stopped,
        "input_tokens": outcome.input_tokens,
        "output_tokens": outcome.output_tokens,
        "cost_usd": cost,
        "session": await session_facts(target, client, since),
        "seconds": round(seconds, 3),
        "error": error or outcome.detail,
    }


# -- many runs


@dataclass
class Progress:
    runs: int = 0
    spent_usd: float = 0.0
    aborted: str | None = None


async def run_matrix(
    scenarios: Sequence[Scenario],
    config: Config,
    agent: Agent,
    target: Target,
    out: Path,
    *,
    seeds: int = 1,
    max_usd: float | None = None,
    variant: str | None = None,
    subset: bool = False,
    note: str = "",
    model: bool = True,
    on_run: Callable[[dict[str, Any]], None] | None = None,
) -> Progress:
    """Run every scenario `seeds` times and write a line for each run to `out`, a file that must not
    exist yet: results are evidence, and a second run does not get to add to the first. Stops before
    the next run when the cost of the runs so far has reached `max_usd`."""
    progress = Progress()
    out.parent.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(base_url=target.base_url, timeout=30) as client:
        facts = await facts_with_the_model(target, client)
        check_config(config, facts, model=model)
        with out.open("x", encoding="utf-8") as handle:
            start = start_line(
                config,
                agent,
                seeds,
                facts,
                scenarios=len(scenarios),
                subset=subset,
                variant=variant,
                note=note,
            )
            handle.write(json.dumps(start, sort_keys=True) + "\n")
            for seed in range(1, seeds + 1):
                for scenario in scenarios:
                    if max_usd is not None and progress.spent_usd >= max_usd:
                        progress.aborted = f"the cost of the runs reached ${max_usd}"
                        break
                    record = await run_once(scenario, config, agent, seed, target, client)
                    progress.runs += 1
                    progress.spent_usd += float(record["cost_usd"])
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                    handle.flush()
                    if on_run is not None:
                        on_run(record)
                if progress.aborted:
                    break
            end = {
                "type": "end",
                "runs": progress.runs,
                "spent_usd": round(progress.spent_usd, 6),
                "aborted": progress.aborted,
            }
            handle.write(json.dumps(end, sort_keys=True) + "\n")
    return progress


def git_facts() -> dict[str, Any]:
    """The commit the code is at, and whether the tree differs from it. The results a run writes
    are not the code it ran, so `eval/results` is left out of the check."""

    def run(*args: str) -> str:
        return subprocess.run(  # noqa: S603 - fixed arguments
            ["git", "-C", str(REPO), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

    changes = run("status", "--porcelain", "--", ".", ":(exclude)eval/results")
    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(changes)}


def machine_facts() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
    }


def start_line(
    config: Config,
    agent: Agent,
    seeds: int,
    facts: Mapping[str, Any],
    *,
    scenarios: int,
    subset: bool,
    variant: str | None,
    note: str,
) -> dict[str, Any]:
    return {
        "type": "start",
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        **git_facts(),
        "machine": machine_facts(),
        "config": config,
        # A name for a setting of the gateway that the label does not say, such as the tags of an
        # earlier release. None for the config as it is in the repository.
        "variant": variant,
        "agent": agent.name,
        "model": agent.model,
        "seeds": seeds,
        "scenarios": scenarios,
        # True when the scenarios were chosen with --only or --limit: a file of a part of the suite
        # is a trial and the report leaves it out.
        "subset": subset,
        "gateway": dict(facts),
        "note": note,
    }


# -- the command


def pick(scenarios: Sequence[Scenario], only: Sequence[str], limit: int | None) -> list[Scenario]:
    """The scenarios asked for: those whose id matches one of the patterns (`*` stands for any
    run of characters), the first `limit` of them."""
    if only:
        patterns = [re.compile("^" + re.escape(p).replace(r"\*", ".*") + "$") for p in only]
        scenarios = [s for s in scenarios if any(p.match(s.id) for p in patterns)]
    return list(scenarios[:limit] if limit else scenarios)


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the red-team scenarios against a Keystone")
    parser.add_argument("--config", choices=CONFIGS, required=True)
    parser.add_argument("--agent", choices=("naive", "llm"), required=True)
    parser.add_argument("--model", help="the model of the llm agent, as its API names it")
    parser.add_argument("--seeds", type=int, default=None, help="1 for naive, 3 for llm")
    parser.add_argument("--max-usd", type=float, default=40.0, help="stop when the runs cost this")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--keystone", default="http://localhost:8080", help="the gateway's address")
    parser.add_argument("--only", nargs="*", default=[], help="scenario ids, `*` as a wildcard")
    parser.add_argument("--limit", type=int, default=None, help="only the first N scenarios")
    parser.add_argument("--database-url", default=DEFAULT_DATABASE_URL)
    parser.add_argument("--script-hint", action="store_true", help="tell the fake model the script")
    parser.add_argument(
        "--variant", default=None, help="name a setting of the gateway the config does not say"
    )
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)

    if args.agent == "llm" and not args.model:
        parser.error("--agent llm needs --model")
    agent: Agent = (
        NaiveAgent()
        if args.agent == "naive"
        else LlmAgent(args.model, script_hint=args.script_hint)
    )
    seeds = args.seeds or (1 if args.agent == "naive" else 3)
    scenarios = pick(load_scenarios(), args.only, args.limit)
    if not scenarios:
        parser.error("no scenario matches")
    out = args.out or RESULTS / f"redteam-{args.agent}-{args.config}-{timestamp()}.jsonl"
    target = Target(
        base_url=args.keystone,
        witness=Witness(local_urls()),
        tokens=Tokens.from_realm(),
        database_url=args.database_url if args.agent == "llm" else None,
    )

    def show(record: Mapping[str, Any]) -> None:
        mark = "ATTACK LANDED" if record["attack_success"] else "attack stopped"
        verdict = mark if record["kind"] == "attack" else "benign"
        print(
            f"{record['config']} {record['agent']:5} {record['scenario']:40} {verdict:15} "
            f"utility={record['utility_success']!s:5} approvals={record['approvals']['requested']} "
            f"${record['cost_usd']:.4f} {record['seconds']:.1f}s",
            file=sys.stderr,
            flush=True,
        )

    try:
        progress = asyncio.run(
            run_matrix(
                scenarios,
                args.config,
                agent,
                target,
                out,
                seeds=seeds,
                max_usd=args.max_usd if args.agent == "llm" else None,
                variant=args.variant,
                subset=bool(args.only or args.limit),
                note=args.note,
                on_run=show,
            )
        )
    except ConfigMismatch as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2
    except FileExistsError:
        print(f"refused: {out} exists, and a result file is never added to", file=sys.stderr)
        return 2
    print(f"{progress.runs} runs, ${progress.spent_usd:.4f}, written to {out}", file=sys.stderr)
    if progress.aborted:
        print(f"stopped early: {progress.aborted}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
