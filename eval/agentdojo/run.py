"""Run AgentDojo against a model with Keystone's output defense in the pipeline (KS-904).

    uv run --with agentdojo==0.1.35 python -m eval.agentdojo.run \
        --suite workspace --model <model> --attack important_instructions

It does what AgentDojo's own `python -m agentdojo.scripts.benchmark` does, with one difference: the
defense is Keystone's, which that script cannot take (its `--defense` is one of a fixed list). The
pipeline is the one AgentDojo builds for a model with no defense, and the element of
`eval.agentdojo.keystone` is put in its tools loop after the tools have run and before the model is
asked again, where AgentDojo's own detectors go.

A model needs a key (the variables AgentDojo reads for its provider, such as OPENAI_API_KEY or
ANTHROPIC_API_KEY, from the environment or a `.env` file), a running Keystone with the scanner on,
and a token of an admin of its tenant (`--user`, a user of the local realm). Nothing runs without
them, and the results this repository publishes for AgentDojo are blank until someone has a model to
run: `docs/results.md` says so, and `eval/agentdojo/NOTES.md` has the command and the version.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path
from typing import Any

from eval.agentdojo.keystone import (
    AGENTDOJO_VERSION,
    KeystoneScanner,
    add_to_pipeline,
    build_element,
)


def parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AgentDojo with Keystone's output defense")
    parser.add_argument("--suite", required=True, help="workspace, banking, travel or slack")
    parser.add_argument("--model", required=True, help="a model of agentdojo.models.ModelsEnum")
    parser.add_argument("--model-id", default=None, help="the model id of a local model")
    parser.add_argument("--attack", default=None, help="an attack of AgentDojo, or none")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--logdir", type=Path, default=Path("runs"))
    parser.add_argument("--user-task", "-ut", action="append", default=[], dest="user_tasks")
    parser.add_argument(
        "--injection-task", "-it", action="append", default=[], dest="injection_tasks"
    )
    parser.add_argument("--force-rerun", "-f", action="store_true")
    parser.add_argument("--keystone", default="http://localhost:8080", help="the gateway's address")
    parser.add_argument("--user", default="root", help="an admin of the local realm")
    parser.add_argument("--client", default="keystone-cli", help="the OAuth client for --user")
    parser.add_argument("--risk", default="medium", help="the risk Keystone gives a tool's output")
    parser.add_argument(
        "--no-defense", action="store_true", help="the same run with no defense, for the baseline"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse(argv)
    try:
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
        from agentdojo.attacks.attack_registry import load_attack
        from agentdojo.benchmark import (
            benchmark_suite_with_injections,
            benchmark_suite_without_injections,
        )
        from agentdojo.logging import OutputLogger
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo.types import get_text_content_as_str, text_content_block_from_string
    except ImportError:
        print(
            f"AgentDojo {AGENTDOJO_VERSION} is not installed: see eval/agentdojo/NOTES.md",
            file=sys.stderr,
        )
        return 2
    installed = version("agentdojo")
    if installed != AGENTDOJO_VERSION:
        print(
            f"this was written for AgentDojo {AGENTDOJO_VERSION} and {installed} is installed",
            file=sys.stderr,
        )

    try:
        pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=args.model,
                model_id=args.model_id,
                defense=None,
                tool_delimiter="tool",
                system_message_name=None,
                system_message=None,
                tool_output_format=None,
            )
        )
    except Exception as error:  # the client of the provider says what is missing, such as a key
        print(f"no pipeline for {args.model}: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    element: Any = None
    if not args.no_defense:
        from examples.agents.auto_reject import token_from_script

        scanner = KeystoneScanner(
            args.keystone,
            lambda: token_from_script(args.user, args.client),
            risk=args.risk,
        )
        element = build_element(
            BasePipelineElement, scanner, get_text_content_as_str, text_content_block_from_string
        )
        add_to_pipeline(pipeline, element, ToolsExecutionLoop, ToolsExecutor)
        # AgentDojo finds the model's name in the name of the pipeline, so the name is kept.
        pipeline.name = f"{pipeline.name}-keystone"

    suite = get_suite(args.benchmark_version, args.suite)
    user_tasks = tuple(args.user_tasks) or None
    injection_tasks = tuple(args.injection_tasks) or None
    with OutputLogger(str(args.logdir), live=None):
        if args.attack is None:
            results = benchmark_suite_without_injections(
                pipeline,
                suite,
                user_tasks=user_tasks,
                logdir=args.logdir,
                force_rerun=args.force_rerun,
                benchmark_version=args.benchmark_version,
            )
        else:
            attacker = load_attack(args.attack, suite, pipeline)
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attacker,
                user_tasks=user_tasks,
                injection_tasks=injection_tasks,
                logdir=args.logdir,
                force_rerun=args.force_rerun,
                benchmark_version=args.benchmark_version,
            )
    utility = results["utility_results"].values()
    print(f"suite {args.suite}, model {args.model}, attack {args.attack}, pipeline {pipeline.name}")
    print(f"utility: {sum(utility)} of {len(utility)}")
    if args.attack is not None:
        security = results["security_results"].values()
        print(f"security (attacks that succeeded): {sum(security)} of {len(security)}")
    if element is not None:
        print(f"keystone scanned {element.counts.scanned} tool results: {element.counts.by_action}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
