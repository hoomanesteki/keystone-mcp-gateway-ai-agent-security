"""KS-609: the browser test of the approval loop is set up as the story says."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = (ROOT / "console" / "playwright.config.ts").read_text()
SPEC = (ROOT / "console" / "e2e" / "approval.spec.ts").read_text()

pytestmark = pytest.mark.phase(6)


def test_the_test_runs_in_chromium_alone_and_starts_what_it_needs() -> None:
    assert 'name: "chromium"' in CONFIG
    assert "firefox" not in CONFIG and "webkit" not in CONFIG
    assert 'globalSetup: "./e2e/global-setup.ts"' in CONFIG
    assert re.search(r'webServer: \{\s+command: "pnpm dev"', CONFIG)
    # One bank and one stack: a retry would approve a second request against a bank that already
    # holds the transfer.
    assert "retries: 0" in CONFIG and "workers: 1" in CONFIG


def test_the_agent_script_is_the_transfer_the_test_approves() -> None:
    script = yaml.safe_load(
        (ROOT / "examples" / "agents" / "scripts" / "approval_demo.yaml").read_text()
    )

    first, second = script["steps"]

    assert first["tool"] == "bank__transfer"
    assert first["args"] == {
        "from_account": "CHK-001",
        "to": "SAV-002",
        "amount": 900,
        "memo": "invoice 4471",
    }
    assert second == {"tool": "keystone__await_approval"}
    # What the browser test looks for in the transcript and at the bank.
    assert '"amount": 900' in SPEC and "invoice 4471" in SPEC
    assert "CHK-001" in SPEC and "SAV-002" in SPEC


def test_the_test_waits_for_the_pending_answer_so_that_the_await_path_runs() -> None:
    """Keystone holds a call for 10 s. An approval inside that time finishes the first call and
    leaves the await tool nothing to do, so the test must see KS_APPROVAL_PENDING first."""
    compose = yaml.safe_load((ROOT / "deploy" / "keystone.compose.yaml").read_text())

    assert compose["approvals"]["wait_seconds"] == 10
    assert SPEC.index("KS_APPROVAL_PENDING") < SPEC.index('"Approve"')
    assert "answered KS_APPROVAL_PENDING; waited for approval" in SPEC


def test_the_gate_runs_the_console_checks_from_phase_six() -> None:
    makefile = (ROOT / "Makefile").read_text()

    assert re.search(r"^console-e2e:", makefile, re.MULTILINE)
    assert "if [ $(PHASE) -ge 6 ]; then $(MAKE) console-check console-e2e; fi" in makefile
    check = re.search(r"^check:(.*)$", makefile, re.MULTILINE)
    assert check is not None and "console-check" in check.group(1)
