"""An approver who turns down everything (KS-705).

    python -m examples.agents.auto_reject --url http://localhost:8080 --note "not this time"

It signs in as lena, the approver of the local realm, polls the admin API for approval requests
that are waiting, and rejects each one with a note. It stands for the person in the Phase 7 demo:
the naive agent obeys an injected instruction, Keystone holds the call for a person, and this
approver says no to whatever reaches the queue. If Keystone stops the naive agent, it does so
without depending on a person being careful.

For every request it prints one line of JSON with what a person would see on the approval card:
the tool and its risk, the reasons, whether the session is tainted, the flags of the session and
the arguments. A smoke script reads those lines to check that the approval said why it was needed.

The token comes from `--token`, from KEYSTONE_APPROVER_TOKEN, or from scripts/get_token.sh (the
password grant of the local realm, for development). A token lives five minutes, so a long run
asks for a new one when the API answers 401.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import anyio
import httpx2

REPO = Path(__file__).resolve().parents[2]
TOKEN_SCRIPT = REPO / "scripts" / "get_token.sh"
TOKEN_ENV = "KEYSTONE_APPROVER_TOKEN"  # noqa: S105 - the name of the variable, not a token
API = "/admin/api/v1"
DEFAULT_NOTE = "rejected by the auto-reject approver"
REQUEST_TIMEOUT_S = 15.0
TOKEN_TIMEOUT_S = 30.0

Token = Callable[[], str]


class AuthError(RuntimeError):
    """The API refused the token, or no token could be had."""


def token_from_script(user: str = "lena", client: str = "keystone-cli") -> str:
    """A fresh access token for `user`, from the development script. It needs the stack up."""
    done = subprocess.run(  # noqa: S603 - fixed arguments, the repository's own script
        ["bash", str(TOKEN_SCRIPT), user, client],  # noqa: S607 - bash is looked up on PATH
        capture_output=True,
        text=True,
        timeout=TOKEN_TIMEOUT_S,
        cwd=REPO,
        check=False,
    )
    token = done.stdout.strip()
    if done.returncode != 0 or not token:
        raise AuthError(f"no token for {user}: {done.stderr.strip() or 'the script printed none'}")
    return token


def card(item: dict[str, Any], note: str, status: str) -> dict[str, Any]:
    """What a person sees on the approval card, as one object for a smoke script to read."""
    return {
        "id": item["id"],
        "status": status,
        "tool": item["tool"],
        "risk": item.get("risk"),
        "reasons": sorted(item.get("reasons", [])),
        "tainted": bool(item.get("tainted")),
        "flags": sorted(item.get("flags", [])),
        "arguments": item.get("arguments"),
        "requested_by": item.get("requested_by_user"),
        "session_id": item.get("session_id"),
        "note": note,
    }


class AutoReject:
    """Rejects every pending request once. `sweep` does one pass and `run` repeats it."""

    def __init__(
        self,
        client: httpx2.AsyncClient,
        token: Token,
        *,
        note: str = DEFAULT_NOTE,
        emit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._client = client
        self._token = token
        self._note = note
        self._emit = emit or (lambda line: print(json.dumps(line, sort_keys=True), flush=True))
        self._bearer: str | None = None
        self.rejected: list[dict[str, Any]] = []

    async def sweep(self) -> list[dict[str, Any]]:
        """Reject what is waiting now. Returns the cards of the requests it rejected. A request
        that someone else decided first (409) is not an error."""
        done = []
        for item in await self._pending():
            answer = await self._send("POST", f"/approvals/{item['id']}/decision")
            if answer.status_code == 409:
                continue
            answer.raise_for_status()
            line = card(item, self._note, str(answer.json().get("status", "rejected")))
            self.rejected.append(line)
            self._emit(line)
            done.append(line)
        return done

    async def run(self, interval_s: float = 0.5, duration_s: float | None = None) -> None:
        """Sweep until `duration_s` have passed, or until cancelled. A pass that fails (the stack
        restarting, a token that cannot be had) is reported on stderr and tried again."""
        with anyio.move_on_after(duration_s if duration_s else None):
            while True:
                try:
                    await self.sweep()
                except (httpx2.HTTPError, AuthError) as error:
                    print(f"auto_reject: {type(error).__name__}: {error}", file=sys.stderr)
                await anyio.sleep(interval_s)

    async def _pending(self) -> list[dict[str, Any]]:
        answer = await self._send("GET", "/approvals?status=pending")
        answer.raise_for_status()
        found: list[dict[str, Any]] = answer.json()
        return found

    async def _send(self, method: str, path: str) -> httpx2.Response:
        """One call to the admin API. A 401 gets one new token and one more try."""
        body = {"approve": False, "note": self._note} if method == "POST" else None
        for attempt in (1, 2):
            if self._bearer is None:
                self._bearer = await anyio.to_thread.run_sync(self._token)
            answer = await self._client.request(
                method,
                f"{API}{path}",
                json=body,
                headers={"Authorization": f"Bearer {self._bearer}"},
            )
            if answer.status_code != 401 or attempt == 2:
                return answer
            self._bearer = None
        raise AuthError("the API refused a new token")  # unreachable, for the type checker


def parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reject every approval request that is waiting")
    parser.add_argument("--url", default="http://localhost:8080", help="Keystone's address")
    parser.add_argument("--note", default=DEFAULT_NOTE, help="what the agent is told")
    parser.add_argument("--interval", type=float, default=0.5, help="seconds between polls")
    parser.add_argument("--duration", type=float, default=0.0, help="stop after this many seconds")
    parser.add_argument("--token", default=os.environ.get(TOKEN_ENV), help=f"or ${TOKEN_ENV}")
    parser.add_argument("--user", default="lena")
    parser.add_argument("--client", default="keystone-cli")
    return parser.parse_args(argv)


async def serve(args: argparse.Namespace) -> None:
    token: Token = (
        (lambda: str(args.token))
        if args.token
        else (lambda: token_from_script(args.user, args.client))
    )
    async with httpx2.AsyncClient(
        base_url=args.url.removesuffix("/mcp").rstrip("/"),
        timeout=httpx2.Timeout(REQUEST_TIMEOUT_S),
    ) as client:
        await AutoReject(client, token, note=args.note).run(args.interval, args.duration or None)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        asyncio.run(serve(parse(argv)))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
