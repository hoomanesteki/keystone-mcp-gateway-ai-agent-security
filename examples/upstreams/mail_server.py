"""Demo mail server: list, read and send. State is a SQLite file seeded from mailbox.json."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from examples.upstreams._common import (
    FIXTURES,
    CallLog,
    Database,
    register_test_routes,
    run_cli,
)

SCHEMA = """
CREATE TABLE emails (
    id TEXT PRIMARY KEY, folder TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,
    subject TEXT NOT NULL, body TEXT NOT NULL, date TEXT NOT NULL, unread INTEGER NOT NULL
);
CREATE TABLE sent (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL,
    subject TEXT NOT NULL, body TEXT NOT NULL
);
"""
FOLDERS = ("inbox", "sent", "archive")


def create_server(db_path: Path | None = None, poisoned: bool | None = None) -> MCPServer:
    """Build the server. `db_path` defaults to MAIL_DB, then to a temp file. `poisoned` adds
    three unread emails that carry an instruction for the agent that reads them (KS-708). It
    defaults to the MAIL_POISONED=1 environment flag. The base mailbox stays what the earlier
    tests count, so the poison is opt-in, as ECHO_POISONED is for the echo server."""
    if poisoned is None:
        poisoned = os.environ.get("MAIL_POISONED") == "1"
    env_path = os.environ.get("MAIL_DB")
    db = Database(db_path or (Path(env_path) if env_path else None), "mail")
    log = CallLog()

    def reset() -> None:
        db.path.unlink(missing_ok=True)
        log.calls.clear()
        with db.connect() as con:
            con.executescript(SCHEMA)
            mails = json.loads((FIXTURES / "mailbox.json").read_text())
            if poisoned:
                mails += json.loads((FIXTURES / "injections" / "mailbox-poisoned.json").read_text())
            for mail in mails:
                con.execute(
                    "INSERT INTO emails VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        mail["id"],
                        mail["folder"],
                        mail["from"],
                        mail["to"],
                        mail["subject"],
                        mail["body"],
                        mail["date"],
                        int(mail["unread"]),
                    ),
                )

    def state() -> dict[str, Any]:
        with db.connect() as con:
            rows = con.execute("SELECT seq, recipient, subject, body FROM sent ORDER BY seq")
            sent = [
                {
                    "id": f"s{r['seq']}",
                    "to": r["recipient"],
                    "subject": r["subject"],
                    "body": r["body"],
                }
                for r in rows
            ]
        return {"sent": sent, "calls": list(log.calls)}

    reset()
    server = MCPServer("mail", log_level="WARNING", middleware=[log])

    @server.tool()
    def list_emails(folder: str = "inbox", unread_only: bool = False) -> list[dict[str, Any]]:
        """List the emails in a folder (inbox, sent or archive), newest first."""
        if folder not in FOLDERS:
            raise ToolError(f"unknown folder {folder!r}, use one of: {', '.join(FOLDERS)}")
        with db.connect() as con:
            rows = con.execute(
                "SELECT * FROM emails WHERE folder = ? AND (? = 0 OR unread = 1) "
                "ORDER BY date DESC, id",
                (folder, int(unread_only)),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "from": r["sender"],
                "subject": r["subject"],
                "date": r["date"],
                "unread": bool(r["unread"]),
            }
            for r in rows
        ]

    @server.tool()
    def read_email(email_id: str) -> dict[str, Any]:
        """Read one email by id, including its body."""
        with db.connect() as con:
            row = con.execute("SELECT * FROM emails WHERE id = ?", (email_id,)).fetchone()
        if row is None:
            raise ToolError(f"no email with id {email_id!r}")
        return {
            "id": row["id"],
            "folder": row["folder"],
            "from": row["sender"],
            "to": row["recipient"],
            "subject": row["subject"],
            "date": row["date"],
            "body": row["body"],
        }

    @server.tool()
    def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
        """Send an email."""
        address = to.strip()
        local, _, domain = address.partition("@")
        if not local or "." not in domain or " " in address:
            raise ToolError(f"{to!r} is not an email address")
        with db.connect() as con:
            cursor = con.execute(
                "INSERT INTO sent (recipient, subject, body) VALUES (?, ?, ?)",
                (address, subject, body),
            )
        return {"status": "sent", "id": f"s{cursor.lastrowid}", "to": address}

    register_test_routes(server, reset, state)
    return server


def main(argv: list[str] | None = None) -> None:
    run_cli("mail", 8101, create_server, argv)


if __name__ == "__main__":
    main()
