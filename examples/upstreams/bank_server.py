"""Demo bank server: balances, transactions and transfers, in SQLite seeded from accounts.json."""

from __future__ import annotations

import json
import math
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
    variant_folders,
)

SCHEMA = """
CREATE TABLE accounts (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL, currency TEXT NOT NULL, balance_cents INTEGER NOT NULL
);
CREATE TABLE transactions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, account TEXT NOT NULL,
    date TEXT NOT NULL, description TEXT NOT NULL, amount_cents INTEGER NOT NULL
);
CREATE TABLE transfers (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, from_account TEXT NOT NULL, destination TEXT NOT NULL,
    amount_cents INTEGER NOT NULL, memo TEXT NOT NULL
);
"""
# Transfers get a fixed label instead of today's date, so results repeat from run to run.
TRANSFER_DATE = "transfer"


def to_cents(amount: float) -> int:
    if not math.isfinite(amount) or amount <= 0:
        raise ToolError("amount must be a positive number")
    cents = round(amount * 100)
    if abs(amount * 100 - cents) > 1e-6:
        raise ToolError("amount can have at most two decimal places")
    return cents


def create_server(db_path: Path | None = None) -> MCPServer:
    """Build the server. `db_path` defaults to BANK_DB, then to a temp file."""
    env_path = os.environ.get("BANK_DB")
    db = Database(db_path or (Path(env_path) if env_path else None), "bank")
    log = CallLog()

    def reset(variant: str | None = None) -> None:
        # A variant adds the transactions its folders list (`bank.json`) to the seed's (KS-901).
        folders = variant_folders(variant)
        db.path.unlink(missing_ok=True)
        log.calls.clear()
        seed = json.loads((FIXTURES / "accounts.json").read_text())
        for folder in folders:
            if (overlay := folder / "bank.json").is_file():
                seed["transactions"] += json.loads(overlay.read_text()).get("transactions", [])
        with db.connect() as con:
            con.executescript(SCHEMA)
            for a in seed["accounts"]:
                con.execute(
                    "INSERT INTO accounts VALUES (?, ?, ?, ?)",
                    (a["id"], a["owner"], a["currency"], a["balance_cents"]),
                )
            for t in seed["transactions"]:
                con.execute(
                    "INSERT INTO transactions (id, account, date, description, amount_cents) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (t["id"], t["account"], t["date"], t["description"], t["amount_cents"]),
                )

    def state() -> dict[str, Any]:
        with db.connect() as con:
            balances = {
                r["id"]: r["balance_cents"] / 100
                for r in con.execute("SELECT id, balance_cents FROM accounts ORDER BY id")
            }
            transfers = [
                {
                    "id": f"t{r['seq']}",
                    "from": r["from_account"],
                    "to": r["destination"],
                    "amount": r["amount_cents"] / 100,
                    "memo": r["memo"],
                }
                for r in con.execute("SELECT * FROM transfers ORDER BY seq")
            ]
        return {"balances": balances, "transfers": transfers, "calls": list(log.calls)}

    reset()
    server = MCPServer("bank", log_level="WARNING", middleware=[log])

    @server.tool()
    def get_balance(account: str) -> dict[str, Any]:
        """Get the balance of one account."""
        with db.connect() as con:
            row = con.execute("SELECT * FROM accounts WHERE id = ?", (account,)).fetchone()
        if row is None:
            raise ToolError(f"unknown account {account!r}")
        return {
            "account": row["id"],
            "owner": row["owner"],
            "currency": row["currency"],
            "balance": row["balance_cents"] / 100,
        }

    @server.tool()
    def list_transactions(account: str, limit: int = 10) -> list[dict[str, Any]]:
        """List the most recent transactions of an account, newest first. The limit is 1 to 100."""
        if not 1 <= limit <= 100:
            raise ToolError("limit must be between 1 and 100")
        with db.connect() as con:
            if con.execute("SELECT 1 FROM accounts WHERE id = ?", (account,)).fetchone() is None:
                raise ToolError(f"unknown account {account!r}")
            rows = con.execute(
                "SELECT id, date, description, amount_cents FROM transactions "
                "WHERE account = ? ORDER BY seq DESC LIMIT ?",
                (account, limit),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "date": r["date"],
                "description": r["description"],
                "amount": r["amount_cents"] / 100,
            }
            for r in rows
        ]

    @server.tool()
    def transfer(from_account: str, to: str, amount: float, memo: str = "") -> dict[str, Any]:
        """Move money out of an account. `to` is another account id or an external destination."""
        cents = to_cents(amount)
        with db.connect() as con:
            source = con.execute(
                "SELECT balance_cents FROM accounts WHERE id = ?", (from_account,)
            ).fetchone()
            if source is None:
                raise ToolError(f"unknown account {from_account!r}")
            if source["balance_cents"] < cents:
                raise ToolError("insufficient funds")
            con.execute(
                "UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?",
                (cents, from_account),
            )
            internal = con.execute("SELECT 1 FROM accounts WHERE id = ?", (to,)).fetchone()
            if internal is not None:
                con.execute(
                    "UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?",
                    (cents, to),
                )
            cursor = con.execute(
                "INSERT INTO transfers (from_account, destination, amount_cents, memo) "
                "VALUES (?, ?, ?, ?)",
                (from_account, to, cents, memo),
            )
            transfer_id = f"t{cursor.lastrowid}"
            entries = [("out", from_account, f"Transfer to {to}", -cents)]
            if internal is not None:
                entries.append(("in", to, f"Transfer from {from_account}", cents))
            for direction, account, description, signed in entries:
                con.execute(
                    "INSERT INTO transactions (id, account, date, description, amount_cents) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (f"tx-{transfer_id}-{direction}", account, TRANSFER_DATE, description, signed),
                )
        return {
            "status": "completed",
            "transfer_id": transfer_id,
            "from_account": from_account,
            "to": to,
            "amount": cents / 100,
            "memo": memo,
        }

    register_test_routes(server, reset, state, variants=True)
    return server


def main(argv: list[str] | None = None) -> None:
    run_cli("bank", 8103, create_server, argv)


if __name__ == "__main__":
    main()
