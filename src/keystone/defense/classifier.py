"""A classifier that scores text for injection, behind the rules (KS-702).

The scanner asks a classifier for a number between 0 and 1, the chance that a text is an
injection. A classifier that cannot answer in time returns None, and the scanner goes on with the
rules alone.
"""

from __future__ import annotations

from typing import Protocol


class Classifier(Protocol):
    """Names itself in `ScanResult.model`, and scores a text."""

    name: str

    async def score(self, text: str) -> float | None: ...
