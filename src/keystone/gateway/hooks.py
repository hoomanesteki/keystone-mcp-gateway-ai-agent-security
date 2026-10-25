"""Marks a hook that does nothing, so the pipeline does not open a span for it.

A call opened a span for each of the two hooks of each of the nine slots, and eight to nine of
those hooks were `return None`. A span is about 100 microseconds of the gateway's CPU (made, ended,
encoded and sent), which is a tenth of what a call cost (KS-992). The pipeline still runs the hook
and still counts its time; only the span is left out.

`tests/unit/test_noop_hooks.py` holds that every function marked here has nothing in its body, so a
hook that later gains a line cannot keep the mark and run without a trace.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

NOOP_ATTR = "keystone_noop_hook"


def noop_hook[Hook: Callable[..., Any]](hook: Hook) -> Hook:
    setattr(hook, NOOP_ATTR, True)
    return hook


def is_noop(hook: Callable[..., object]) -> bool:
    return bool(getattr(hook, NOOP_ATTR, False))
