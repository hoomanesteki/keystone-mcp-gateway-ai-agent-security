"""The tracer the pipeline wraps every call in. Phase 5 adds an OpenTelemetry implementation."""

from __future__ import annotations

import contextlib
from contextlib import AbstractContextManager
from typing import Protocol

SpanValue = str | int | float | bool


class Tracer(Protocol):
    def span(self, name: str, **attrs: SpanValue) -> AbstractContextManager[None]: ...


class NoopTracer:
    def span(self, name: str, **attrs: SpanValue) -> AbstractContextManager[None]:
        return contextlib.nullcontext()
