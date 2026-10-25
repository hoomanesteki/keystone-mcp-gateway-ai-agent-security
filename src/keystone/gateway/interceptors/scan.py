"""The output slot: scan what a tool returned and taint the session that read an injection (KS-704).

After the upstream answers, the output goes through the scanner (`defense/scanner.py`). The slot
writes the scan on the call (`ctx.scan`, which the audit record keeps as `scan_score` and
`scan_action`), replaces the output with what the action for the tool's risk made of it, and
observes the score. An output that scores as an `injection` taints the session, whatever the
tool's tags are (plan section 3.5): the taint is what the Rule of Two policies read.

The taint is recorded with the store's own atomic change and the call's copy is then brought up to
date with what the store returned (ADR-0015). It is never recorded by saving the copy, because the
copy is as old as the start of the call.

The scanner cannot crash a call. `OutputScanner.inspect` handles a classifier that raises (the rules
decide) and rules that raise (the output goes on as it was, with `action="error"`), and counts both.
This slot repeats the second rule for a scanner that raises out of `inspect` anyway, because the
phase gate says an exception in scanning never costs a call. A session store that cannot record
the taint is another matter: it is not caught. The pipeline then withholds the output, so an output
that was found to be an injection and could not be recorded as one never reaches the agent.

Keystone's own tools are not scanned: their output is Keystone's. An error result from an upstream
is scanned, because the text of an error can quote what an attacker wrote (an error that repeats
its input). Only the flags slot leaves errors out, since a call that returned nothing read nothing.
"""

from __future__ import annotations

from collections.abc import Callable

import structlog

from keystone.core.types import CallContext, ScanResult, ToolResult
from keystone.defense.scanner import Inspection, OutputScanner
from keystone.gateway.hooks import noop_hook
from keystone.gateway.sessions import SessionStore, catch_up
from keystone.registry.naming import is_virtual
from keystone.telemetry.metrics import Metrics

log = structlog.get_logger()


class OutputScanInterceptor:
    name = "output_scan"

    def __init__(
        self,
        guard: OutputScanner | None,
        sessions: SessionStore | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        """`guard` is None when the scanner is switched off (`scanner.enabled`): nothing is
        scanned and nothing is recorded, so an audit record never says "pass" for a text that
        no one read. Without `sessions` the taint is set on the call's copy alone."""
        self._guard = guard
        self._sessions = sessions
        self._metrics = metrics

    @noop_hook
    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        result = ctx.result
        if self._guard is None or result is None or is_virtual(ctx.tool):
            return
        seen = await self._inspect(self._guard, ctx, result)
        ctx.scan = seen.scan
        ctx.result = seen.result
        # A scan that failed has no score to observe. The failure is counted where it happened.
        if seen.scan.action != "error":
            self._observe(ctx, seen.scan)
        if seen.scan.label == "injection":
            await self._taint(ctx)

    async def _inspect(
        self, guard: OutputScanner, ctx: CallContext, result: ToolResult
    ) -> Inspection:
        try:
            return await guard.inspect(result, ctx.tool, ctx.call_id)
        except Exception as error:
            # Cancellation is not an Exception and goes through. The log names the exception and
            # not what was being read, which is the content of a tool output.
            log.error("scanner_slot_failed", error=type(error).__name__, call_id=ctx.call_id)
            log.debug("scanner_slot_failed_detail", exc_info=True)
            self._count_failure("rules")
            return Inspection(result, ScanResult(score=0.0, label="benign", action="error"))

    async def _taint(self, ctx: CallContext) -> None:
        session = ctx.session
        new = not session.tainted
        if self._sessions is not None:
            changed = await self._sessions.mark_tainted(session.session_id)
            if changed is not None:
                catch_up(session, changed)
        # A session the store does not have (a request with no session id has a throwaway one)
        # is tainted in the call's copy alone, which is all there is to taint.
        session.tainted = True
        if new and self._metrics is not None:
            self._safely(self._metrics.session_tainted, ctx.principal.tenant_id)

    def _observe(self, ctx: CallContext, scan: ScanResult) -> None:
        if self._metrics is not None:
            self._safely(self._metrics.scan_scored, ctx.principal.tenant_id, scan.score)
            self._safely(self._metrics.scan_modelled, scan.model)

    def _count_failure(self, stage: str) -> None:
        if self._metrics is not None:
            self._safely(self._metrics.scan_failed, stage)

    @staticmethod
    def _safely(write: Callable[..., None], *args: object) -> None:
        """A metric that fails to write never fails a call."""
        try:
            write(*args)
        except Exception:
            log.error("metrics_failed", exc_info=True)
