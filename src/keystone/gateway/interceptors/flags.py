"""The flags slot: a session remembers what it has read (KS-704).

After a call that returned, the tags `reads_untrusted` and `reads_sensitive` of its tool are added
to the session's flags and the call is counted. These two are the first and the second of the
Rule of Two (plan section 3.5, `policies/default/approval/rule_of_two.cedar`). The third, an
external effect, is read off the tool being called and is not something a session has done, so
`external_effect` and `code_exec` are not recorded.

A call that returned an error read nothing, so it adds no flags and is not counted. Keystone's own
tools (`keystone__whoami`, `keystone__await_approval`) are not calls to an upstream and are not
counted either: the await tool runs the call that waited through the pipeline again, and that call
is counted when it returns.

Everything is recorded with the store's atomic changes, `add_flags` and `incr_calls`, and never by
saving the call's copy, because that copy is as old as the start of the call and another call of
the session may have recorded a flag or a taint since (ADR-0015). The copy is then brought up to
date with what the store returned, so the slots after this one and the rest of the call see what
other calls recorded too. A session the store does not have (a request with no session id has a
throwaway one) is changed in the call's copy alone.
"""

from __future__ import annotations

from keystone.core.types import CallContext, ToolTag
from keystone.gateway.hooks import noop_hook
from keystone.gateway.sessions import SessionStore, catch_up
from keystone.registry.naming import is_virtual

# What a session is told it has read. Order is not meaningful; a set keeps it from being.
SESSION_TAGS = frozenset({ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE})


class SessionFlagsInterceptor:
    name = "session_flags"

    def __init__(self, sessions: SessionStore | None = None) -> None:
        self._sessions = sessions

    @noop_hook
    async def before_call(self, ctx: CallContext) -> None:
        return None

    async def after_call(self, ctx: CallContext) -> None:
        result = ctx.result
        if result is None or result.is_error or is_virtual(ctx.tool):
            return
        session = ctx.session
        flags = SESSION_TAGS & ctx.tool.tags
        if flags:
            session.flags |= flags
            if self._sessions is not None:
                changed = await self._sessions.add_flags(session.session_id, flags)
                if changed is not None:
                    catch_up(session, changed)
        before = session.call_count
        if self._sessions is not None:
            changed = await self._sessions.incr_calls(session.session_id)
            if changed is not None:
                catch_up(session, changed)
                return
        # No store, or a session it does not have: this call counts itself on the copy it has.
        session.call_count = before + 1
