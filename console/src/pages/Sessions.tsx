import { Link } from "react-router";
import { SESSION_LIMIT, useSessions } from "../api/sessions";
import type { SessionInfo } from "../api/types";
import { Badge, TaintBadge } from "../components/Badge";
import { EmptyState, ErrorState, LoadingList, PageHeader } from "../components/StateViews";
import { formatUsd } from "../lib/budgets";
import { relativeTime } from "../lib/format";
import { useNow } from "../lib/useNow";
import { usePageTitle } from "../lib/usePageTitle";

const INTRO =
  "Sessions that agents have open now, newest first. A session ends 24 hours after its last use. " +
  "Open one to see its calls in the audit log.";
const HEADINGS = ["User and agent", "Started", "Flags", "State", "Calls", "Spend"];

/** The start of the id, to tell two sessions of one person apart. */
function shortId(id: string): string {
  return id.slice(0, 8);
}

function Row({ session, now }: { session: SessionInfo; now: number }) {
  return (
    <tr className="relative hover:bg-sunken focus-within:bg-sunken">
      <td className="px-4 py-2.5">
        <Link
          to={`/audit?session=${encodeURIComponent(session.session_id)}`}
          aria-label={`Open the audit log for ${session.user_id}, session ${shortId(session.session_id)}`}
          className="rounded font-medium text-accent-text after:absolute after:inset-0 hover:underline"
        >
          {session.user_id}
        </Link>
        <div className="text-xs whitespace-nowrap text-fg-subtle">
          {session.agent_id} · <span className="font-mono">{shortId(session.session_id)}</span>
        </div>
      </td>
      <td className="px-4 py-2.5 whitespace-nowrap text-fg-muted">
        <time dateTime={session.created_at} title={session.created_at}>
          {relativeTime(session.created_at, now)}
        </time>
      </td>
      <td className="px-4 py-2.5">
        <div className="flex flex-wrap gap-1">
          {session.flags.length === 0 ? <span className="text-fg-subtle">none</span> : null}
          {session.flags.map((flag) => (
            <Badge key={flag}>
              <span className="font-mono">{flag}</span>
            </Badge>
          ))}
        </div>
      </td>
      <td className="px-4 py-2.5">
        {session.tainted ? <TaintBadge /> : <Badge tone="ok">clean</Badge>}
      </td>
      <td className="px-4 py-2.5 tabular-nums">{session.call_count}</td>
      <td className="px-4 py-2.5 whitespace-nowrap text-fg-muted tabular-nums">
        {formatUsd(session.spent_usd)}
      </td>
    </tr>
  );
}

export function Sessions() {
  const sessions = useSessions();
  const now = useNow(30_000);
  usePageTitle("Sessions");

  if (sessions.isPending) {
    return (
      <>
        <PageHeader title="Sessions">{INTRO}</PageHeader>
        <LoadingList label="Loading sessions" rows={3} />
      </>
    );
  }
  if (sessions.isError) {
    return (
      <>
        <PageHeader title="Sessions">{INTRO}</PageHeader>
        <ErrorState
          title="Could not load the sessions"
          error={sessions.error}
          onRetry={() => {
            void sessions.refetch();
          }}
        />
      </>
    );
  }

  const tainted = sessions.data.filter((session) => session.tainted).length;
  return (
    <>
      <PageHeader title="Sessions">{INTRO}</PageHeader>
      {sessions.data.length === 0 ? (
        <EmptyState icon="sessions" title="No live sessions">
          A session appears when an agent connects, and is gone 24 hours after its last use.
        </EmptyState>
      ) : (
        <>
          <p className="mb-3 text-fg-muted" role="status">
            {sessions.data.length >= SESSION_LIMIT
              ? `The newest ${sessions.data.length} sessions, and there may be more`
              : `${sessions.data.length} ${sessions.data.length === 1 ? "session" : "sessions"}`}
            , {tainted === 0 ? "none tainted" : `${tainted} tainted`}.
          </p>
          <div className="rounded-lg border border-line bg-surface shadow-card">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[46rem] text-left text-[13px]">
                <caption className="sr-only">
                  Live sessions, newest first. Open a user to see the session's calls.
                </caption>
                <thead className="border-b border-line bg-sunken text-xs text-fg-subtle">
                  <tr>
                    {HEADINGS.map((heading) => (
                      <th key={heading} scope="col" className="px-4 py-2.5 font-medium">
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {sessions.data.map((session) => (
                    <Row key={session.session_id} session={session} now={now} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}
