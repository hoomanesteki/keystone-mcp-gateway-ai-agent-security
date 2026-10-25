import { useEffect, useId, useRef, useState } from "react";
import type { ApprovalItem } from "../api/types";
import { relativeTime, secondsLeft } from "../lib/format";
import { useNow } from "../lib/useNow";
import { ArgumentsView } from "./ArgumentsView";
import { Badge, RiskBadge, TaintBadge } from "./Badge";
import { Button } from "./Button";
import { Countdown } from "./Countdown";
import { Icon } from "./Icon";
import { PolicyReason } from "./PolicyReason";
import { RecentCalls } from "./RecentCalls";

/** What a session flag means, for the person reading it. Flags are the tags of tools it has used. */
const FLAG_HELP: Record<string, string> = {
  reads_untrusted: "Has read content that an outsider could have written",
  reads_sensitive: "Has read private data",
  external_effect: "Has changed something outside Keystone",
  code_exec: "Has run code",
};

const NOTE_LIMIT = 500;

function Heading({ children, id }: { children: string; id: string }) {
  return (
    <h3 id={id} className="mb-2 text-xs font-semibold tracking-wide text-fg-subtle uppercase">
      {children}
    </h3>
  );
}

interface ApprovalCardProps {
  item: ApprovalItem;
  /** When the list this card is from arrived, in milliseconds, for the countdown. */
  receivedAt: number;
  /** The request a link pointed at: it is scrolled to and outlined. */
  highlighted?: boolean;
  onDecide: (approve: boolean, note: string) => void;
}

export function ApprovalCard({
  item,
  receivedAt,
  highlighted = false,
  onDecide,
}: ApprovalCardProps) {
  const ids = useId();
  const [note, setNote] = useState("");
  const [needsNote, setNeedsNote] = useState(false);
  const noteField = useRef<HTMLInputElement>(null);
  const card = useRef<HTMLElement>(null);
  const now = useNow(1000);
  const left = secondsLeft(item.expires_in_s, receivedAt, now);
  const expired = left <= 0;

  useEffect(() => {
    if (highlighted) card.current?.scrollIntoView({ block: "center" });
  }, [highlighted]);

  const reject = () => {
    const text = note.trim();
    if (text === "") {
      setNeedsNote(true);
      noteField.current?.focus();
      return;
    }
    onDecide(false, text);
  };

  const title = `${ids}-title`;
  return (
    <article
      ref={card}
      data-approval-id={item.id}
      aria-labelledby={title}
      className={`rounded-lg border bg-surface shadow-card ${highlighted ? "border-accent ring-2 ring-accent/30" : "border-line"}`}
    >
      <div className="p-5">
        <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 id={title} className="font-mono text-[15px] font-semibold">
              {item.tool}
            </h2>
            <RiskBadge risk={item.risk} />
            {item.tainted ? <TaintBadge /> : null}
          </div>
          <Countdown left={left} />
        </header>
        <p className="mt-1 text-fg-muted">
          Requested by <strong className="font-medium text-fg">{item.requested_by_user}</strong>{" "}
          through <strong className="font-medium text-fg">{item.requested_by_agent}</strong>
          <span aria-hidden="true"> &middot; </span>
          <time dateTime={item.requested_at} title={item.requested_at}>
            {relativeTime(item.requested_at, now)}
          </time>
        </p>

        <div className="mt-5 grid gap-6 md:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <div role="group" aria-labelledby={`${ids}-arguments`}>
            <Heading id={`${ids}-arguments`}>Arguments</Heading>
            <ArgumentsView value={item.arguments} masked={item.arguments_masked} />
          </div>
          <div className="space-y-5">
            <div role="group" aria-labelledby={`${ids}-reasons`}>
              <Heading id={`${ids}-reasons`}>Why it needs approval</Heading>
              {item.reasons.length > 0 ? (
                <ul className="space-y-1">
                  {item.reasons.map((reason) => (
                    <li key={reason}>
                      <PolicyReason reason={reason} />
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-fg-muted">No policy is named.</p>
              )}
            </div>
            <div role="group" aria-labelledby={`${ids}-session`}>
              <Heading id={`${ids}-session`}>Session</Heading>
              <div className="flex flex-wrap gap-1.5">
                {item.tainted ? <TaintBadge /> : null}
                {item.flags.map((flag) => (
                  <Badge key={flag} title={FLAG_HELP[flag]}>
                    <span className="font-mono">{flag}</span>
                  </Badge>
                ))}
                {item.session_state !== "live" ? (
                  <span className="text-fg-muted">
                    {item.session_state === "ended"
                      ? "The session has ended: its flags are not known."
                      : "The session store did not answer: its flags are not known."}
                  </span>
                ) : !item.tainted && item.flags.length === 0 ? (
                  <span className="text-fg-muted">No flags on this session.</span>
                ) : null}
              </div>
            </div>
          </div>
        </div>
      </div>

      <RecentCalls id={item.id} />

      <div className="rounded-b-lg border-t border-line bg-sunken p-5">
        {item.own_request ? (
          <p className="flex items-center gap-2 text-fg-muted">
            <Icon name="lock" />
            You made this request, so someone else has to decide it.
          </p>
        ) : (
          <div className="flex flex-col gap-3 md:flex-row md:items-start">
            <div className="flex-1">
              <label
                htmlFor={`${ids}-note`}
                className="mb-1 block text-xs font-medium text-fg-muted"
              >
                Note
              </label>
              <input
                ref={noteField}
                id={`${ids}-note`}
                type="text"
                value={note}
                maxLength={NOTE_LIMIT}
                placeholder="Optional to approve, required to reject"
                aria-describedby={`${ids}-note-help`}
                aria-invalid={needsNote}
                onChange={(event) => {
                  setNote(event.target.value);
                  if (event.target.value.trim() !== "") setNeedsNote(false);
                }}
                className="h-9 w-full rounded-md border border-line-strong bg-surface px-3 text-fg placeholder:text-fg-subtle aria-invalid:border-danger-fg"
              />
              <p
                id={`${ids}-note-help`}
                role={needsNote ? "alert" : undefined}
                className={`mt-1 text-xs ${needsNote ? "text-danger-fg" : "text-fg-subtle"}`}
              >
                {needsNote
                  ? "Add a note to reject. The agent is told what you write."
                  : "If you reject, the agent is told this note."}
              </p>
            </div>
            <div className="flex gap-2 md:pt-5">
              <Button variant="danger" disabled={expired} onClick={reject}>
                <Icon name="x" />
                Reject
              </Button>
              <Button
                variant="primary"
                disabled={expired}
                onClick={() => {
                  onDecide(true, note.trim());
                }}
              >
                <Icon name="check" />
                Approve
              </Button>
            </div>
          </div>
        )}
      </div>
    </article>
  );
}
