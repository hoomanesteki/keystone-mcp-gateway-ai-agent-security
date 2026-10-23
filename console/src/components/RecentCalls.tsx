import { useId, useState } from "react";
import { useApprovalDetail } from "../api/approvals";
import { formatClock, formatScan } from "../lib/format";
import { describeError } from "../lib/errors";
import { Badge, OutcomeBadge } from "./Badge";
import { Button } from "./Button";
import { Icon } from "./Icon";
import { Skeleton } from "./StateViews";

/** What the scanner made of the output of a call. An output that was flagged is marked, so the
 * call that brought the injection in is the one the eye finds in the list. */
function Scan({ score, action }: { score: string | null; action: string | null }) {
  const scan = formatScan(score, action);
  if (scan === null) return <span className="text-fg-subtle">not scanned</span>;
  if (action === "pass") return <span className="text-fg-muted">{scan}</span>;
  return <Badge tone={action === "block" ? "danger" : "warn"}>{scan}</Badge>;
}

function Calls({ id }: { id: string }) {
  const detail = useApprovalDetail(id, true);
  if (detail.isPending) {
    return (
      <div role="status" aria-label="Loading recent calls" className="space-y-2 pt-1">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-5/6" />
      </div>
    );
  }
  if (detail.isError) {
    return (
      <div role="alert" className="flex items-center gap-3 pt-1 text-danger-fg">
        <span>Could not load the recent calls. {describeError(detail.error)}</span>
        <Button
          size="sm"
          onClick={() => {
            void detail.refetch();
          }}
        >
          Try again
        </Button>
      </div>
    );
  }
  const calls = detail.data.recent_calls;
  if (calls.length === 0) {
    return <p className="pt-1 text-fg-muted">This session has made no earlier calls.</p>;
  }
  return (
    <table className="w-full text-left text-[13px]">
      <caption className="sr-only">The last calls of this session, newest first</caption>
      <thead className="text-xs text-fg-subtle">
        <tr>
          <th scope="col" className="py-1 pr-4 font-medium">
            Time
          </th>
          <th scope="col" className="py-1 pr-4 font-medium">
            Tool
          </th>
          <th scope="col" className="py-1 pr-4 font-medium">
            Result
          </th>
          <th scope="col" className="py-1 pr-4 font-medium">
            Scan
          </th>
          <th scope="col" className="py-1 font-medium">
            Detail
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {calls.map((call) => (
          <tr key={call.seq}>
            <td className="py-1.5 pr-4 whitespace-nowrap text-fg-muted tabular-nums">
              <time dateTime={call.ts}>{formatClock(call.ts)}</time>
            </td>
            <td className="py-1.5 pr-4 font-mono">{call.tool_name}</td>
            <td className="py-1.5 pr-4">
              <OutcomeBadge outcome={call.outcome} code={call.reject_code} />
            </td>
            <td className="py-1.5 pr-4 font-mono whitespace-nowrap">
              <Scan score={call.scan_score} action={call.scan_action} />
            </td>
            <td className="py-1.5 font-mono text-fg-muted">{call.reject_code ?? call.effect}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The last calls of the session that asked, to read the request in context. Fetched when opened. */
export function RecentCalls({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const panel = useId();
  return (
    <div className="border-t border-line">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panel}
        onClick={() => {
          setOpen((was) => !was);
        }}
        className="flex w-full items-center gap-2 px-5 py-3 text-left font-medium text-fg-muted hover:text-fg"
      >
        <Icon name={open ? "chevronDown" : "chevronRight"} />
        Recent calls in this session
      </button>
      <div id={panel} hidden={!open} className="px-5 pb-4">
        {open ? <Calls id={id} /> : null}
      </div>
    </div>
  );
}
