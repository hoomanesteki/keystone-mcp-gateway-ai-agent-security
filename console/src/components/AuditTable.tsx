import { useState } from "react";
import { PAGE_SIZE, useAuditPage, type AuditFilters } from "../api/audit";
import type { AuditRecord } from "../api/types";
import { formatLatency, formatStamp } from "../lib/format";
import { EffectBadge, OutcomeBadge } from "./Badge";
import { Button } from "./Button";
import { Icon } from "./Icon";
import { EmptyState, ErrorState, Skeleton } from "./StateViews";

const HEADINGS = ["Time", "User and agent", "Tool", "Decision", "Result", "Reason", "Latency"];

function Placeholder() {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label="Loading the audit log"
      className="space-y-3 p-4"
    >
      {Array.from({ length: 6 }, (_, row) => (
        <Skeleton key={row} className="h-5 w-full" />
      ))}
    </div>
  );
}

interface AuditTableProps {
  filters: AuditFilters;
  filtered: boolean;
  onOpen: (record: AuditRecord) => void;
  onClear: () => void;
}

/**
 * The records that match, a page at a time. The page keeps its own trail of cursors, so "Newer"
 * can go back: the API only pages toward older records. A change of filters gives the table a new
 * key, which starts it again on the newest page.
 */
export function AuditTable({ filters, filtered, onOpen, onClear }: AuditTableProps) {
  const [trail, setTrail] = useState<number[]>([]);
  const page = useAuditPage(filters, trail[trail.length - 1]);

  if (page.isPending) {
    return (
      <div className="rounded-lg border border-line bg-surface shadow-card">
        <Placeholder />
      </div>
    );
  }
  if (page.isError) {
    return (
      <ErrorState
        title="Could not load the audit log"
        error={page.error}
        onRetry={() => {
          void page.refetch();
        }}
      />
    );
  }

  const { items } = page.data;
  const older = page.data.next_cursor ?? null;
  if (items.length === 0 && trail.length === 0) {
    return (
      <EmptyState icon="search" title={filtered ? "No records match" : "The audit log is empty"}>
        {filtered ? (
          <>
            Nothing in the log has all of these filters.{" "}
            <button
              type="button"
              onClick={onClear}
              className="text-accent-text underline underline-offset-2"
            >
              Clear the filters
            </button>
            .
          </>
        ) : (
          "Records appear here as agents make calls."
        )}
      </EmptyState>
    );
  }

  return (
    <div className="rounded-lg border border-line bg-surface shadow-card">
      <div className={`overflow-x-auto ${page.isPlaceholderData ? "opacity-60" : ""}`}>
        <table className="w-full min-w-[52rem] text-left text-[13px]">
          <caption className="sr-only">
            Audit records, newest first. Open a tool name to see the whole record.
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
            {items.map((record) => (
              <tr key={record.seq} className="relative hover:bg-sunken focus-within:bg-sunken">
                <td className="px-4 py-2.5 whitespace-nowrap text-fg-muted tabular-nums">
                  <time dateTime={record.ts} title={record.ts}>
                    {formatStamp(record.ts)}
                  </time>
                </td>
                <td className="px-4 py-2.5">
                  <div>{record.user_id}</div>
                  <div className="text-xs whitespace-nowrap text-fg-subtle">{record.agent_id}</div>
                </td>
                <td className="px-4 py-2.5">
                  <button
                    type="button"
                    onClick={() => {
                      onOpen(record);
                    }}
                    aria-label={`Open record ${record.seq}, ${record.tool_name}`}
                    className="rounded font-mono font-medium text-accent-text after:absolute after:inset-0 hover:underline"
                  >
                    {record.tool_name}
                  </button>
                </td>
                <td className="px-4 py-2.5">
                  <EffectBadge effect={record.effect} />
                </td>
                <td className="px-4 py-2.5">
                  <OutcomeBadge outcome={record.outcome} code={record.reject_code} />
                </td>
                <td className="max-w-[18rem] px-4 py-2.5 font-mono text-fg-muted">
                  <div
                    className="truncate"
                    title={record.reasons.join(", ") || (record.reject_code ?? "")}
                  >
                    {record.reasons[0] ?? record.reject_code ?? ""}
                    {record.reasons.length > 1 ? ` +${record.reasons.length - 1}` : ""}
                  </div>
                </td>
                <td className="px-4 py-2.5 whitespace-nowrap text-fg-muted tabular-nums">
                  {formatLatency(record.latency_ms)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-3">
        <p className="text-fg-muted">
          Page {trail.length + 1}, {items.length} of up to {PAGE_SIZE} records
        </p>
        <div className="flex gap-2">
          <Button
            size="sm"
            disabled={trail.length === 0}
            onClick={() => {
              setTrail((was) => was.slice(0, -1));
            }}
          >
            <Icon name="chevronLeft" />
            Newer
          </Button>
          <Button
            size="sm"
            disabled={older === null}
            onClick={() => {
              if (older !== null) setTrail((was) => [...was, older]);
            }}
          >
            Older
            <Icon name="chevronRight" />
          </Button>
        </div>
      </div>
    </div>
  );
}
