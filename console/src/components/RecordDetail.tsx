import type { ReactNode } from "react";
import type { AuditRecord } from "../api/types";
import { formatCost, formatLatency, formatStamp, isMaskedValue } from "../lib/format";
import { traceUrl } from "../lib/trace";
import { ArgumentsView } from "./ArgumentsView";
import { EffectBadge, OutcomeBadge } from "./Badge";
import { Icon } from "./Icon";
import { PolicyReason } from "./PolicyReason";

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="border-b border-line py-3.5 first:pt-0 last:border-b-0">
      <dt className="mb-1.5 text-xs font-semibold tracking-wide text-fg-subtle uppercase">
        {label}
      </dt>
      <dd className="m-0">{children}</dd>
    </div>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[13px] break-all">{children}</span>;
}

function scanned(record: AuditRecord): string {
  if (record.scan_score === null && record.scan_action === null) return "Not scanned";
  return `${record.scan_action ?? "no action"}, score ${record.scan_score ?? "none"}`;
}

/** Everything one record of the audit log says, in the order a reviewer asks it: what was
 * decided and why, what was asked, what it cost, and where to look next. */
export function RecordDetail({ record }: { record: AuditRecord }) {
  const trace = traceUrl(record.trace_id);
  return (
    <dl>
      <Item label="Decision">
        <div className="flex flex-wrap items-center gap-2">
          <EffectBadge effect={record.effect} />
          <span className="text-fg-muted">decided by {record.decision_source ?? "nothing"}</span>
        </div>
      </Item>
      <Item label="Reasons">
        {record.reasons.length > 0 ? (
          <ul className="space-y-1">
            {record.reasons.map((reason) => (
              <li key={reason}>
                <PolicyReason reason={reason} />
              </li>
            ))}
          </ul>
        ) : (
          <span className="text-fg-muted">No reason was recorded.</span>
        )}
      </Item>
      <Item label="Policy version">
        {record.policy_version ? (
          <Mono>{record.policy_version}</Mono>
        ) : (
          <span className="text-fg-muted">Not recorded.</span>
        )}
      </Item>
      <Item label="Result">
        <div className="flex flex-wrap items-center gap-2">
          <OutcomeBadge outcome={record.outcome} code={record.reject_code} />
          {record.reject_code ? <Mono>{record.reject_code}</Mono> : null}
          <span className="text-fg-muted">
            {record.dispatched ? "sent to the upstream" : "not sent to the upstream"}
          </span>
        </div>
      </Item>
      <Item label="Arguments">
        <ArgumentsView value={record.args_redacted} masked={isMaskedValue(record.args_redacted)} />
      </Item>
      <Item label="Digest of the arguments">
        {record.args_digest ? (
          <Mono>{record.args_digest}</Mono>
        ) : (
          <span className="text-fg-muted">None.</span>
        )}
      </Item>
      <Item label="Injection scan">{scanned(record)}</Item>
      <Item label="Cost and time">
        <div className="flex gap-8">
          <div>
            <div className="text-xs text-fg-subtle">Cost</div>
            {formatCost(record.cost_usd)}
          </div>
          <div>
            <div className="text-xs text-fg-subtle">Latency</div>
            {formatLatency(record.latency_ms)}
          </div>
          <div>
            <div className="text-xs text-fg-subtle">When</div>
            <time dateTime={record.ts}>{formatStamp(record.ts)}</time>
          </div>
        </div>
      </Item>
      <Item label="Trace">
        {trace ? (
          <a
            href={trace}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-accent-text underline underline-offset-2"
          >
            Open the trace in Jaeger
            <Icon name="external" className="size-3.5" />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        ) : (
          <span className="text-fg-muted">This call has no trace.</span>
        )}
      </Item>
      <Item label="Who and where">
        <div className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1">
          <span className="text-fg-subtle">User</span>
          <span>{record.user_id}</span>
          <span className="text-fg-subtle">Agent</span>
          <span>{record.agent_id}</span>
          <span className="text-fg-subtle">Tenant</span>
          <span>{record.tenant_id}</span>
          <span className="text-fg-subtle">Session</span>
          <Mono>{record.session_id}</Mono>
          <span className="text-fg-subtle">Call</span>
          <Mono>{record.call_id}</Mono>
        </div>
      </Item>
      <Item label="Chain">
        <div className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1">
          <span className="text-fg-subtle">Record</span>
          <span className="tabular-nums">{record.seq}</span>
          <span className="text-fg-subtle">Previous hash</span>
          <Mono>{record.prev_hash}</Mono>
          <span className="text-fg-subtle">Hash</span>
          <Mono>{record.hash}</Mono>
        </div>
      </Item>
    </dl>
  );
}
