import { useId, useRef, useState } from "react";
import { useApproveChange, useToolDetail } from "../api/tools";
import type { ToolSummary } from "../api/types";
import { stableStringify } from "../lib/diff";
import { describeError } from "../lib/errors";
import { describeReason, describeScan, describeScreening, sentences } from "../lib/tools";
import { Button } from "./Button";
import { Icon } from "./Icon";
import { SideBySideDiff } from "./SideBySideDiff";
import { Skeleton } from "./StateViews";

function Heading({ children }: { children: string }) {
  return (
    <h3 className="mb-2 text-xs font-semibold tracking-wide text-fg-subtle uppercase">
      {children}
    </h3>
  );
}

function Screening({ label, hits }: { label: string; hits: readonly string[] }) {
  if (hits.length === 0) return null;
  return (
    <p className="flex items-start gap-2 rounded-md border border-danger-line bg-danger-bg px-3 py-2 text-danger-fg">
      <Icon name="alert" className="mt-0.5 size-4" />
      <span>
        {label} matched a screening rule: it contains {describeScreening(hits).join(", ")}.
      </span>
    </p>
  );
}

/**
 * What a person needs to decide on a held tool: why it is held, what changed (the current and the
 * pending definition side by side), and a note that says why the change is fine. Approving sends
 * the fingerprint of the definition that was read, so one that changed again is refused.
 */
export function ToolReview({ tool, onDone }: { tool: ToolSummary; onDone: () => void }) {
  const detail = useToolDetail(tool.name, true);
  const approve = useApproveChange();
  const [note, setNote] = useState("");
  const [needsNote, setNeedsNote] = useState(false);
  const field = useRef<HTMLTextAreaElement>(null);
  const ids = useId();

  if (detail.isPending) {
    return (
      <div role="status" aria-label="Loading the definition" className="space-y-2">
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-20 w-full" />
      </div>
    );
  }
  if (detail.isError) {
    return (
      <div role="alert" className="flex items-center gap-3 text-danger-fg">
        <span>Could not load the definition. {describeError(detail.error)}</span>
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

  const tool_ = detail.data;
  const scan = describeScan(tool.reason);
  const changed = tool_.pending_description !== null && tool_.pending_schema !== null;
  const submit = () => {
    const text = note.trim();
    if (text === "") {
      setNeedsNote(true);
      field.current?.focus();
      return;
    }
    approve.mutate({ tool, note: text, fingerprint: tool_.fingerprint }, { onSuccess: onDone });
  };

  return (
    <div className="space-y-5">
      <p className="text-fg-muted">
        <span className="font-medium text-fg">Held because:</span> {describeReason(tool.reason)}.
        Agents cannot see or call this tool until it is approved.
      </p>

      {scan ? (
        <p className="text-fg-muted">
          The scanner scored it <span className="font-mono text-fg">{scan.score}</span> in{" "}
          <span className="font-mono text-fg">{scan.where}</span>.
        </p>
      ) : null}

      <Screening label="The current description" hits={tool_.description_screening} />
      <Screening label="The pending description" hits={tool_.pending_screening} />

      {changed ? (
        <>
          <section aria-label="Description changes">
            <Heading>Description</Heading>
            <SideBySideDiff
              label="Description"
              before={sentences(tool_.description)}
              after={sentences(tool_.pending_description ?? "")}
            />
          </section>
          <section aria-label="Schema changes">
            <Heading>Input schema</Heading>
            <SideBySideDiff
              label="Input schema"
              before={stableStringify(tool_.input_schema)}
              after={stableStringify(tool_.pending_schema)}
            />
          </section>
        </>
      ) : (
        <section aria-label="Definition">
          <Heading>Definition</Heading>
          <p className="whitespace-pre-wrap">{tool_.description}</p>
          <p className="mt-2 text-fg-muted">
            No changed definition is waiting. Approving releases the tool as it is.
          </p>
        </section>
      )}

      <div className="rounded-md border border-line bg-sunken p-4">
        <label htmlFor={`${ids}-note`} className="mb-1 block text-xs font-medium text-fg-muted">
          Note
        </label>
        <textarea
          ref={field}
          id={`${ids}-note`}
          rows={2}
          maxLength={500}
          value={note}
          placeholder="Why this change is fine. It goes in the log."
          aria-describedby={`${ids}-note-help`}
          aria-invalid={needsNote}
          onChange={(event) => {
            setNote(event.target.value);
            if (event.target.value.trim() !== "") setNeedsNote(false);
          }}
          className="w-full rounded-md border border-line-strong bg-surface px-3 py-2 text-fg placeholder:text-fg-subtle aria-invalid:border-danger-fg"
        />
        <p
          id={`${ids}-note-help`}
          role={needsNote ? "alert" : undefined}
          className={`mt-1 text-xs ${needsNote ? "text-danger-fg" : "text-fg-subtle"}`}
        >
          {needsNote
            ? "Add a note to approve. A change to a tool is a decision someone should be able to read later."
            : "Required. The log keeps it with your name."}
        </p>
        <div className="mt-3 flex justify-end">
          <Button variant="primary" disabled={approve.isPending} onClick={submit}>
            <Icon name="check" />
            Approve change
          </Button>
        </div>
      </div>
    </div>
  );
}
