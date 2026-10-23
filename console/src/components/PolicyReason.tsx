import { config } from "../config";
import { Icon } from "./Icon";

/** A policy id is a kebab-case name. Anything else a reason can be (`approval:<id>`) is text. */
const POLICY_ID = /^[a-z][a-z0-9-]*$/;

/**
 * One reason of a decision. A policy id links to its explanation in `docs/policies.md`, where
 * each shipped policy has a heading of its own, and opens in a new tab so the card stays put.
 */
export function PolicyReason({ reason }: { reason: string }) {
  if (!POLICY_ID.test(reason)) {
    return <span className="font-mono text-[13px] text-fg-muted">{reason}</span>;
  }
  return (
    <a
      href={`${config.policyDocsUrl}#${reason}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 rounded font-mono text-[13px] text-accent-text underline decoration-accent-text/40 underline-offset-2 hover:decoration-accent-text"
    >
      {reason}
      <Icon name="external" className="size-3.5" />
      <span className="sr-only">(opens the policy documentation in a new tab)</span>
    </a>
  );
}
