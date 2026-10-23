import type { ToolSummary } from "../api/types";

/** Why a tool is not active, in words. The ids are the registry's `quarantine_reason`; a held
 * change can be one reason or two joined by a comma, and a screening hit follows a colon. */
const REASONS: Record<string, string> = {
  description_changed: "The description changed",
  schema_changed: "The input schema changed",
  suspicious_description: "A new tool whose description matched a screening rule",
  removed_from_upstream: "The upstream no longer lists it",
  disabled_by_operator: "Disabled by an operator",
};

/** The screening a new tool is held for starts `suspicious_description:`. What follows is one
 * finding: the rules, then (with the scanner) `score=0.70 in=description`. It has commas of its
 * own, so it is read as a whole and not as several reasons. */
const SCREENED = "suspicious_description:";

export function describeReason(reason: string | null): string {
  if (reason === null) return "";
  if (reason.startsWith(SCREENED)) return REASONS["suspicious_description"] ?? reason;
  const parts = reason
    .split(",")
    .map((part) => part.split(":")[0] ?? part)
    .map((part) => REASONS[part] ?? part)
    // "The description changed and the input schema changed", not "... and The input ...".
    .map((text, index) => (index === 0 ? text : text.charAt(0).toLowerCase() + text.slice(1)));
  return parts.join(" and ");
}

/** What a screening rule found in a description (the ids are `defense/description_check.py`'s). */
const SCREENING: Record<string, string> = {
  hidden_unicode: "hidden characters",
  instruction_override: "an instruction to ignore what came before",
  pseudo_tag: "a made-up tag such as <important>",
  cross_tool_reference: "a reference to another tool",
  oversized: "an unusually long text",
  // The rules of the scanner (ADR-0011), which read the descriptions of a schema too (KS-706).
  role_spoof: "text that poses as the system or the assistant",
  tool_directive: "an instruction to call a tool or to send something to an address",
  secrecy: "an instruction to keep something from the user",
  markdown_exfil: "an image or link that carries data out in its address",
  encoded_payload: "a long block of encoded text",
};

export interface ScanFinding {
  score: string;
  where: string;
}

/** The scanner's score and where it found it, from a screening reason such as
 * `suspicious_description:role_spoof,tool_directive score=0.70 in=input_schema.properties.note`.
 * Null for a reason without a score: the first check alone held the tool, or it was not held for
 * screening. */
export function describeScan(reason: string | null): ScanFinding | null {
  if (!reason?.startsWith(SCREENED)) return null;
  const found = /\sscore=(\d+(?:\.\d+)?)\sin=(\S+)$/.exec(reason);
  return found ? { score: found[1] ?? "", where: found[2] ?? "" } : null;
}

export function describeScreening(hits: readonly string[]): string[] {
  return hits.map((hit) => SCREENING[hit] ?? hit);
}

/** A description split at sentence ends and line ends, as the server's diff does, because it is
 * often one long line and comparing whole lines would show all of it as changed. */
export function sentences(text: string): string {
  return text
    .split(/(?<=[.!?])\s+|\n/)
    .filter((piece) => piece !== "")
    .join("\n");
}

export interface Group {
  upstream: string;
  tools: ToolSummary[];
}

/** The tools by upstream, upstreams and tools in name order. */
export function groupByUpstream(tools: readonly ToolSummary[]): Group[] {
  const groups = new Map<string, ToolSummary[]>();
  for (const tool of tools) {
    const members = groups.get(tool.upstream) ?? [];
    members.push(tool);
    groups.set(tool.upstream, members);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([upstream, members]) => ({
      upstream,
      tools: members.sort((a, b) => a.name.localeCompare(b.name)),
    }));
}
