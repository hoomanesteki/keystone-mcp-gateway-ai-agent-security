import type { AuditFilters, EffectFilter, OutcomeFilter } from "../api/audit";

/** What the filter form holds: the text as typed, and the times as a `datetime-local` field gives
 * them (the person's local time, no zone). `filtersFromDraft` makes what the API takes. */
export interface Draft {
  user: string;
  agent: string;
  tool: string;
  effect: EffectFilter;
  outcome: OutcomeFilter;
  since: string;
  until: string;
}

export const EMPTY_DRAFT: Draft = {
  user: "",
  agent: "",
  tool: "",
  effect: "",
  outcome: "",
  since: "",
  until: "",
};

export const EFFECTS: readonly { value: EffectFilter; label: string }[] = [
  { value: "", label: "Any decision" },
  { value: "allow", label: "Allowed" },
  { value: "deny", label: "Denied" },
  { value: "require_approval", label: "Needs approval" },
];

export const OUTCOMES: readonly { value: OutcomeFilter; label: string }[] = [
  { value: "", label: "Any result" },
  { value: "ok", label: "ok" },
  { value: "rejected", label: "rejected" },
  { value: "error", label: "error" },
];

const KEYS = ["user", "agent", "tool", "effect", "outcome", "since", "until"] as const;

function oneOf<T extends string>(value: string | null, allowed: readonly { value: T }[]): T | "" {
  const found = allowed.find((option) => option.value === value);
  return found ? found.value : "";
}

/** The filters in the address, so a filtered view can be bookmarked or sent. */
export function draftFromParams(params: URLSearchParams): Draft {
  return {
    user: params.get("user") ?? "",
    agent: params.get("agent") ?? "",
    tool: params.get("tool") ?? "",
    effect: oneOf(params.get("effect"), EFFECTS),
    outcome: oneOf(params.get("outcome"), OUTCOMES),
    since: params.get("since") ?? "",
    until: params.get("until") ?? "",
  };
}

export function paramsFromDraft(draft: Draft): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of KEYS) {
    if (draft[key] !== "") params.set(key, draft[key]);
  }
  return params;
}

export function hasFilters(draft: Draft): boolean {
  return KEYS.some((key) => draft[key] !== "");
}

/** A local time from a `datetime-local` field as the ISO time the API takes, or "" if it is not a
 * time. The API reads a time with no zone as UTC, so the zone is made explicit here. */
function isoFromLocal(value: string): string {
  if (value === "") return "";
  const moment = new Date(value);
  return Number.isNaN(moment.getTime()) ? "" : moment.toISOString();
}

export function filtersFromDraft(draft: Draft): AuditFilters {
  return { ...draft, since: isoFromLocal(draft.since), until: isoFromLocal(draft.until) };
}
