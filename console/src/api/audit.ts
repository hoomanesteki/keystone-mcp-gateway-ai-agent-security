import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useApi } from "./context";

export const PAGE_SIZE = 25;
export const VERIFY_EVERY_MS = 60_000;

export type EffectFilter = "" | "allow" | "deny" | "require_approval";
export type OutcomeFilter = "" | "ok" | "rejected" | "error";

/** What the filter form holds. An empty string means no filter. `since` and `until` are the ISO
 * times that the API takes, already converted from the person's local time. */
export interface AuditFilters {
  user: string;
  agent: string;
  tool: string;
  effect: EffectFilter;
  outcome: OutcomeFilter;
  since: string;
  until: string;
}

export const NO_FILTERS: AuditFilters = {
  user: "",
  agent: "",
  tool: "",
  effect: "",
  outcome: "",
  since: "",
  until: "",
};

/** One page of the log, newest first. `cursor` is the `next_cursor` of the page before. The
 * previous page stays on screen while the next is read, so a filter does not blank the table. */
export function useAuditPage(filters: AuditFilters, cursor: number | undefined) {
  const api = useApi();
  return useQuery({
    queryKey: ["audit", "search", filters, cursor ?? null] as const,
    queryFn: ({ signal }) =>
      api.get("/audit", {
        query: {
          user: filters.user.trim(),
          agent: filters.agent.trim(),
          tool: filters.tool.trim(),
          effect: filters.effect === "" ? undefined : filters.effect,
          outcome: filters.outcome === "" ? undefined : filters.outcome,
          since: filters.since,
          until: filters.until,
          cursor,
          limit: PAGE_SIZE,
        },
        signal,
      }),
    placeholderData: keepPreviousData,
  });
}

/** Whether the hash chain of the newest records holds. Checked again every minute. */
export function useChainStatus(enabled: boolean) {
  const api = useApi();
  return useQuery({
    queryKey: ["audit", "verify"] as const,
    queryFn: ({ signal }) => api.get("/audit/verify", { signal }),
    enabled,
    refetchInterval: VERIFY_EVERY_MS,
    retry: false,
  });
}
