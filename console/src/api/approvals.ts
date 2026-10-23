import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "../components/toast-context";
import { describeError } from "../lib/errors";
import { ApiError } from "./client";
import { useApi } from "./context";
import type { ApprovalItem } from "./types";

export const POLL_MS = 5000;

export const approvalKeys = {
  all: ["approvals"] as const,
  pending: ["approvals", "pending"] as const,
  detail: (id: string) => ["approvals", "detail", id] as const,
};

/** The requests waiting for a person, oldest first. Polled, so a new one shows within seconds. */
export function usePendingApprovals() {
  const api = useApi();
  return useQuery({
    queryKey: approvalKeys.pending,
    queryFn: ({ signal }) => api.get("/approvals", { query: { status: "pending" }, signal }),
    refetchInterval: POLL_MS,
  });
}

/** One request with the last calls of the session that asked. Fetched when a card is opened. */
export function useApprovalDetail(id: string, enabled: boolean) {
  const api = useApi();
  return useQuery({
    queryKey: approvalKeys.detail(id),
    queryFn: ({ signal }) =>
      api.get("/approvals/{approval_id}", { path: { approval_id: id }, signal }),
    enabled,
    refetchInterval: enabled ? POLL_MS : false,
  });
}

interface Decision {
  item: ApprovalItem;
  approve: boolean;
  note: string;
}

/** What a 409 says about a request that someone else got to first. */
function alreadyDecided(state: string | null): string {
  switch (state) {
    case "approved":
      return "Someone approved it already.";
    case "rejected":
      return "Someone rejected it already.";
    case "consumed":
      return "It was approved earlier and has already run.";
    case "expired":
      return "It expired before anyone decided it.";
    default:
      return "It is no longer waiting.";
  }
}

/**
 * Approve or reject. The card leaves the list at once, before the server has answered, and comes
 * back if the answer is a failure. A 409 is not a failure of the person: the request was decided
 * or expired meanwhile, so it stays gone and the list is read again.
 */
export function useDecision() {
  const api = useApi();
  const queries = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: ({ item, approve, note }: Decision) =>
      api.post("/approvals/{approval_id}/decision", {
        path: { approval_id: item.id },
        body: note ? { approve, note } : { approve },
      }),
    onMutate: async ({ item }) => {
      await queries.cancelQueries({ queryKey: approvalKeys.pending });
      const before = queries.getQueryData<ApprovalItem[]>(approvalKeys.pending);
      queries.setQueryData<ApprovalItem[]>(approvalKeys.pending, (list) =>
        list?.filter((entry) => entry.id !== item.id),
      );
      return { before };
    },
    onSuccess: (_answer, { item, approve, note }) => {
      toast.push({
        tone: "success",
        title: `${approve ? "Approved" : "Rejected"} ${item.tool}`,
        detail: approve
          ? `The call by ${item.requested_by_user} can go ahead.`
          : `${item.requested_by_user}'s agent is told: ${note}`,
      });
    },
    onError: (error, { item }, context) => {
      if (error instanceof ApiError && error.status === 409) {
        toast.push({
          tone: "info",
          title: "Already decided",
          detail: `${item.tool} for ${item.requested_by_user}. ${alreadyDecided(error.state)}`,
        });
        return;
      }
      if (context?.before) queries.setQueryData(approvalKeys.pending, context.before);
      toast.push({
        tone: "error",
        title: "Could not send your decision",
        detail: `${describeError(error)} Nothing was changed.`,
      });
    },
    onSettled: () => queries.invalidateQueries({ queryKey: approvalKeys.pending }),
  });
}
