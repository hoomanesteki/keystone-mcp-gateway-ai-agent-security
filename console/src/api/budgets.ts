import { useQuery } from "@tanstack/react-query";
import { useApi } from "./context";

export const budgetKeys = {
  list: ["budgets", "list"] as const,
};

/** The tenant's budgets and what each has spent in its window. Spend changes with every priced
 * call, so the page asks again every 15 seconds. */
export function useBudgets() {
  const api = useApi();
  return useQuery({
    queryKey: budgetKeys.list,
    queryFn: ({ signal }) => api.get("/budgets", { signal }),
    refetchInterval: 15_000,
  });
}
