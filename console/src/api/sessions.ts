import { useQuery } from "@tanstack/react-query";
import { useApi } from "./context";

export const sessionKeys = {
  list: ["sessions", "list"] as const,
};

/** The most sessions the page asks for. The API's own default is the same, and a page that says
 * how many it shows has to know it. */
export const SESSION_LIMIT = 100;

/** The live sessions of the tenant, newest first. A session lives 24 hours from its last use, and
 * its count of calls and its spend change as the agent works, so the page asks again every 10
 * seconds. */
export function useSessions() {
  const api = useApi();
  return useQuery({
    queryKey: sessionKeys.list,
    queryFn: ({ signal }) => api.get("/sessions", { query: { limit: SESSION_LIMIT }, signal }),
    refetchInterval: 10_000,
  });
}
