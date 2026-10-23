import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "../components/toast-context";
import { describeError } from "../lib/errors";
import { useApi } from "./context";
import type { ToolSummary } from "./types";

export const toolKeys = {
  all: ["tools"] as const,
  list: ["tools", "list"] as const,
  detail: (name: string) => ["tools", "detail", name] as const,
};

/** Every tool of the tenant, whatever its state. A change at an upstream shows up within a
 * quarter of a minute. */
export function useTools() {
  const api = useApi();
  return useQuery({
    queryKey: toolKeys.list,
    queryFn: ({ signal }) => api.get("/tools", { signal }),
    refetchInterval: 15_000,
  });
}

/** A tool with its pending definition, the fingerprint of it and the diff. Read when opened. */
export function useToolDetail(name: string, enabled: boolean) {
  const api = useApi();
  return useQuery({
    queryKey: toolKeys.detail(name),
    queryFn: ({ signal }) => api.get("/tools/{name}", { path: { name }, signal }),
    enabled,
  });
}

interface Approval {
  tool: ToolSummary;
  note: string;
  /** The fingerprint of the definition that was looked at, when there is a pending one. */
  fingerprint: string | null;
}

/**
 * Accept the pending definition of a quarantined tool. The fingerprint goes with it, so a
 * definition that changed again after the person read it is refused (409) and not approved
 * unseen.
 */
export function useApproveChange() {
  const api = useApi();
  const queries = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: ({ tool, note, fingerprint }: Approval) =>
      api.post("/tools/{name}/approve-change", {
        path: { name: tool.name },
        body: fingerprint ? { note, expect: fingerprint } : { note },
      }),
    onSuccess: (_answer, { tool }) => {
      toast.push({
        tone: "success",
        title: `Approved the change to ${tool.name}`,
        detail: "The tool is active again.",
      });
    },
    onError: (error, { tool }) => {
      toast.push({
        tone: "error",
        title: `Could not approve ${tool.name}`,
        detail: describeError(error),
      });
    },
    onSettled: () => queries.invalidateQueries({ queryKey: toolKeys.all }),
  });
}

/** Take a tool out of service, or put one back that an operator disabled. */
export function useToolSwitch() {
  const api = useApi();
  const queries = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: ({ tool, enable }: { tool: ToolSummary; enable: boolean }) =>
      enable
        ? api.post("/tools/{name}/enable", { path: { name: tool.name } })
        : api.post("/tools/{name}/disable", { path: { name: tool.name } }),
    onSuccess: (_answer, { tool, enable }) => {
      toast.push({
        tone: "success",
        title: `${enable ? "Enabled" : "Disabled"} ${tool.name}`,
      });
    },
    onError: (error, { tool, enable }) => {
      toast.push({
        tone: "error",
        title: `Could not ${enable ? "enable" : "disable"} ${tool.name}`,
        detail: describeError(error),
      });
    },
    onSettled: () => queries.invalidateQueries({ queryKey: toolKeys.all }),
  });
}
