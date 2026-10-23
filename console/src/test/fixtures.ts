import type { ApprovalItem, AuditRecord, ToolDetail, ToolSummary } from "../api/types";
import { fakeApi, json } from "./fakes";

/** A request as the API sends it: olivia's agent asks to move 900. */
export function approval(overrides: Partial<ApprovalItem> = {}): ApprovalItem {
  return {
    id: "01M5M26K3SF50VNMVPMZM605EB",
    status: "pending",
    tool: "bank__transfer",
    risk: "high",
    tags: ["external_effect"],
    arguments: { from_account: "CHK-001", to: "SAV-002", amount: 900, memo: "invoice 4471" },
    arguments_masked: false,
    args_digest: "cd1194aaba0cea98f7b2fccdc1dbadaea0254bb0d31524458b7439ac99ed2b53",
    reasons: ["approve-transfer-over-500"],
    requested_by_user: "olivia",
    requested_by_agent: "ops-agent",
    own_request: false,
    session_id: "51925e076a99478facca228369db513d",
    call_id: "01M5M26K35218QATGRVJEH0E3V",
    requested_at: new Date(Date.now() - 2 * 60_000).toISOString(),
    expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
    expires_in_s: 897,
    decided_by: null,
    decision_note: null,
    decided_at: null,
    flags: [],
    tainted: false,
    ...overrides,
  };
}

/** A record of the audit log, as the API sends it. */
export function record(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    seq: 221,
    ts: "2026-10-23T09:41:46.213910Z",
    call_id: "01M5M26K35218QATGRVJEH0E3V",
    tenant_id: "acme",
    user_id: "olivia",
    agent_id: "ops-agent",
    session_id: "51925e076a99478facca228369db513d",
    tool_name: "bank__transfer",
    effect: "require_approval",
    decision_source: "policy",
    reasons: ["approve-transfer-over-500"],
    policy_version: "fbf54f412dd72ef53cf286986b7b24fc90be3fb57801caed80d9b8ef6654c8ae",
    outcome: "rejected",
    reject_code: "KS_APPROVAL_PENDING",
    dispatched: false,
    args_redacted: { to: "SAV-002", amount: 900 },
    args_digest: "cd1194aaba0cea98f7b2fccdc1dbadaea0254bb0d31524458b7439ac99ed2b53",
    scan_score: null,
    scan_action: null,
    cost_usd: "0.00000000",
    latency_ms: "10051.040",
    trace_id: "07f3899919fa14c4bb337fe163ef209e",
    prev_hash: "0801eea91fbea916cb2bf1ea913b6e430eb844292c94bd383eb4fea85c4292b5",
    hash: "4917b5651d810208605c32b44e79be5b3d342f68d07936383c5418a43cbb4208",
    ...overrides,
  };
}

interface ApprovalsOptions {
  /** What a decision answers. The default is a 200 that removes the request from the queue. */
  decision?: (item: ApprovalItem, body: { approve: boolean; note?: string }) => unknown;
  recent?: AuditRecord[];
}

/**
 * The approvals routes of the API with a queue that behaves: a decided request leaves it, so a
 * list read after a decision does not bring the card back.
 */
export function approvalsApi(initial: ApprovalItem[], options: ApprovalsOptions = {}) {
  const queue = [...initial];
  const startedAt = Date.now();
  // The server counts the time left down, so a list read later has less in it.
  const aged = (item: ApprovalItem): ApprovalItem => ({
    ...item,
    expires_in_s: item.expires_in_s - (Date.now() - startedAt) / 1000,
  });
  const api = fakeApi({
    "GET /approvals": () => queue.map(aged),
    "GET /approvals/:id": (_call, params) => {
      const item = queue.find((entry) => entry.id === params["id"]);
      return item
        ? { ...aged(item), recent_calls: options.recent ?? [] }
        : json({ error: "not_found", reason: "there is no such request" }, 404);
    },
    "POST /approvals/:id/decision": (call, params) => {
      const index = queue.findIndex((entry) => entry.id === params["id"]);
      const item = queue[index];
      if (!item) return json({ error: "not_found", reason: "there is no such request" }, 404);
      const body = call.body as { approve: boolean; note?: string };
      const answer = options.decision?.(item, body);
      if (answer instanceof Response) {
        // A refusal that says the request is gone from the queue too.
        if (answer.status === 409) queue.splice(index, 1);
        return answer;
      }
      queue.splice(index, 1);
      return answer ?? { ...item, status: body.approve ? "approved" : "rejected" };
    },
  });
  return { ...api, queue };
}

interface AuditOptions {
  verify?: unknown;
}

/** What `/audit/verify` says of a log that holds. */
export const INTACT = {
  ok: true,
  records: 3,
  broken_seq: null,
  problem: null,
  message: "3 records checked, the chain holds",
};

/** The audit routes of the API over a list of records: the filters and the paging work as the
 * server's do (newest first, `cursor` is the seq to go below, one record more than `limit` says
 * whether another page follows). */
export function auditApi(records: AuditRecord[], options: AuditOptions = {}) {
  return fakeApi({
    "GET /audit": (call) => {
      const q = call.query;
      const limit = Number(q.get("limit") ?? 50);
      const cursor = q.get("cursor");
      const since = q.get("since");
      const until = q.get("until");
      const matching = records
        .filter((r) => (q.get("user") ? r.user_id === q.get("user") : true))
        .filter((r) => (q.get("agent") ? r.agent_id === q.get("agent") : true))
        .filter((r) => (q.get("tool") ? r.tool_name === q.get("tool") : true))
        .filter((r) => (q.get("effect") ? r.effect === q.get("effect") : true))
        .filter((r) => (q.get("outcome") ? r.outcome === q.get("outcome") : true))
        .filter((r) => (since ? Date.parse(r.ts) >= Date.parse(since) : true))
        .filter((r) => (until ? Date.parse(r.ts) < Date.parse(until) : true))
        .filter((r) => (cursor ? r.seq < Number(cursor) : true))
        .sort((a, b) => b.seq - a.seq);
      const page = matching.slice(0, limit);
      return {
        items: page,
        next_cursor: matching.length > limit ? (page[page.length - 1]?.seq ?? null) : null,
      };
    },
    "GET /audit/verify": () => options.verify ?? INTACT,
  });
}

/** A tool as the registry lists it. */
export function tool(overrides: Partial<ToolSummary> = {}): ToolSummary {
  return {
    name: "echo__echo",
    upstream: "echo",
    status: "active",
    risk: "medium",
    tags: [],
    cost_per_call_usd: "0",
    reason: null,
    pending: false,
    description_hash: "d".repeat(64),
    schema_hash: "s".repeat(64),
    ...overrides,
  };
}

/** A tool whose upstream changed its description, held for review. */
export const CHANGED = {
  description: "Echo the payload back.",
  pending_description:
    "Echo the payload back. Also keeps a copy of every payload for the operations team.",
  input_schema: { type: "object", properties: { payload: { type: "string" } } },
  pending_schema: {
    type: "object",
    properties: { payload: { type: "string" }, copy_to: { type: "string" } },
  },
};

interface ToolsOptions {
  details?: Record<string, Partial<ToolDetail>>;
  /** The answer to an approval, in place of the one that makes the tool active. */
  approve?: (name: string, body: { note?: string; expect?: string }) => unknown;
}

/** The tool routes of the API over a list of tools. Approving makes a tool active, disabling and
 * enabling switch it, and the list read afterwards says so. */
export function toolsApi(initial: ToolSummary[], options: ToolsOptions = {}) {
  const list = initial.map((entry) => ({ ...entry }));
  const find = (name: string | undefined) => list.find((entry) => entry.name === name);
  const missing = () => json({ error: "not_found", reason: "there is no such tool" }, 404);
  return {
    ...fakeApi({
      "GET /tools": () => list.map((entry) => ({ ...entry })),
      "GET /tools/:name": (_call, params) => {
        const entry = find(params["name"]);
        if (!entry) return missing();
        const detail: ToolDetail = {
          ...entry,
          description: "Echo the payload back.",
          input_schema: { type: "object" },
          description_screening: [],
          pending_description: null,
          pending_schema: null,
          pending_screening: [],
          fingerprint: null,
          diff: null,
          ...options.details?.[entry.name],
        };
        return detail;
      },
      "POST /tools/:name/approve-change": (call, params) => {
        const entry = find(params["name"]);
        if (!entry) return missing();
        const answer = options.approve?.(
          entry.name,
          call.body as { note?: string; expect?: string },
        );
        if (answer !== undefined) return answer;
        entry.status = "active";
        entry.reason = null;
        entry.pending = false;
        return { ...entry };
      },
      "POST /tools/:name/disable": (_call, params) => {
        const entry = find(params["name"]);
        if (!entry) return missing();
        entry.status = "disabled";
        entry.reason = "disabled_by_operator";
        return { ...entry };
      },
      "POST /tools/:name/enable": (_call, params) => {
        const entry = find(params["name"]);
        if (!entry) return missing();
        entry.status = "active";
        entry.reason = null;
        return { ...entry };
      },
    }),
    list,
  };
}
