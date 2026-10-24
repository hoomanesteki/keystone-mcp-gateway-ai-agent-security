import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { auditApi, record } from "../test/fixtures";
import { addressOf, json, PEOPLE } from "../test/fakes";
import { renderApp } from "../test/render";

const TRANSFER = record({ seq: 30, tool_name: "bank__transfer" });
const BALANCE = record({
  seq: 29,
  tool_name: "bank__get_balance",
  effect: "allow",
  outcome: "ok",
  reject_code: null,
  reasons: ["same-tenant-low-medium"],
  latency_ms: "12.4",
  trace_id: null,
});
const DENIED = record({
  seq: 28,
  tool_name: "mail__send_email",
  user_id: "alice",
  agent_id: "support-agent",
  effect: "deny",
  outcome: "rejected",
  reject_code: "KS_DENIED",
  reasons: ["default-deny"],
});

function lastQuery(api: ReturnType<typeof auditApi>) {
  return api.to("GET", "/audit").at(-1)?.query;
}

test("filters by tool", async () => {
  const api = auditApi([TRANSFER, BALANCE, DENIED]);
  renderApp({ path: "/audit", session: PEOPLE.root, api });
  expect(await screen.findByRole("button", { name: /bank__get_balance/ })).toBeVisible();
  expect(lastQuery(api)?.get("tool")).toBeNull();

  await userEvent.type(screen.getByLabelText("Tool"), "bank__transfer");

  await waitFor(() => {
    expect(lastQuery(api)?.get("tool")).toBe("bank__transfer");
  });
  await waitFor(() => {
    expect(screen.queryByRole("button", { name: /bank__get_balance/ })).not.toBeInTheDocument();
  });
  expect(screen.getByRole("button", { name: /bank__transfer/ })).toBeVisible();
});

test("shows trace link", async () => {
  renderApp({ path: "/audit", session: PEOPLE.root, api: auditApi([TRANSFER]) });

  await userEvent.click(await screen.findByRole("button", { name: /Open record 30/ }));

  const drawer = await screen.findByRole("dialog");
  const link = within(drawer).getByRole("link", { name: /Open the trace in Jaeger/ });
  expect(link).toHaveAttribute(
    "href",
    "http://localhost:16686/trace/07f3899919fa14c4bb337fe163ef209e",
  );
  expect(link).toHaveAttribute("target", "_blank");
  expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
});

test("shows broken chain badge", async () => {
  const broken = {
    ok: false,
    records: 216,
    broken_seq: 217,
    problem: "hash mismatch",
    message: "record 217 does not match its hash",
  };
  renderApp({
    path: "/audit",
    session: PEOPLE.root,
    api: auditApi([TRANSFER], { verify: broken }),
  });

  const badge = await screen.findByRole("status", { name: "Audit chain" });

  await waitFor(() => {
    expect(badge).toHaveAttribute("data-chain", "broken");
  });
  expect(badge).toHaveTextContent("Chain broken at record 217");
  expect(within(badge).getByText(/Chain broken/)).toHaveClass("bg-critical-bg");
});

test("shows the chain as verified when it holds", async () => {
  renderApp({ path: "/audit", session: PEOPLE.root, api: auditApi([TRANSFER]) });

  const badge = await screen.findByRole("status", { name: "Audit chain" });

  await waitFor(() => {
    expect(badge).toHaveAttribute("data-chain", "ok");
  });
  expect(badge).toHaveTextContent("Chain verified");
});

test("says the chain was not checked when the check fails", async () => {
  const api = auditApi([TRANSFER]);
  const failing = {
    ...api,
    fetch: (async (input, init) =>
      addressOf(input).includes("/audit/verify")
        ? json({ error: "unavailable", reason: "the database is down" }, 503)
        : api.fetch(input, init)) satisfies typeof fetch,
  };
  renderApp({ path: "/audit", session: PEOPLE.root, api: failing });

  const badge = await screen.findByRole("status", { name: "Audit chain" });

  await waitFor(() => {
    expect(badge).toHaveAttribute("data-chain", "unknown");
  });
  expect(badge).toHaveTextContent("Audit chain not checked");
});

test("shows the whole record in the drawer and gives the focus back when it closes", async () => {
  renderApp({
    path: "/audit",
    session: PEOPLE.root,
    api: auditApi([
      record({
        seq: 31,
        args_redacted: { to: "priya@outside.test", body: "card [redacted:card]" },
        scan_score: "0.91",
        scan_action: "flag",
        cost_usd: "0.0024",
        latency_ms: "10051.040",
      }),
    ]),
  });
  const opener = await screen.findByRole("button", { name: /Open record 31/ });

  await userEvent.click(opener);

  const drawer = await screen.findByRole("dialog", { name: /bank__transfer/ });
  expect(within(drawer).getByText("approve-transfer-over-500")).toBeVisible();
  expect(
    within(drawer).getByText("fbf54f412dd72ef53cf286986b7b24fc90be3fb57801caed80d9b8ef6654c8ae"),
  ).toBeVisible();
  expect(within(drawer).getByText("flag, score 0.91")).toBeVisible();
  expect(within(drawer).getByText("$0.0024")).toBeVisible();
  expect(within(drawer).getByText("10.05 s")).toBeVisible();
  expect(within(drawer).getByText(/hidden or cut short/)).toBeVisible();
  expect(within(drawer).getByText("not sent to the upstream")).toBeVisible();
  expect(drawer).toHaveFocus();

  await userEvent.keyboard("{Escape}");

  await waitFor(() => {
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  expect(opener).toHaveFocus();
});

test("keeps the keyboard inside the drawer while it is open", async () => {
  renderApp({ path: "/audit", session: PEOPLE.root, api: auditApi([TRANSFER]) });
  await userEvent.click(await screen.findByRole("button", { name: /Open record 30/ }));
  const drawer = await screen.findByRole("dialog");
  const close = within(drawer).getByRole("button", { name: "Close" });

  for (let press = 0; press < 6; press += 1) {
    await userEvent.tab();
    expect(drawer.contains(document.activeElement)).toBe(true);
  }
  await userEvent.click(close);

  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

test("pages toward older records and back", async () => {
  const many = Array.from({ length: 30 }, (_, index) =>
    record({ seq: index + 1, tool_name: `echo__call${String(index + 1).padStart(2, "0")}` }),
  );
  const api = auditApi(many);
  renderApp({ path: "/audit", session: PEOPLE.root, api });
  expect(await screen.findByRole("button", { name: /echo__call30/ })).toBeVisible();
  expect(screen.getByRole("button", { name: /Newer/ })).toBeDisabled();

  await userEvent.click(screen.getByRole("button", { name: /Older/ }));

  expect(await screen.findByRole("button", { name: /echo__call05/ })).toBeVisible();
  expect(lastQuery(api)?.get("cursor")).toBe("6");
  expect(screen.getByRole("button", { name: /Older/ })).toBeDisabled();

  await userEvent.click(screen.getByRole("button", { name: /Newer/ }));

  expect(await screen.findByRole("button", { name: /echo__call30/ })).toBeVisible();
});

test("sends a time range as absolute times", async () => {
  const api = auditApi([TRANSFER]);
  renderApp({ path: "/audit", session: PEOPLE.root, api });
  await screen.findByRole("button", { name: /Open record 30/ });

  await userEvent.type(screen.getByLabelText("From"), "2026-10-23T09:30");

  await waitFor(() => {
    expect(lastQuery(api)?.get("since")).toBe(new Date("2026-10-23T09:30").toISOString());
  });
});

test("starts from the filters in the address and clears them on request", async () => {
  const api = auditApi([TRANSFER, BALANCE, DENIED]);
  renderApp({ path: "/audit?effect=deny&user=alice", session: PEOPLE.root, api });

  expect(await screen.findByRole("button", { name: /mail__send_email/ })).toBeVisible();
  expect(screen.getByLabelText("User")).toHaveValue("alice");
  expect(screen.getByLabelText("Decision")).toHaveValue("deny");
  expect(screen.queryByRole("button", { name: /bank__transfer/ })).not.toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));

  expect(await screen.findByRole("button", { name: /bank__transfer/ })).toBeVisible();
  expect(screen.getByLabelText("User")).toHaveValue("");
});

test("says so when no record matches", async () => {
  renderApp({ path: "/audit?tool=nothing__here", session: PEOPLE.root, api: auditApi([TRANSFER]) });

  expect(await screen.findByText("No records match")).toBeVisible();
  expect(screen.getByRole("button", { name: "Clear the filters" })).toBeVisible();
});

test("says so when the log is empty", async () => {
  renderApp({ path: "/audit", session: PEOPLE.root, api: auditApi([]) });

  expect(await screen.findByText("The audit log is empty")).toBeVisible();
});

test("shows why the log could not load and reads it again on request", async () => {
  const api = auditApi([TRANSFER]);
  let failing = true;
  const flaky: typeof fetch = (input, init) =>
    failing && addressOf(input).includes("/audit?")
      ? Promise.resolve(json({ error: "unavailable", reason: "the database is down" }, 503))
      : api.fetch(input, init);
  renderApp({ path: "/audit", session: PEOPLE.root, api: { ...api, fetch: flaky } });

  expect(await screen.findByText("Could not load the audit log")).toBeVisible();
  expect(screen.getByText(/the database is down/)).toBeVisible();
  failing = false;
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));

  expect(await screen.findByRole("button", { name: /Open record 30/ })).toBeVisible();
});

test("does not ask an approver for the chain or the log", async () => {
  const api = auditApi([TRANSFER]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  await screen.findByRole("heading", { level: 1, name: "Approvals" });

  expect(screen.queryByRole("status", { name: "Audit chain" })).not.toBeInTheDocument();
  expect(api.to("GET", "/audit/verify")).toHaveLength(0);
});

test("filters by session", async () => {
  const mine = record({ seq: 31, session_id: "sess-mine", tool_name: "echo__echo" });
  const api = auditApi([mine, TRANSFER, BALANCE]);
  renderApp({ path: "/audit", session: PEOPLE.root, api });
  expect(await screen.findByRole("button", { name: /bank__get_balance/ })).toBeVisible();
  expect(lastQuery(api)?.get("session")).toBeNull();

  await userEvent.type(screen.getByLabelText("Session"), "sess-mine");

  await waitFor(() => {
    expect(lastQuery(api)?.get("session")).toBe("sess-mine");
  });
  await waitFor(() => {
    expect(screen.queryByRole("button", { name: /bank__get_balance/ })).not.toBeInTheDocument();
  });
  expect(screen.getByRole("button", { name: /echo__echo/ })).toBeVisible();
});

test("starts filtered by the session in the address", async () => {
  const mine = record({ seq: 31, session_id: "sess-mine", tool_name: "echo__echo" });
  const api = auditApi([mine, TRANSFER]);
  renderApp({ path: "/audit?session=sess-mine", session: PEOPLE.root, api });

  expect(await screen.findByRole("button", { name: /echo__echo/ })).toBeVisible();

  expect(screen.getByLabelText("Session")).toHaveValue("sess-mine");
  expect(api.to("GET", "/audit")[0]?.query.get("session")).toBe("sess-mine");
  expect(screen.queryByRole("button", { name: /bank__transfer/ })).not.toBeInTheDocument();
});
