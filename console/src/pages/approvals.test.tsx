import { focusManager } from "@tanstack/react-query";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { approval, approvalsApi, record } from "../test/fixtures";
import { json } from "../test/fakes";
import { PEOPLE } from "../test/fakes";
import { renderApp } from "../test/render";

const POLICY_DOCS =
  "https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security/blob/main/docs/policies.md";

async function cardFor(tool = "bank__transfer") {
  return screen.findByRole("article", { name: tool });
}

test("shows pending approval with reasons", async () => {
  const api = approvalsApi([
    approval({ tainted: true, flags: ["reads_sensitive"], arguments_masked: true }),
  ]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  const card = await cardFor();
  // The browser test finds its card by this id, and the agent's transcript names the same one.
  expect(card).toHaveAttribute("data-approval-id", "01M5M26K3SF50VNMVPMZM605EB");
  expect(within(card).getByText("high")).toBeVisible();
  expect(within(card).getAllByText("tainted").length).toBeGreaterThan(0);
  expect(within(card).getByText("reads_sensitive")).toBeVisible();
  expect(within(card).getByText("olivia")).toBeVisible();
  expect(within(card).getByText("ops-agent")).toBeVisible();
  expect(within(card).getByText("amount")).toBeVisible();
  expect(within(card).getByText("900")).toBeVisible();
  expect(within(card).getByText(/hidden or cut short/)).toBeVisible();
  expect(within(card).getByRole("timer")).toHaveTextContent(/^1[45]:\d\d left$/);
  const reason = within(card).getByRole("link", { name: /approve-transfer-over-500/ });
  expect(reason).toHaveAttribute("href", `${POLICY_DOCS}#approve-transfer-over-500`);
  expect(reason).toHaveAttribute("target", "_blank");
  expect(reason).toHaveAttribute("rel", expect.stringContaining("noopener"));
});

test("approve calls decision endpoint", async () => {
  const item = approval();
  const api = approvalsApi([item]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  await userEvent.click(within(await cardFor()).getByRole("button", { name: "Approve" }));

  await waitFor(() => {
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });
  const [sent, ...more] = api.to("POST", `/approvals/${item.id}/decision`);
  expect(more).toHaveLength(0);
  expect(sent?.body).toEqual({ approve: true });
  expect(sent?.authorization).toBe("Bearer test-token");
  expect(await screen.findByText("No approvals waiting")).toBeVisible();
  expect(screen.getByRole("status", { name: "" })).toHaveTextContent("Approved bank__transfer");
});

test("handles already decided", async () => {
  const api = approvalsApi([approval()], {
    decision: () =>
      json({ error: "conflict", reason: "the request is approved", status: "approved" }, 409),
  });
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  await userEvent.click(within(await cardFor()).getByRole("button", { name: "Approve" }));

  expect(await screen.findByText("Already decided")).toBeVisible();
  expect(screen.getByText(/Someone approved it already/)).toBeVisible();
  await waitFor(() => {
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });
  // The list was read again after the refusal.
  expect(api.to("GET", "/approvals").length).toBeGreaterThanOrEqual(2);
});

test("rejecting asks for a note and sends nothing without one", async () => {
  const api = approvalsApi([approval()]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });
  const card = await cardFor();

  await userEvent.click(within(card).getByRole("button", { name: "Reject" }));

  expect(within(card).getByRole("alert")).toHaveTextContent("Add a note to reject");
  expect(within(card).getByLabelText("Note")).toHaveFocus();
  expect(within(card).getByLabelText("Note")).toBeInvalid();
  expect(api.calls.filter((call) => call.method === "POST")).toHaveLength(0);
});

test("reject sends the note the agent will read", async () => {
  const item = approval();
  const api = approvalsApi([item]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });
  const card = await cardFor();

  await userEvent.type(within(card).getByLabelText("Note"), "  not this quarter ");
  await userEvent.click(within(card).getByRole("button", { name: "Reject" }));

  await waitFor(() => {
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });
  const [sent] = api.to("POST", `/approvals/${item.id}/decision`);
  expect(sent?.body).toEqual({ approve: false, note: "not this quarter" });
  expect(await screen.findByText(/is told: not this quarter/)).toBeVisible();
});

test("puts the card back when the decision cannot be sent", async () => {
  const api = approvalsApi([approval()], {
    decision: () => json({ error: "unavailable", reason: "approvals need master keys" }, 503),
  });
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  await userEvent.click(within(await cardFor()).getByRole("button", { name: "Approve" }));

  expect(await screen.findByText("Could not send your decision")).toBeVisible();
  expect(screen.getByText(/approvals need master keys/)).toBeVisible();
  expect(await cardFor()).toBeVisible();
});

test("does not let a person decide a request they made", async () => {
  const api = approvalsApi([approval({ own_request: true, requested_by_user: "lena" })]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  const card = await cardFor();

  expect(within(card).getByText(/someone else has to decide it/)).toBeVisible();
  expect(within(card).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  expect(within(card).queryByRole("button", { name: "Reject" })).not.toBeInTheDocument();
});

test("says so when nothing is waiting", async () => {
  renderApp({ path: "/approvals", session: PEOPLE.lena, api: approvalsApi([]) });

  expect(await screen.findByText("No approvals waiting")).toBeVisible();
});

test("shows why the list could not load and tries again on request", async () => {
  let failing = true;
  const api = approvalsApi([approval()]);
  const real = api.fetch;
  const flaky: typeof fetch = (input, init) =>
    failing
      ? Promise.resolve(json({ error: "unavailable", reason: "approvals need master keys" }, 503))
      : real(input, init);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api: { ...api, fetch: flaky } });

  expect(await screen.findByText("Could not load the approvals")).toBeVisible();
  failing = false;
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));

  expect(await cardFor()).toBeVisible();
});

test("lists the recent calls of the session when the card is opened", async () => {
  const api = approvalsApi([approval()], {
    recent: [
      record(),
      record({
        seq: 220,
        tool_name: "bank__get_balance",
        outcome: "ok",
        effect: "allow",
        reject_code: null,
      }),
    ],
  });
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });
  const card = await cardFor();
  expect(api.calls.some((call) => call.path.startsWith("/approvals/01"))).toBe(false);

  await userEvent.click(within(card).getByRole("button", { name: /Recent calls in this session/ }));

  const table = await within(card).findByRole("table", { name: /last calls of this session/ });
  expect(within(table).getByText("bank__get_balance")).toBeVisible();
  expect(within(table).getByText("waiting")).toBeVisible();
  expect(within(table).getByText("KS_APPROVAL_PENDING")).toBeVisible();
});

test("does not say a session is clean when its flags could not be read", async () => {
  const api = approvalsApi([approval({ session_state: "unavailable" })]);
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  const card = await cardFor();
  expect(within(card).getByText(/session store did not answer/)).toBeVisible();
  expect(within(card).queryByText("No flags on this session.")).toBeNull();
});

test("shows what the scanner made of the calls the session has read", async () => {
  const api = approvalsApi([approval({ tainted: true, flags: ["reads_untrusted"] })], {
    recent: [
      record({ seq: 222, tool_name: "mail__read_email", outcome: "ok", reject_code: null }),
      record({
        seq: 221,
        tool_name: "mail__read_email",
        outcome: "ok",
        effect: "allow",
        reject_code: null,
        scan_score: "0.880000",
        scan_action: "annotate",
      }),
      record({
        seq: 220,
        tool_name: "mail__list_emails",
        outcome: "ok",
        effect: "allow",
        reject_code: null,
        scan_score: "0.000000",
        scan_action: "pass",
      }),
    ],
  });
  renderApp({ path: "/approvals", session: PEOPLE.lena, api });
  const card = await cardFor();

  await userEvent.click(within(card).getByRole("button", { name: /Recent calls in this session/ }));

  const table = await within(card).findByRole("table", { name: /last calls of this session/ });
  expect(within(table).getByRole("columnheader", { name: "Scan" })).toBeVisible();
  expect(within(table).getByText("0.88 annotate")).toBeVisible();
  expect(within(table).getByText("0.00 pass")).toBeVisible();
  expect(within(table).getByText("not scanned")).toBeVisible();
});

test("outlines the request that a link points at and says when it is gone", async () => {
  const api = approvalsApi([approval()]);
  const { unmount } = renderApp({
    path: "/approvals?id=01M5M26K3SF50VNMVPMZM605EB",
    session: PEOPLE.lena,
    api,
  });
  expect(await cardFor()).toHaveClass("border-accent");
  unmount();

  renderApp({ path: "/approvals?id=01GONE", session: PEOPLE.lena, api });

  expect(await screen.findByText(/not waiting any more/)).toBeVisible();
});

test("reads the list again every five seconds and shows the count in the menu", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    const api = approvalsApi([approval()]);
    renderApp({ path: "/approvals", session: PEOPLE.lena, api });
    await cardFor();
    const before = api.to("GET", "/approvals").length;

    await vi.advanceTimersByTimeAsync(5200);

    await waitFor(() => {
      expect(api.to("GET", "/approvals").length).toBeGreaterThan(before);
    });
    const menu = screen.getByRole("navigation", { name: "Main" });
    expect(within(menu).getByRole("link", { name: /Approvals/ })).toHaveTextContent("1 waiting");
  } finally {
    vi.useRealTimers();
  }
});

test("keeps reading the list in a tab nobody is looking at", async () => {
  // The count in the tab's title and the menu exist for the approver who is in another tab, and
  // TanStack skips interval reads of an unfocused document unless the query says otherwise.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  focusManager.setFocused(false);
  try {
    const api = approvalsApi([approval()]);
    renderApp({ path: "/approvals", session: PEOPLE.lena, api });
    await cardFor();
    const before = api.to("GET", "/approvals").length;

    await vi.advanceTimersByTimeAsync(5200);

    await waitFor(() => {
      expect(api.to("GET", "/approvals").length).toBeGreaterThan(before);
    });
    expect(document.title).toMatch(/^\(1\) Approvals/);
  } finally {
    focusManager.setFocused(undefined);
    vi.useRealTimers();
  }
});

test("counts down in minutes and seconds and stops offering a decision at zero", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    const api = approvalsApi([approval({ expires_in_s: 62 })]);
    renderApp({ path: "/approvals", session: PEOPLE.lena, api });
    const card = await cardFor();
    expect(within(card).getByRole("timer")).toHaveTextContent(/^1:0[12] left$/);

    await vi.advanceTimersByTimeAsync(3000);
    expect(within(card).getByRole("timer")).toHaveTextContent(/^0:5\d left$/);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(within(card).getByText("Expired")).toBeVisible();
    expect(within(card).getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(within(card).getByRole("button", { name: "Reject" })).toBeDisabled();
  } finally {
    vi.useRealTimers();
  }
});

test("every control of a card has a label and can be reached with the keyboard", async () => {
  renderApp({ path: "/approvals", session: PEOPLE.lena, api: approvalsApi([approval()]) });
  const card = await cardFor();

  await userEvent.tab();
  const focusOrder: string[] = [];
  for (let step = 0; step < 8; step += 1) {
    const focused = document.activeElement;
    if (focused && card.contains(focused)) focusOrder.push(focused.textContent || focused.tagName);
    await userEvent.tab();
  }

  expect(within(card).getByRole("textbox", { name: "Note" })).toBeVisible();
  expect(focusOrder.some((text) => text.includes("approve-transfer-over-500"))).toBe(true);
  expect(focusOrder.some((text) => text.includes("Recent calls"))).toBe(true);
  expect(focusOrder.some((text) => text.includes("Reject"))).toBe(true);
  expect(focusOrder.some((text) => text.includes("Approve"))).toBe(true);
});
