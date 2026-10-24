import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { json, PEOPLE } from "../test/fakes";
import { budget, budgetsApi } from "../test/fixtures";
import { fakeApi } from "../test/fakes";
import { renderApp } from "../test/render";

const TENANT = budget({
  scope: "tenant",
  scope_id: "acme",
  limit_usd: "25",
  spent_usd: "0.000576",
});
const LENA = budget({ spent_usd: "0.03" });
const AGENT = budget({
  scope: "agent",
  scope_id: "ops-agent",
  window: "month",
  limit_usd: "200",
  spent_usd: "160",
  resets_at: "2026-11-01T00:00:00.000000Z",
});

function bar(name: string) {
  return screen.getByRole("progressbar", { name });
}

test("shows spend against limit", async () => {
  renderApp({ path: "/budgets", session: PEOPLE.root, api: budgetsApi([AGENT, LENA, TENANT]) });

  expect(await screen.findByRole("progressbar", { name: "lena" })).toBeVisible();
  expect(screen.getByRole("heading", { level: 1, name: "Budgets" })).toBeVisible();
  // One group for each scope, the tenant first.
  expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
    "Tenant",
    "Users",
    "Agents",
  ]);

  const lena = bar("lena");
  expect(lena).toHaveAttribute("aria-valuenow", "100");
  expect(lena).toHaveAttribute("aria-valuetext", "$0.03 of $0.03, 100%, at limit");
  expect(within(lena.closest("li") as HTMLElement).getByText("at limit")).toBeVisible();
  expect(within(lena.closest("li") as HTMLElement).getByText("a day")).toBeVisible();

  const acme = bar("acme");
  expect(acme).toHaveAttribute("aria-valuetext", "$0.000576 of $25.00, 0%, within limit");
  expect(within(acme.closest("li") as HTMLElement).getByText("$0.000576")).toBeVisible();
  expect(within(acme.closest("li") as HTMLElement).getByText(/of \$25\.00/)).toBeVisible();

  const agent = bar("ops-agent");
  expect(agent).toHaveAttribute("aria-valuenow", "80");
  expect(within(agent.closest("li") as HTMLElement).getByText("near limit")).toBeVisible();
  expect(within(agent.closest("li") as HTMLElement).getByText("a month")).toBeVisible();

  // When each window ends, in UTC, which is how the windows are counted.
  expect(screen.getAllByText("Oct 25, 00:00 UTC")).toHaveLength(2);
  expect(screen.getByText("Nov 1, 00:00 UTC")).toBeVisible();
  expect(screen.getAllByText(/^Resets in/)).toHaveLength(3);
  // A budget that is full is said so above the list.
  expect(within(screen.getByRole("main")).getByRole("status")).toHaveTextContent(
    "1 budget is at its limit",
  );
});

test("fills the bar by the share spent, and no more than all of it", async () => {
  renderApp({
    path: "/budgets",
    session: PEOPLE.root,
    api: budgetsApi([
      budget({ scope_id: "alice", limit_usd: "10", spent_usd: "2.5" }),
      budget({ scope_id: "bob", limit_usd: "10", spent_usd: "12" }),
    ]),
  });

  const alice = await screen.findByRole("progressbar", { name: "alice" });
  const bob = bar("bob");

  expect(alice.firstElementChild).toHaveStyle({ width: "25%" });
  expect(bob.firstElementChild).toHaveStyle({ width: "100%" });
  expect(bob).toHaveAttribute("aria-valuenow", "100");
  expect(bob).toHaveAttribute("aria-valuetext", "$12.00 of $10.00, 120%, over limit");
  expect(within(bob.closest("li") as HTMLElement).getByText("over limit")).toBeVisible();
});

test("says when no budget is set", async () => {
  renderApp({ path: "/budgets", session: PEOPLE.root, api: budgetsApi([]) });

  expect(await screen.findByText("No budgets are set")).toBeVisible();
  expect(screen.getByText(/listed in the config file/)).toBeVisible();
  expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
});

test("holds its place while the budgets load", async () => {
  let release: () => void = () => undefined;
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  const api = fakeApi({
    "GET /budgets": async () => {
      await wait;
      return [LENA];
    },
  });
  renderApp({ path: "/budgets", session: PEOPLE.root, api });

  expect(await screen.findByRole("status", { name: "Loading budgets" })).toHaveAttribute(
    "aria-busy",
    "true",
  );
  release();
  expect(await screen.findByRole("progressbar", { name: "lena" })).toBeVisible();
  expect(screen.queryByRole("status", { name: "Loading budgets" })).not.toBeInTheDocument();
});

test("says when the budgets cannot be read, and reads them again on request", async () => {
  let failing = true;
  const api = fakeApi({
    "GET /budgets": () =>
      failing ? json({ error: "unavailable", reason: "redis is away" }, 503) : [LENA],
  });
  renderApp({ path: "/budgets", session: PEOPLE.root, api });

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load the budgets");
  failing = false;
  await userEvent.click(within(alert).getByRole("button", { name: "Try again" }));

  expect(await screen.findByRole("progressbar", { name: "lena" })).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("is for administrators and not offered to an approver", async () => {
  const api = budgetsApi([LENA]);
  renderApp({ path: "/budgets", session: PEOPLE.lena, api });

  expect(await screen.findByText("You cannot open this page")).toBeVisible();
  expect(screen.queryByRole("link", { name: /Budgets/ })).not.toBeInTheDocument();
  expect(api.to("GET", "/budgets")).toHaveLength(0);
});

test("is in the menu of an administrator", async () => {
  renderApp({ path: "/budgets", session: PEOPLE.root, api: budgetsApi([LENA]) });

  const menu = await screen.findByRole("navigation", { name: "Main" });

  expect(within(menu).getByRole("link", { name: "Budgets" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  expect(within(menu).getByRole("link", { name: "Sessions" })).toBeVisible();
});
