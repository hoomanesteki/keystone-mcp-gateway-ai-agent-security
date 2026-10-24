import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { fakeApi, json, PEOPLE } from "../test/fakes";
import { auditRoutes, liveSession, record, sessionRoutes, sessionsApi } from "../test/fixtures";
import { renderApp } from "../test/render";

const CLEAN = liveSession({
  session_id: "aaaaaaaa11112222333344445555",
  user_id: "alice",
  agent_id: "support-agent",
  call_count: 3,
  spent_usd: 0,
});
const TAINTED = liveSession({
  session_id: "bbbbbbbb11112222333344445555",
  user_id: "olivia",
  flags: ["reads_untrusted", "reads_sensitive"],
  tainted: true,
  call_count: 12,
  spent_usd: 0.030192,
});

function rowOf(user: string) {
  return screen
    .getByRole("link", { name: new RegExp(`audit log for ${user}`) })
    .closest("tr") as HTMLElement;
}

test("shows taint badge", async () => {
  renderApp({ path: "/sessions", session: PEOPLE.root, api: sessionsApi([TAINTED, CLEAN]) });

  expect(await screen.findByRole("link", { name: /audit log for olivia/ })).toBeVisible();
  expect(screen.getByRole("heading", { level: 1, name: "Sessions" })).toBeVisible();
  const tainted = rowOf("olivia");
  // The word is in the badge, and the red is a repeat of it.
  expect(within(tainted).getByText("tainted")).toBeVisible();
  expect(within(tainted).queryByText("clean")).not.toBeInTheDocument();
  expect(within(tainted).getByText("reads_untrusted")).toBeVisible();
  expect(within(tainted).getByText("reads_sensitive")).toBeVisible();
  expect(within(tainted).getByText("12")).toBeVisible();
  expect(within(tainted).getByText("$0.030192")).toBeVisible();
  expect(within(tainted).getByText("ops-agent", { exact: false })).toBeVisible();

  const clean = rowOf("alice");
  expect(within(clean).getByText("clean")).toBeVisible();
  expect(within(clean).queryByText("tainted")).not.toBeInTheDocument();
  expect(within(clean).getByText("none")).toBeVisible();
  expect(within(clean).getByText("$0.00")).toBeVisible();
  expect(within(screen.getByRole("main")).getByRole("status")).toHaveTextContent(
    "2 sessions, 1 tainted.",
  );
});

test("opens the audit log for the session that was chosen", async () => {
  const calls = [
    record({ seq: 3, session_id: TAINTED.session_id, tool_name: "mail__send_email" }),
    record({ seq: 2, session_id: CLEAN.session_id, tool_name: "echo__echo", user_id: "alice" }),
    record({ seq: 1, session_id: TAINTED.session_id, tool_name: "mail__read_email" }),
  ];
  const api = fakeApi({ ...sessionRoutes([TAINTED, CLEAN]), ...auditRoutes(calls) });
  renderApp({ path: "/sessions", session: PEOPLE.root, api });

  await userEvent.click(await screen.findByRole("link", { name: /audit log for olivia/ }));

  expect(await screen.findByRole("heading", { level: 1, name: "Audit" })).toBeVisible();
  expect(screen.getByLabelText("Session")).toHaveValue(TAINTED.session_id);
  expect(await screen.findByRole("button", { name: /mail__send_email/ })).toBeVisible();
  expect(screen.getByRole("button", { name: /mail__read_email/ })).toBeVisible();
  expect(screen.queryByRole("button", { name: /echo__echo/ })).not.toBeInTheDocument();
  const asked = api.to("GET", "/audit").at(-1);
  expect(asked?.query.get("session")).toBe(TAINTED.session_id);
});

test("says that no session is open", async () => {
  renderApp({ path: "/sessions", session: PEOPLE.root, api: sessionsApi([]) });

  expect(await screen.findByText("No live sessions")).toBeVisible();
  expect(screen.getByText(/gone 24 hours after its last use/)).toBeVisible();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});

test("holds its place while the sessions load", async () => {
  let release: () => void = () => undefined;
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  const api = fakeApi({
    "GET /sessions": async () => {
      await wait;
      return [CLEAN];
    },
  });
  renderApp({ path: "/sessions", session: PEOPLE.root, api });

  expect(await screen.findByRole("status", { name: "Loading sessions" })).toHaveAttribute(
    "aria-busy",
    "true",
  );
  release();
  expect(await screen.findByRole("link", { name: /audit log for alice/ })).toBeVisible();
});

test("says when the sessions cannot be read, and reads them again on request", async () => {
  let failing = true;
  const api = fakeApi({
    "GET /sessions": () =>
      failing ? json({ error: "unavailable", reason: "redis is away" }, 503) : [CLEAN],
  });
  renderApp({ path: "/sessions", session: PEOPLE.root, api });

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Could not load the sessions");
  failing = false;
  await userEvent.click(within(alert).getByRole("button", { name: "Try again" }));

  await waitFor(() => {
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  expect(await screen.findByRole("link", { name: /audit log for alice/ })).toBeVisible();
});

test("counts one session in the singular", async () => {
  renderApp({ path: "/sessions", session: PEOPLE.root, api: sessionsApi([CLEAN]) });

  await screen.findByRole("link", { name: /audit log for alice/ });

  expect(within(screen.getByRole("main")).getByRole("status")).toHaveTextContent(
    "1 session, none tainted.",
  );
});

test("says when only the newest sessions are shown", async () => {
  const many = Array.from({ length: 100 }, (_, number) =>
    liveSession({ session_id: `session-${String(number).padStart(3, "0")}-x`, user_id: "alice" }),
  );
  const api = sessionsApi(many);
  renderApp({ path: "/sessions", session: PEOPLE.root, api });

  await screen.findAllByRole("link", { name: /audit log for alice/ });

  expect(within(screen.getByRole("main")).getByRole("status")).toHaveTextContent(
    "The newest 100 sessions, and there may be more, none tainted.",
  );
  expect(api.to("GET", "/sessions")[0]?.query.get("limit")).toBe("100");
});

test("is for administrators and not offered to an approver", async () => {
  const api = sessionsApi([CLEAN]);
  renderApp({ path: "/sessions", session: PEOPLE.lena, api });

  expect(await screen.findByText("You cannot open this page")).toBeVisible();
  expect(api.to("GET", "/sessions")).toHaveLength(0);
});
