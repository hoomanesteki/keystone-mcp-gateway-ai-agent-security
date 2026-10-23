import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { fakeApi, json, PEOPLE } from "./test/fakes";
import { approval, approvalsApi } from "./test/fixtures";
import { renderApp } from "./test/render";

function menu() {
  return screen.getByRole("navigation", { name: "Main" });
}

test("renders approvals nav for an approver", async () => {
  renderApp({ session: PEOPLE.lena });

  expect(await screen.findByRole("heading", { level: 1, name: "Approvals" })).toBeVisible();
  expect(within(menu()).getByRole("link", { name: "Approvals" })).toHaveAttribute(
    "aria-current",
    "page",
  );
});

test("hides admin pages from approvers", async () => {
  renderApp({ path: "/audit", session: PEOPLE.lena });

  expect(await screen.findByText("You cannot open this page")).toBeVisible();
  expect(within(menu()).queryByRole("link", { name: "Audit" })).not.toBeInTheDocument();
  expect(within(menu()).queryByRole("link", { name: "Tools" })).not.toBeInTheDocument();
  expect(screen.queryByRole("heading", { level: 1, name: "Audit" })).not.toBeInTheDocument();
});

test("shows every page to an admin", async () => {
  renderApp({ session: PEOPLE.root });

  await screen.findByRole("heading", { level: 1, name: "Approvals" });
  const links = within(menu())
    .getAllByRole("link")
    .map((link) => link.textContent);
  expect(links).toEqual(["Approvals", "Audit", "Tools"]);
});

test("tells a person with no role to ask for one", async () => {
  renderApp({ session: PEOPLE.olivia });

  expect(await screen.findByText("No console access yet")).toBeVisible();
  expect(within(menu()).queryAllByRole("link")).toHaveLength(0);
});

test("names the person and the tenant in the header", async () => {
  renderApp({ session: PEOPLE.lena });

  const header = await screen.findByRole("banner");
  expect(within(header).getByText("Lena Fischer")).toBeVisible();
  expect(within(header).getByText("acme")).toBeVisible();
  expect(within(header).getByText(/lena/)).toHaveTextContent("approver");
});

test("signs out from the header", async () => {
  const { signOut } = renderApp({ session: PEOPLE.lena });

  await userEvent.click(await screen.findByRole("button", { name: "Sign out" }));

  expect(signOut).toHaveBeenCalledOnce();
});

test("sends a signed out visitor to sign in and comes back to the same page", async () => {
  const { signIn } = renderApp({ path: "/tools?group=bank", session: null });

  expect(await screen.findByText("Signing you in")).toBeVisible();
  expect(signIn).toHaveBeenCalledExactlyOnceWith("/tools?group=bank");
});

test("says so when a page does not exist", async () => {
  renderApp({ path: "/nowhere", session: PEOPLE.lena });

  expect(await screen.findByText("There is no page here")).toBeVisible();
});

test("goes to the sign-in page once when several calls are refused for an expired token", async () => {
  const refused = () => json({ error: "unauthorized", reason: "expired" }, 401);
  const api = fakeApi({ "GET /audit": refused, "GET /audit/verify": refused });

  const { signIn } = renderApp({ path: "/audit", session: PEOPLE.root, api });

  await waitFor(() => {
    expect(api.calls.length).toBeGreaterThanOrEqual(2);
  });
  expect(signIn).toHaveBeenCalledTimes(1);
});

test("names the page and the number of waiting requests in the tab title", async () => {
  const api = approvalsApi([approval(), approval({ id: "01SECOND" })]);

  renderApp({ path: "/approvals", session: PEOPLE.lena, api });

  await waitFor(() => {
    expect(document.title).toBe("(2) Approvals - Keystone console");
  });
});
