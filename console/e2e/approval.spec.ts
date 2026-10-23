import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { devEnv, urls } from "./support/dev-env";

const POLICY_DOCS = /docs\/policies\.md#approve-transfer-over-500$/;

/** What axe finds on the page as it is: WCAG 2.1 A and AA and its best practices. */
async function violations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"])
    .analyze();
  return results.violations.map((found) => ({
    rule: found.id,
    help: found.help,
    where: found.nodes.map((node) => node.target.join(" ")),
  }));
}

test("lena approves a pending transfer", async ({ page, request }) => {
  const env = devEnv();
  const transcript = process.env["KS_E2E_TRANSCRIPT"];
  if (!transcript) throw new Error("global setup did not start the agent");

  await test.step("lena signs in on Keycloak's own page and sees the Approvals menu only", async () => {
    await page.goto("/");
    await page.getByLabel("Username or email").fill("lena");
    await page.getByLabel("Password", { exact: true }).fill(env["LENA_PASSWORD"] ?? "");
    await page.getByRole("button", { name: "Sign In" }).click();

    await expect(page).toHaveURL(/\/approvals$/);
    const menu = page.getByRole("navigation", { name: "Main" });
    await expect(menu.getByRole("link")).toHaveText([/^Approvals/]);
    await expect(page.getByRole("banner")).toContainText("Lena Fischer");
  });

  // The newest request for this transfer: requests of earlier runs that nobody decided may still be
  // waiting above it, because the list is oldest first.
  const card = page
    .getByRole("article", { name: "bank__transfer" })
    .filter({ hasText: "invoice 4471" })
    .last();

  await test.step("the card says what is asked, by whom and why", async () => {
    await expect(card).toBeVisible();
    await expect(card.getByText("high", { exact: true })).toBeVisible();
    await expect(card.getByText("olivia", { exact: true })).toBeVisible();
    await expect(card.getByText("ops-agent", { exact: true })).toBeVisible();
    await expect(card.getByText("900", { exact: true })).toBeVisible();
    await expect(card.getByRole("timer")).toHaveText(/^\d+:\d\d left$/);
    await expect(card.getByRole("link", { name: /approve-transfer-over-500/ })).toHaveAttribute(
      "href",
      POLICY_DOCS,
    );
  });

  const approvalId = await card.getAttribute("data-approval-id");
  expect(approvalId).toBeTruthy();

  await test.step("the page has no accessibility violations, in the light and the dark theme", async () => {
    expect(await violations(page)).toEqual([]);
    await page.emulateMedia({ colorScheme: "dark" });
    expect(await violations(page)).toEqual([]);
    await page.emulateMedia({ colorScheme: "light" });
  });

  await test.step("wait until Keystone has told the agent to wait", async () => {
    // Keystone holds a call for 10 seconds before it answers KS_APPROVAL_PENDING. An approval made
    // inside that time would finish the first call and leave the await tool nothing to do, so the
    // test waits for the pending answer, which the session's recent calls show.
    await card.getByRole("button", { name: /Recent calls in this session/ }).click();
    await expect(card.getByRole("table")).toContainText("KS_APPROVAL_PENDING", { timeout: 30_000 });
  });

  await test.step("lena approves it with a note", async () => {
    await card.getByLabel("Note").fill("e2e: invoice 4471");
    await card.getByRole("button", { name: "Approve" }).click();

    await expect(page.getByText("Approved bank__transfer")).toBeVisible();
    await expect(page.locator(`article[data-approval-id="${approvalId}"]`)).toHaveCount(0);
  });

  await test.step("the agent's transcript shows the transfer, completed after the wait", async () => {
    await expect
      .poll(() => readFileSync(transcript, "utf8"), {
        message: "the agent's transcript, written when its script ends",
        timeout: 30_000,
      })
      .toContain('"status": "completed"');

    const text = readFileSync(transcript, "utf8");
    expect(text).toMatch(/^1\. ok\s+bank__transfer\s.*"amount": 900/m);
    expect(text).toContain(`answered KS_APPROVAL_PENDING; waited for approval ${approvalId ?? ""}`);
    expect(text).not.toMatch(/^\d+\. FAIL/m);
  });

  await test.step("the bank holds the transfer, once", async () => {
    const response = await request.get(`${urls(env).bank}/_state`);
    expect(response.ok()).toBe(true);
    const state = (await response.json()) as { transfers: Record<string, unknown>[] };
    expect(state.transfers).toEqual([
      { id: "t1", from: "CHK-001", to: "SAV-002", amount: 900, memo: "invoice 4471" },
    ]);
  });
});
