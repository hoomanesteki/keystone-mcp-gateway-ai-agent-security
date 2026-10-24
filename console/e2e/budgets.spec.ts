import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { devEnv } from "./support/dev-env";

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

/** The page has nothing axe objects to in either theme. */
async function accessibleInBothThemes(page: Page) {
  expect(await violations(page)).toEqual([]);
  await page.emulateMedia({ colorScheme: "dark" });
  expect(await violations(page)).toEqual([]);
  await page.emulateMedia({ colorScheme: "light" });
}

test("root reads the budgets and the live sessions", async ({ page }) => {
  const env = devEnv();

  await test.step("root signs in and has all five pages in the menu", async () => {
    await page.goto("/");
    await page.getByLabel("Username or email").fill("root");
    await page.getByLabel("Password", { exact: true }).fill(env["ROOT_PASSWORD"] ?? "");
    await page.getByRole("button", { name: "Sign In" }).click();

    await expect(page).toHaveURL(/\/approvals$/);
    const menu = page.getByRole("navigation", { name: "Main" });
    await expect(menu.getByRole("link")).toHaveText([
      /^Approvals/,
      /^Audit/,
      /^Tools/,
      /^Budgets/,
      /^Sessions/,
    ]);
  });

  await test.step("the budgets page shows each limit with its spend and when it resets", async () => {
    await page
      .getByRole("navigation", { name: "Main" })
      .getByRole("link", { name: "Budgets" })
      .click();

    await expect(page).toHaveURL(/\/budgets$/);
    await expect(page.getByRole("heading", { level: 1, name: "Budgets" })).toBeVisible();
    // The compose config sets lena's day and the tenant's day (deploy/keystone.compose.yaml).
    const lena = page.getByRole("progressbar", { name: "lena" });
    await expect(lena).toBeVisible();
    await expect(page.getByRole("progressbar", { name: "acme" })).toBeVisible();
    await expect(lena).toHaveAttribute("aria-valuetext", /^\$[\d.,]+ of \$0\.03, \d+%, /);
    await expect(page.getByText(/^Resets in /).first()).toBeVisible();
    await expect(page.getByText(/UTC$/).first()).toBeVisible();
    await accessibleInBothThemes(page);
  });

  await test.step("the sessions page lists the open sessions, and a click opens their calls", async () => {
    await page
      .getByRole("navigation", { name: "Main" })
      .getByRole("link", { name: "Sessions" })
      .click();

    await expect(page).toHaveURL(/\/sessions$/);
    await expect(page.getByRole("heading", { level: 1, name: "Sessions" })).toBeVisible();
    const links = page.getByRole("link", { name: /^Open the audit log for / });
    // The agent that the test started opened a session, so there is at least one.
    await expect(links.first()).toBeVisible();
    await accessibleInBothThemes(page);

    await links.first().click();
    await expect(page).toHaveURL(/\/audit\?session=[0-9a-f]+$/);
    // The page changes a moment after the address does, and a label that is only a part of the
    // name of a link on the page before it would match a hundred of them.
    await expect(page.getByRole("heading", { level: 1, name: "Audit" })).toBeVisible();
    await expect(page.getByLabel("Session", { exact: true })).not.toHaveValue("");
  });
});
