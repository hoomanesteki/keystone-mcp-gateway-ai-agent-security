import { describe, expect, test } from "vitest";
import { safeReturnTo, sessionFromClaims } from "./oidc";

describe("the claims of an ID token", () => {
  test("become the person the console shows", () => {
    expect(
      sessionFromClaims({
        preferred_username: "lena",
        name: "Lena Fischer",
        email: "lena@acme.test",
        tenant: "acme",
        roles: ["default-roles-keystone", "approver"],
      }),
    ).toEqual({
      username: "lena",
      name: "Lena Fischer",
      email: "lena@acme.test",
      tenant: "acme",
      roles: ["default-roles-keystone", "approver"],
    });
  });

  test("never turn a missing or odd claim into a role", () => {
    const session = sessionFromClaims({
      preferred_username: "alice",
      roles: ["admin", 7, null, { role: "admin" }],
    });

    expect(session.roles).toEqual(["admin"]);
    expect(session.name).toBe("alice");
    expect(session.tenant).toBe("");
    expect(sessionFromClaims({ roles: "admin" }).roles).toEqual([]);
  });
});

describe("where to go after signing in", () => {
  test.each(["/approvals", "/approvals?id=01J0", "/tools#bank"])("follows %s", (path) => {
    expect(safeReturnTo(path)).toBe(path);
  });

  test.each([
    "https://evil.test/",
    "//evil.test/",
    "/\\evil.test",
    "approvals",
    "javascript:alert(1)",
    "",
    undefined,
    42,
  ])("does not follow %s", (value) => {
    expect(safeReturnTo(value)).toBe("/");
  });
});
