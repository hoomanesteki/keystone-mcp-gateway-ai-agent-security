import { describe, expect, test, vi } from "vitest";
import { ApiError, createApi } from "./client";
import { fakeApi, json } from "../test/fakes";

function clientFor(api: ReturnType<typeof fakeApi>, token: string | null = "t0ken") {
  const onUnauthorized = vi.fn();
  const client = createApi({
    baseUrl: "/admin/api/v1",
    getToken: () => Promise.resolve(token),
    onUnauthorized,
    fetch: api.fetch,
  });
  return { client, onUnauthorized };
}

describe("the admin API client", () => {
  test("sends the token, the query and the body, and expands path parameters", async () => {
    const api = fakeApi({
      "GET /audit": { items: [], next_cursor: null },
      "POST /approvals/:id/decision": { id: "a/b" },
    });
    const { client } = clientFor(api);

    await client.get("/audit", { query: { tool: "bank__transfer", user: "", limit: 25 } });
    await client.post("/approvals/{approval_id}/decision", {
      path: { approval_id: "a/b" },
      body: { approve: true },
    });

    const [search, decision] = api.calls;
    expect(search?.authorization).toBe("Bearer t0ken");
    expect([...(search?.query ?? [])]).toEqual([
      ["tool", "bank__transfer"],
      ["limit", "25"],
    ]);
    expect(decision?.path).toBe("/approvals/a%2Fb/decision");
    expect(decision?.body).toEqual({ approve: true });
  });

  test("turns an error answer into an ApiError that says what the API said", async () => {
    const api = fakeApi({
      "POST /approvals/:id/decision": () =>
        json({ error: "conflict", reason: "it is no longer pending", status: "approved" }, 409),
    });
    const { client } = clientFor(api);

    const failure = await client
      .post("/approvals/{approval_id}/decision", {
        path: { approval_id: "x" },
        body: { approve: false },
      })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ApiError);
    expect(failure).toMatchObject({
      status: 409,
      code: "conflict",
      state: "approved",
      message: "it is no longer pending",
    });
  });

  test("describes an answer with no JSON body by its status", async () => {
    const api = fakeApi({ "GET /tools": () => new Response("bad gateway", { status: 502 }) });
    const { client } = clientFor(api);

    await expect(client.get("/tools", {})).rejects.toMatchObject({ status: 502 });
  });

  test("reports an API that cannot be reached as status 0", async () => {
    const client = createApi({
      baseUrl: "/admin/api/v1",
      getToken: () => Promise.resolve("t"),
      fetch: () => Promise.reject(new TypeError("Failed to fetch")),
    });

    await expect(client.get("/tools", {})).rejects.toMatchObject({
      status: 0,
      code: "unreachable",
    });
  });

  test("asks to sign in again when the API says 401, and when there is no token", async () => {
    const api = fakeApi({
      "GET /tools": () => json({ error: "unauthorized", reason: "token expired" }, 401),
    });
    const refused = clientFor(api);
    const signedOut = clientFor(api, null);

    await expect(refused.client.get("/tools", {})).rejects.toMatchObject({ status: 401 });
    await expect(signedOut.client.get("/tools", {})).rejects.toMatchObject({ status: 401 });

    expect(refused.onUnauthorized).toHaveBeenCalledOnce();
    expect(signedOut.onUnauthorized).toHaveBeenCalledOnce();
    expect(api.calls).toHaveLength(1);
  });
});
