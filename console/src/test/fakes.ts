import { vi } from "vitest";
import type { AuthClient, Session } from "../auth/types";

/** The people of the local Keycloak realm that the tests stand in for. */
export const PEOPLE = {
  lena: {
    username: "lena",
    name: "Lena Fischer",
    email: "lena@acme.test",
    tenant: "acme",
    roles: ["default-roles-keystone", "approver"],
  },
  root: {
    username: "root",
    name: "Root Admin",
    email: "root@acme.test",
    tenant: "acme",
    roles: ["default-roles-keystone", "admin"],
  },
  olivia: {
    username: "olivia",
    name: "Olivia Reyes",
    email: "olivia@acme.test",
    tenant: "acme",
    roles: ["default-roles-keystone"],
  },
} satisfies Record<string, Session>;

export function fakeAuth(session: Session | null) {
  const signIn = vi.fn<AuthClient["signIn"]>(() => Promise.resolve());
  const signOut = vi.fn<AuthClient["signOut"]>(() => Promise.resolve());
  const client: AuthClient = {
    session: () => session,
    subscribe: () => () => undefined,
    accessToken: () => Promise.resolve(session ? "test-token" : null),
    signIn,
    completeSignIn: () => Promise.resolve("/"),
    signOut,
  };
  return { client, signIn, signOut };
}

export interface RecordedCall {
  method: string;
  /** The path below the API prefix, without the query. */
  path: string;
  query: URLSearchParams;
  body: unknown;
  authorization: string | null;
}

type Responder = (call: RecordedCall, params: Record<string, string>) => unknown;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * A stand-in for the admin API. `routes` maps "METHOD /path" (with `:name` for a path part) to the
 * answer, or to a function that makes it. A function may return a `Response` for an error. Every
 * call is recorded, and a call with no route answers 404 so a missing fake shows up in the test.
 */
export function fakeApi(routes: Record<string, unknown> = {}) {
  const compiled = Object.entries(routes).map(([key, handler]) => {
    const [method = "GET", pattern = "/"] = key.split(" ");
    const source = pattern.replace(/:(\w+)/g, "(?<$1>[^/]+)");
    return { method, regex: new RegExp(`^${source}$`), handler };
  });
  const calls: RecordedCall[] = [];

  const fetchImpl: typeof fetch = async (input, init) => {
    const address =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(address, "http://console.test");
    const headers = new Headers(init?.headers);
    const call: RecordedCall = {
      method: (init?.method ?? "GET").toUpperCase(),
      path: url.pathname.replace(/^\/admin\/api\/v1/, ""),
      query: url.searchParams,
      body: typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined,
      authorization: headers.get("Authorization"),
    };
    calls.push(call);
    for (const route of compiled) {
      const found = route.method === call.method ? route.regex.exec(call.path) : null;
      if (!found) continue;
      const answer =
        typeof route.handler === "function"
          ? await (route.handler as Responder)(call, found.groups ?? {})
          : route.handler;
      return answer instanceof Response ? answer : json(answer);
    }
    return json(
      { error: "not_found", reason: `the test has no fake for ${call.method} ${call.path}` },
      404,
    );
  };

  return {
    fetch: fetchImpl,
    calls,
    to: (method: string, path: string) =>
      calls.filter((call) => call.method === method && call.path === path),
  };
}
