import type { paths } from "./schema";

/**
 * A small typed client for the admin API. The routes, their parameters and their answers all come
 * from `schema.d.ts`, which `pnpm gen:api` writes from the API's own schema, so a route that
 * changes shape stops this file from compiling instead of failing in a browser.
 */

type Method = "get" | "post";

type PathsWith<M extends Method> = {
  [P in keyof paths]: [NonNullable<paths[P][M]>] extends [never] ? never : P;
}[keyof paths];

type Operation<P extends keyof paths, M extends Method> = NonNullable<paths[P][M]>;

type ParametersOf<O> = O extends { parameters: infer P } ? P : never;

type PathPart<O> =
  ParametersOf<O> extends { path: infer X extends Record<string, string | number> }
    ? { path: X }
    : unknown;

type QueryPart<O> =
  ParametersOf<O> extends { query?: infer Q }
    ? [NonNullable<Q>] extends [never]
      ? unknown
      : { query?: NonNullable<Q> }
    : unknown;

type BodyOf<O> = O extends { requestBody?: infer R } ? NonNullable<R> : never;

type JsonBody<O> = BodyOf<O> extends { content: { "application/json": infer B } } ? B : never;

/** A required body is `body`, an optional one (the schema allows none) is `body?`, none is nothing. */
type BodyPart<O> = [BodyOf<O>] extends [never]
  ? unknown
  : O extends { requestBody: unknown }
    ? { body: JsonBody<O> }
    : { body?: NonNullable<JsonBody<O>> };

export type RequestOptions<O> = PathPart<O> & QueryPart<O> & BodyPart<O> & { signal?: AbortSignal };

export type Answer<O> = O extends {
  responses: { 200: { content: { "application/json": infer R } } };
}
  ? R
  : never;

type Arguments<O> = keyof RequestOptions<O> extends "signal"
  ? [options?: RequestOptions<O>]
  : [options: RequestOptions<O>];

export interface Api {
  get: <P extends PathsWith<"get">>(
    path: P,
    ...options: Arguments<Operation<P, "get">>
  ) => Promise<Answer<Operation<P, "get">>>;
  post: <P extends PathsWith<"post">>(
    path: P,
    ...options: Arguments<Operation<P, "post">>
  ) => Promise<Answer<Operation<P, "post">>>;
}

/** An answer that is not a success, or no answer at all (`status` 0). */
export class ApiError extends Error {
  readonly status: number;
  /** The API's short error name (`conflict`, `forbidden`), when it sent one. */
  readonly code: string | null;
  /** With a 409 on an approval: what the request is now (`approved`, `expired`, ...). */
  readonly state: string | null;

  constructor(
    status: number,
    message: string,
    code: string | null = null,
    state: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.state = state;
  }
}

export interface ApiDeps {
  /** Where the API is served from. The dev server proxies this prefix to Keystone. */
  baseUrl: string;
  /** A valid access token, or null when nobody is signed in. */
  getToken: () => Promise<string | null>;
  /** Called on a 401 so that the person is sent to sign in again. */
  onUnauthorized?: () => void;
  fetch?: typeof fetch;
}

interface Call {
  path?: Record<string, string | number>;
  query?: Record<string, unknown>;
  body?: unknown;
  signal?: AbortSignal;
}

function expand(template: string, values: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = values[key];
    if (value === undefined) throw new Error(`the path ${template} needs ${key}`);
    return encodeURIComponent(String(value));
  });
}

function search(query: Record<string, unknown> = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      if (value !== "") params.set(key, String(value));
    }
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

async function failure(response: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // An answer with no JSON body (a proxy's 502, say) is described by its status line.
  }
  const fields = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  const reason = typeof fields["reason"] === "string" ? fields["reason"] : null;
  const code = typeof fields["error"] === "string" ? fields["error"] : null;
  const state = typeof fields["status"] === "string" ? fields["status"] : null;
  const fallback = response.statusText || `The server answered ${response.status}.`;
  return new ApiError(response.status, reason ?? fallback, code, state);
}

export function createApi(deps: ApiDeps): Api {
  const send = async (method: "GET" | "POST", template: string, call: Call): Promise<unknown> => {
    const token = await deps.getToken();
    if (token === null) {
      deps.onUnauthorized?.();
      throw new ApiError(401, "You are signed out.", "unauthenticated");
    }
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    };
    const init: RequestInit = { method, headers };
    if (call.signal) init.signal = call.signal;
    if (call.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(call.body);
    }
    const url = `${deps.baseUrl}${expand(template, call.path)}${search(call.query)}`;
    let response: Response;
    try {
      response = await (deps.fetch ?? fetch)(url, init);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new ApiError(0, "Cannot reach Keystone. Check that it is running.", "unreachable");
    }
    if (response.status === 401) deps.onUnauthorized?.();
    if (!response.ok) throw await failure(response);
    return response.json();
  };

  // The answer is the 200 body that the schema promises. Nothing checks it at run time, so the
  // one place that trusts the server is here.
  return {
    get: (path, ...options) => send("GET", path, options[0] ?? {}) as never,
    post: (path, ...options) => send("POST", path, options[0] ?? {}) as never,
  };
}
