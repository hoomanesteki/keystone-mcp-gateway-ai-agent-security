import { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { App } from "../app";
import type { Session } from "../auth/types";
import { fakeApi, fakeAuth } from "./fakes";

interface Options {
  /** The address to start at. */
  path?: string;
  /** Who is signed in, or null for nobody. */
  session: Session | null;
  api?: ReturnType<typeof fakeApi>;
}

/** The whole console, as a person at `path` would see it, with the API faked. */
export function renderApp({ path = "/", session, api = fakeApi() }: Options) {
  const auth = fakeAuth(session);
  // No retries: a failed call must show its failure now, not after the backoff.
  const queries = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 2000 } },
  });
  const view = render(
    <MemoryRouter initialEntries={[path]}>
      <App auth={auth.client} fetch={api.fetch} queries={queries} />
    </MemoryRouter>,
  );
  return { ...view, ...auth, api };
}
