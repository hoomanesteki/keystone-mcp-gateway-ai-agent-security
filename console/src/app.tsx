import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { Route, Routes } from "react-router";
import { ApiContext } from "./api/context";
import { ApiError, createApi } from "./api/client";
import { AuthContext } from "./auth/context";
import { Callback } from "./auth/Callback";
import { Guard } from "./auth/Guard";
import { RequireAuth } from "./auth/RequireAuth";
import { SignedOut } from "./auth/SignedOut";
import type { AuthClient } from "./auth/types";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Layout } from "./components/Layout";
import { ToastProvider } from "./components/ToastProvider";
import { config } from "./config";
import { Approvals } from "./pages/Approvals";
import { Audit } from "./pages/Audit";
import { Home } from "./pages/Home";
import { NotFound } from "./pages/NotFound";
import { Tools } from "./pages/Tools";

export interface AppProps {
  auth: AuthClient;
  /** Replaces the browser's fetch, for tests. */
  fetch?: typeof fetch;
  /** Replaces the query cache, for tests that must not wait for a retry. */
  queries?: QueryClient;
}

/** An answer in the 4xx range will not change by asking again; a network failure might. */
function shouldRetry(count: number, error: unknown): boolean {
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
  return count < 2;
}

/** The whole console. The router is the caller's, so tests can start at any address. */
export function App({ auth, fetch: fetchImpl, queries: given }: AppProps) {
  const [api] = useState(() =>
    createApi({
      baseUrl: config.apiBase,
      getToken: () => auth.accessToken(),
      // A token the API refuses is one that was revoked or expired: sign in again.
      onUnauthorized: () => {
        void auth.signIn(`${window.location.pathname}${window.location.search}`);
      },
      ...(fetchImpl ? { fetch: fetchImpl } : {}),
    }),
  );
  const [queries] = useState(
    () =>
      given ??
      new QueryClient({ defaultOptions: { queries: { retry: shouldRetry, staleTime: 2000 } } }),
  );

  return (
    <ErrorBoundary>
      <AuthContext value={auth}>
        <ApiContext value={api}>
          <QueryClientProvider client={queries}>
            <ToastProvider>
              <Routes>
                <Route path="/auth/callback" element={<Callback />} />
                <Route path="/signed-out" element={<SignedOut />} />
                <Route
                  element={
                    <RequireAuth>
                      <Layout />
                    </RequireAuth>
                  }
                >
                  <Route index element={<Home />} />
                  <Route
                    path="approvals"
                    element={
                      <Guard page="approvals">
                        <Approvals />
                      </Guard>
                    }
                  />
                  <Route
                    path="audit"
                    element={
                      <Guard page="audit">
                        <Audit />
                      </Guard>
                    }
                  />
                  <Route
                    path="tools"
                    element={
                      <Guard page="tools">
                        <Tools />
                      </Guard>
                    }
                  />
                  <Route path="*" element={<NotFound />} />
                </Route>
              </Routes>
            </ToastProvider>
          </QueryClientProvider>
        </ApiContext>
      </AuthContext>
    </ErrorBoundary>
  );
}
