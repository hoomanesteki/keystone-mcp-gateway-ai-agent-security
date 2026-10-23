import { useEffect, useRef, useState, type ReactNode } from "react";
import { useLocation } from "react-router";
import { Button } from "../components/Button";
import { FullPage } from "../components/FullPage";
import { describeError } from "../lib/errors";
import { useAuthClient, useSession } from "./context";

/**
 * Shows its children to a signed-in person. Anyone else is sent to the identity provider, once:
 * if that fails (the provider is down), the person sees why and decides when to try again, so a
 * broken sign-in never turns into a redirect loop.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const client = useAuthClient();
  const session = useSession();
  const location = useLocation();
  const [failure, setFailure] = useState<unknown>(null);
  const started = useRef(false);

  const returnTo = `${location.pathname}${location.search}`;
  useEffect(() => {
    if (session || started.current) return;
    started.current = true;
    client.signIn(returnTo).catch((error: unknown) => {
      setFailure(error);
    });
  }, [client, session, returnTo]);

  if (session) return children;
  if (failure) {
    return (
      <FullPage
        title="Cannot reach the sign-in service"
        actions={
          <Button
            variant="primary"
            onClick={() => {
              setFailure(null);
              started.current = false;
            }}
          >
            Try again
          </Button>
        }
      >
        {describeError(failure)}
      </FullPage>
    );
  }
  return (
    <FullPage title="Signing you in">
      <span role="status">Taking you to the sign-in page.</span>
    </FullPage>
  );
}
