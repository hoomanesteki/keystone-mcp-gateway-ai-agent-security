import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router";
import { Button } from "../components/Button";
import { FullPage } from "../components/FullPage";
import { describeError } from "../lib/errors";
import { useAuthClient, useSession } from "./context";

/** The page the identity provider sends the browser back to, with a code in the address. */
export function Callback() {
  const client = useAuthClient();
  const session = useSession();
  const navigate = useNavigate();
  const [failure, setFailure] = useState<unknown>(null);

  useEffect(() => {
    let cancelled = false;
    client
      .completeSignIn()
      .then((to) => {
        if (!cancelled) void navigate(to, { replace: true });
      })
      .catch((error: unknown) => {
        if (!cancelled) setFailure(error);
      });
    return () => {
      cancelled = true;
    };
  }, [client, navigate]);

  // Back to this address after signing in (the browser's back button): nothing is left to finish.
  if (session && !failure) return <Navigate to="/" replace />;
  if (failure) {
    return (
      <FullPage
        title="Sign-in did not finish"
        actions={
          <Button
            variant="primary"
            onClick={() => {
              void client.signIn("/");
            }}
          >
            Sign in again
          </Button>
        }
      >
        {describeError(failure)}
      </FullPage>
    );
  }
  return (
    <FullPage title="Finishing sign-in">
      <span role="status">One moment.</span>
    </FullPage>
  );
}
