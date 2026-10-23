import { Button } from "../components/Button";
import { FullPage } from "../components/FullPage";
import { useAuthClient } from "./context";

export function SignedOut() {
  const client = useAuthClient();
  return (
    <FullPage
      title="You are signed out"
      actions={
        <Button
          variant="primary"
          onClick={() => {
            void client.signIn("/");
          }}
        >
          Sign in
        </Button>
      }
    >
      Your session at the identity provider has ended.
    </FullPage>
  );
}
