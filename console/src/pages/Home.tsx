import { Navigate } from "react-router";
import { pagesFor } from "../auth/roles";
import { useSignedIn } from "../auth/context";
import { EmptyState } from "../components/StateViews";

/** The address `/`: the first page the person may open, or an explanation if there is none. */
export function Home() {
  const session = useSignedIn();
  const [first] = pagesFor(session);
  if (first) return <Navigate to={first.path} replace />;
  return (
    <EmptyState icon="lock" title="No console access yet">
      You are signed in as {session.username}, but your account has neither the approver nor the
      admin role. Ask an administrator to add you to the approvers or admins group.
    </EmptyState>
  );
}
