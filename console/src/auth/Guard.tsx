import type { ReactNode } from "react";
import { EmptyState } from "../components/StateViews";
import { useSignedIn } from "./context";
import { canOpen, type Page } from "./roles";

/** A page for people who may open it. The API refuses everyone else too; this is the explanation. */
export function Guard({ page, children }: { page: Page; children: ReactNode }) {
  const session = useSignedIn();
  if (canOpen(session, page)) return children;
  return (
    <EmptyState icon="lock" title="You cannot open this page">
      This page is for administrators. Your account can use the pages in the menu.
    </EmptyState>
  );
}
