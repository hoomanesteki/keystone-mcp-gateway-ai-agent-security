import { EmptyState, PageHeader } from "../components/StateViews";

export function Approvals() {
  return (
    <>
      <PageHeader title="Approvals">Requests that wait for a person appear here.</PageHeader>
      <EmptyState icon="approvals" title="Nothing to show yet">
        This page is not wired up yet.
      </EmptyState>
    </>
  );
}
