import { EmptyState, PageHeader } from "../components/StateViews";

export function Tools() {
  return (
    <>
      <PageHeader title="Tools">The tools Keystone offers, grouped by upstream.</PageHeader>
      <EmptyState icon="tools" title="Nothing to show yet">
        This page is not wired up yet.
      </EmptyState>
    </>
  );
}
