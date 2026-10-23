import { EmptyState, PageHeader } from "../components/StateViews";

export function Audit() {
  return (
    <>
      <PageHeader title="Audit">Every decision Keystone made, newest first.</PageHeader>
      <EmptyState icon="audit" title="Nothing to show yet">
        This page is not wired up yet.
      </EmptyState>
    </>
  );
}
