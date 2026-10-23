import { useEffect, useRef } from "react";
import { useSearchParams } from "react-router";
import { useDecision, usePendingApprovals } from "../api/approvals";
import { ApprovalCard } from "../components/ApprovalCard";
import { Button } from "../components/Button";
import { Icon } from "../components/Icon";
import { EmptyState, ErrorState, LoadingList, PageHeader } from "../components/StateViews";

export function Approvals() {
  const pending = usePendingApprovals();
  const decide = useDecision();
  const [params] = useSearchParams();
  const wanted = params.get("id");
  const heading = useRef<HTMLDivElement>(null);

  // A decided card disappears under the person's hands, so focus goes to the top of the page
  // instead of to nothing.
  useEffect(() => {
    if (decide.isPending) heading.current?.focus();
  }, [decide.isPending]);

  return (
    <>
      <div ref={heading} tabIndex={-1} className="outline-none">
        <PageHeader title="Approvals">
          Calls that wait for a person. The list is read again every 5 seconds.
        </PageHeader>
      </div>

      {pending.isPending ? <LoadingList label="Loading approvals" /> : null}

      {pending.isError && !pending.data ? (
        <ErrorState
          title="Could not load the approvals"
          error={pending.error}
          onRetry={() => {
            void pending.refetch();
          }}
        />
      ) : null}

      {pending.data ? (
        <>
          {pending.isError ? (
            <div
              role="alert"
              className="mb-4 flex items-center gap-3 rounded-md border border-warn-line bg-warn-bg px-4 py-2.5 text-warn-fg"
            >
              <Icon name="alert" />
              <span className="flex-1">
                The list could not be refreshed. This is the last one that loaded.
              </span>
              <Button
                size="sm"
                onClick={() => {
                  void pending.refetch();
                }}
              >
                Try again
              </Button>
            </div>
          ) : null}

          {wanted && !pending.data.some((item) => item.id === wanted) ? (
            <p className="mb-4 flex items-center gap-2 rounded-md border border-line bg-surface px-4 py-2.5 text-fg-muted">
              <Icon name="info" />
              The request in the link is not waiting any more. Someone decided it or it expired.
            </p>
          ) : null}

          {pending.data.length === 0 ? (
            <EmptyState title="No approvals waiting">
              When an agent asks for something that needs a person, it appears here within 5
              seconds.
            </EmptyState>
          ) : (
            <div className="space-y-5">
              {pending.data.map((item) => (
                <ApprovalCard
                  key={item.id}
                  item={item}
                  receivedAt={pending.dataUpdatedAt}
                  highlighted={item.id === wanted}
                  onDecide={(approve, note) => {
                    decide.mutate({ item, approve, note });
                  }}
                />
              ))}
            </div>
          )}
        </>
      ) : null}
    </>
  );
}
