import { Fragment, useId, useState } from "react";
import { useToolSwitch, useTools } from "../api/tools";
import type { ToolSummary } from "../api/types";
import { Badge, RiskBadge, ToolStatusBadge } from "../components/Badge";
import { Button } from "../components/Button";
import { Icon } from "../components/Icon";
import { EmptyState, ErrorState, LoadingList, PageHeader } from "../components/StateViews";
import { ToolReview } from "../components/ToolReview";
import { formatCost } from "../lib/format";
import { describeReason, groupByUpstream } from "../lib/tools";

const HEADINGS = ["Tool", "Risk", "Tags", "Status", "Cost per call", "Actions"];

function Row({ tool }: { tool: ToolSummary }) {
  const [open, setOpen] = useState(false);
  const toggle = useToolSwitch();
  const panel = useId();
  const quarantined = tool.status === "quarantined";
  return (
    <Fragment>
      <tr className="align-top">
        <td className="px-4 py-2.5">
          <div className="font-mono font-medium">{tool.name}</div>
          {tool.status !== "active" && tool.reason ? (
            <div className="mt-0.5 text-xs text-fg-subtle">{describeReason(tool.reason)}</div>
          ) : null}
        </td>
        <td className="px-4 py-2.5">
          <RiskBadge risk={tool.risk} />
        </td>
        <td className="px-4 py-2.5">
          <div className="flex flex-wrap gap-1">
            {tool.tags.length === 0 ? <span className="text-fg-subtle">none</span> : null}
            {tool.tags.map((tag) => (
              <Badge key={tag}>
                <span className="font-mono">{tag}</span>
              </Badge>
            ))}
          </div>
        </td>
        <td className="px-4 py-2.5">
          <ToolStatusBadge status={tool.status} />
        </td>
        <td className="px-4 py-2.5 whitespace-nowrap text-fg-muted tabular-nums">
          {formatCost(tool.cost_per_call_usd)}
        </td>
        <td className="px-4 py-2.5 text-right whitespace-nowrap">
          {quarantined ? (
            <Button
              size="sm"
              aria-expanded={open}
              aria-controls={panel}
              onClick={() => {
                setOpen((was) => !was);
              }}
            >
              <Icon name={open ? "chevronDown" : "chevronRight"} />
              {open ? "Hide review" : "Review change"}
            </Button>
          ) : tool.status === "active" ? (
            <Button
              size="sm"
              disabled={toggle.isPending}
              aria-label={`Disable ${tool.name}`}
              onClick={() => {
                toggle.mutate({ tool, enable: false });
              }}
            >
              Disable
            </Button>
          ) : (
            <Button
              size="sm"
              disabled={toggle.isPending}
              aria-label={`Enable ${tool.name}`}
              onClick={() => {
                toggle.mutate({ tool, enable: true });
              }}
            >
              Enable
            </Button>
          )}
        </td>
      </tr>
      {quarantined && open ? (
        <tr id={panel} className="bg-sunken/50">
          <td colSpan={HEADINGS.length} className="px-4 py-4">
            {/* On a phone the table scrolls sideways. The review stays as wide as the visible part
                of it (100cqw is the scroll container's width) and stays in view while it scrolls. */}
            <div className="sticky left-4 w-[calc(100cqw-2rem)]">
              <ToolReview
                tool={tool}
                onDone={() => {
                  setOpen(false);
                }}
              />
            </div>
          </td>
        </tr>
      ) : null}
    </Fragment>
  );
}

export function Tools() {
  const tools = useTools();

  if (tools.isPending) {
    return (
      <>
        <PageHeader title="Tools">The tools Keystone offers, grouped by upstream.</PageHeader>
        <LoadingList label="Loading tools" />
      </>
    );
  }
  if (tools.isError) {
    return (
      <>
        <PageHeader title="Tools">The tools Keystone offers, grouped by upstream.</PageHeader>
        <ErrorState
          title="Could not load the tools"
          error={tools.error}
          onRetry={() => {
            void tools.refetch();
          }}
        />
      </>
    );
  }

  const held = tools.data.filter((tool) => tool.status === "quarantined").length;
  return (
    <>
      <PageHeader title="Tools">
        The tools Keystone offers, grouped by upstream. A tool whose definition changed waits here
        for a person to read the change.
      </PageHeader>

      {held > 0 ? (
        <p
          role="status"
          className="mb-5 flex items-center gap-2 rounded-md border border-warn-line bg-warn-bg px-4 py-2.5 text-warn-fg"
        >
          <Icon name="alert" />
          {held === 1 ? "1 tool is" : `${held} tools are`} waiting for review. Agents cannot see
          {held === 1 ? " it" : " them"} until {held === 1 ? "it is" : "they are"} approved.
        </p>
      ) : null}

      {tools.data.length === 0 ? (
        <EmptyState icon="tools" title="No tools yet">
          Tools appear here when an upstream has been registered and synced.
        </EmptyState>
      ) : (
        <div className="space-y-6">
          {groupByUpstream(tools.data).map((group) => (
            <section
              key={group.upstream}
              aria-labelledby={`upstream-${group.upstream}`}
              className="rounded-lg border border-line bg-surface shadow-card"
            >
              <div className="flex items-baseline gap-3 border-b border-line px-4 py-3">
                <h2
                  id={`upstream-${group.upstream}`}
                  className="font-mono text-[15px] font-semibold"
                >
                  {group.upstream}
                </h2>
                <span className="text-fg-subtle">
                  {group.tools.length} {group.tools.length === 1 ? "tool" : "tools"}
                </span>
              </div>
              <div className="@container overflow-x-auto">
                <table className="w-full min-w-[48rem] table-fixed text-left text-[13px]">
                  <caption className="sr-only">Tools of the upstream {group.upstream}</caption>
                  <colgroup>
                    <col className="w-[26%]" />
                    <col className="w-[11%]" />
                    <col className="w-[21%]" />
                    <col className="w-[12%]" />
                    <col className="w-[11%]" />
                    <col className="w-[19%]" />
                  </colgroup>
                  <thead className="border-b border-line bg-sunken text-xs text-fg-subtle">
                    <tr>
                      {HEADINGS.map((heading) => (
                        <th
                          key={heading}
                          scope="col"
                          className={`px-4 py-2.5 font-medium ${heading === "Actions" ? "text-right" : ""}`}
                        >
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {group.tools.map((tool) => (
                      <Row key={tool.name} tool={tool} />
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
        </div>
      )}
    </>
  );
}
