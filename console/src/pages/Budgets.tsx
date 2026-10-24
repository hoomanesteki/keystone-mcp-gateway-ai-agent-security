import { useId } from "react";
import { useBudgets } from "../api/budgets";
import type { BudgetInfo } from "../api/types";
import { Badge, type Tone } from "../components/Badge";
import { Icon } from "../components/Icon";
import { EmptyState, ErrorState, LoadingList, PageHeader } from "../components/StateViews";
import {
  barWidth,
  formatUsd,
  formatUtc,
  groupByScope,
  percent,
  SCOPE_TITLES,
  share,
  standing,
  untilReset,
  windowLabel,
  type Standing,
} from "../lib/budgets";
import { useNow } from "../lib/useNow";
import { usePageTitle } from "../lib/usePageTitle";

const INTRO =
  "Spend against each limit in the current window. Days and months are counted in UTC. A call " +
  "that would take the spend over a limit is refused before it runs.";

/** The word comes first; the bar's color and the badge's repeat it. */
const LOOKS: Record<Standing, { tone: Tone; word: string; bar: string }> = {
  ok: { tone: "ok", word: "within limit", bar: "bg-ok-fg" },
  near: { tone: "warn", word: "near limit", bar: "bg-warn-fg" },
  at: { tone: "danger", word: "at limit", bar: "bg-danger-fg" },
  over: { tone: "danger", word: "over limit", bar: "bg-danger-fg" },
};

function Bar({ budget, now }: { budget: BudgetInfo; now: number }) {
  const heading = useId();
  const ratio = share(budget.spent_usd, budget.limit_usd);
  const look = LOOKS[standing(ratio)];
  const spent = formatUsd(budget.spent_usd);
  const limit = formatUsd(budget.limit_usd);
  return (
    <li className="px-4 py-4">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <div className="flex items-baseline gap-2">
          <h3 id={heading} className="font-medium">
            {budget.scope_id}
          </h3>
          <span className="text-fg-subtle">{windowLabel(budget.window)}</span>
        </div>
        <Badge tone={look.tone}>{look.word}</Badge>
      </div>
      <div className="mt-2 flex items-baseline justify-between gap-4 tabular-nums">
        <span>
          <span className="font-semibold">{spent}</span>
          <span className="text-fg-muted"> of {limit}</span>
        </span>
        <span className="text-fg-muted">{percent(ratio)}%</span>
      </div>
      <div
        role="progressbar"
        aria-labelledby={heading}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.min(100, percent(ratio))}
        aria-valuetext={`${spent} of ${limit}, ${percent(ratio)}%, ${look.word}`}
        className="mt-2 h-2.5 overflow-hidden rounded-full bg-sunken ring-1 ring-line ring-inset"
      >
        <div
          className={`h-full rounded-full ${look.bar}`}
          style={{ width: `${barWidth(ratio)}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-fg-subtle">
        Resets in {untilReset(budget.resets_at, now)}, at{" "}
        <time dateTime={budget.resets_at}>{formatUtc(budget.resets_at)}</time>
      </p>
    </li>
  );
}

export function Budgets() {
  const budgets = useBudgets();
  const now = useNow(30_000);
  usePageTitle("Budgets");

  if (budgets.isPending) {
    return (
      <>
        <PageHeader title="Budgets">{INTRO}</PageHeader>
        <LoadingList label="Loading budgets" />
      </>
    );
  }
  if (budgets.isError) {
    return (
      <>
        <PageHeader title="Budgets">{INTRO}</PageHeader>
        <ErrorState
          title="Could not load the budgets"
          error={budgets.error}
          onRetry={() => {
            void budgets.refetch();
          }}
        />
      </>
    );
  }

  const full = budgets.data.filter(
    (budget) => share(budget.spent_usd, budget.limit_usd) >= 1,
  ).length;
  return (
    <>
      <PageHeader title="Budgets">{INTRO}</PageHeader>
      {full > 0 ? (
        <p
          role="status"
          className="mb-5 flex items-center gap-2 rounded-md border border-danger-line bg-danger-bg px-4 py-2.5 text-danger-fg"
        >
          <Icon name="alert" />
          {full === 1 ? "1 budget is" : `${full} budgets are`} at its limit. Calls that cost money
          for it are refused until its window resets.
        </p>
      ) : null}
      {budgets.data.length === 0 ? (
        <EmptyState icon="budgets" title="No budgets are set">
          Budgets are listed in the config file, under budgets. Until one is set, spend is recorded
          and nothing is refused for it.
        </EmptyState>
      ) : (
        <div className="space-y-6">
          {groupByScope(budgets.data).map((group) => (
            <section
              key={group.scope}
              aria-labelledby={`scope-${group.scope}`}
              className="rounded-lg border border-line bg-surface shadow-card"
            >
              <div className="flex items-baseline gap-3 border-b border-line px-4 py-3">
                <h2 id={`scope-${group.scope}`} className="text-[15px] font-semibold">
                  {SCOPE_TITLES[group.scope]}
                </h2>
                <span className="text-fg-subtle">
                  {group.budgets.length} {group.budgets.length === 1 ? "budget" : "budgets"}
                </span>
              </div>
              <ul className="divide-y divide-line">
                {group.budgets.map((budget) => (
                  <Bar key={`${budget.scope_id}-${budget.window}`} budget={budget} now={now} />
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </>
  );
}
