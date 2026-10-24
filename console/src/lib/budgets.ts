import type { BudgetInfo } from "../api/types";

/** How a budget stands against its limit. The word is what a person reads; the color repeats it. */
export type Standing = "ok" | "near" | "at" | "over";

/** From this share of the limit a budget is "near". */
export const NEAR = 0.8;

const dollars = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 2,
  maximumFractionDigits: 6,
});
const SMALLEST = 0.000001;

/** US dollars for a person: `$0.03`, `$25.00`, `$0.000192`. A model request costs fractions of a
 * cent, so the cents are kept as far as there are any, to six places. */
export function formatUsd(amount: string | number): string {
  const value = Number(amount);
  if (!Number.isFinite(value)) return String(amount);
  if (value > 0 && value < SMALLEST) return `less than ${dollars.format(SMALLEST)}`;
  return dollars.format(value);
}

/** The share of the limit that is spent, 1 being all of it. A limit that is not a positive number
 * has nothing to be a share of. */
export function share(spent: string, limit: string): number {
  const total = Number(limit);
  const used = Number(spent);
  if (!Number.isFinite(total) || !Number.isFinite(used) || total <= 0 || used < 0) return 0;
  return used / total;
}

export function standing(ratio: number): Standing {
  if (ratio > 1) return "over";
  if (ratio === 1) return "at";
  return ratio >= NEAR ? "near" : "ok";
}

/** Whole percent for the label. Never 100 before the limit is reached: 99.6% reads 99%. */
export function percent(ratio: number): number {
  return ratio >= 1 ? Math.round(ratio * 100) : Math.floor(ratio * 100);
}

/** The width of the filled part of a bar, 0 to 100, whatever the share. */
export function barWidth(ratio: number): number {
  return Math.min(100, Math.max(0, ratio * 100));
}

const SCOPES: readonly BudgetInfo["scope"][] = ["tenant", "user", "agent"];
export const SCOPE_TITLES: Record<BudgetInfo["scope"], string> = {
  tenant: "Tenant",
  user: "Users",
  agent: "Agents",
};

export interface ScopeGroup {
  scope: BudgetInfo["scope"];
  budgets: BudgetInfo[];
}

/** The budgets by scope, the tenant's first, and in each the day before the month. A scope with no
 * budget has no group. */
export function groupByScope(budgets: readonly BudgetInfo[]): ScopeGroup[] {
  return SCOPES.map((scope) => ({
    scope,
    budgets: budgets
      .filter((budget) => budget.scope === scope)
      .sort(
        (a, b) =>
          a.scope_id.localeCompare(b.scope_id) ||
          (a.window === b.window ? 0 : a.window === "day" ? -1 : 1),
      ),
  })).filter((group) => group.budgets.length > 0);
}

export function windowLabel(window: BudgetInfo["window"]): string {
  return window === "day" ? "a day" : "a month";
}

const utc = new Intl.DateTimeFormat("en-US", {
  timeZone: "UTC",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

/** `Oct 25, 00:00 UTC`. Budget windows are counted in UTC, so they are shown in UTC. */
export function formatUtc(iso: string): string {
  return `${utc.format(new Date(iso))} UTC`;
}

/** How long until a window ends: `5 h 12 min`, `3 days 2 h`, `less than a minute`. */
export function untilReset(iso: string, now: number): string {
  const minutes = Math.floor((new Date(iso).getTime() - now) / 60_000);
  if (minutes < 1) return "less than a minute";
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ${minutes % 60} min`;
  const days = Math.floor(hours / 24);
  return `${days} ${days === 1 ? "day" : "days"} ${hours % 24} h`;
}
