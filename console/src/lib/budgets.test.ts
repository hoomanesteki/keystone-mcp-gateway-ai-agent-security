import { describe, expect, test } from "vitest";
import type { BudgetInfo } from "../api/types";
import {
  barWidth,
  formatUsd,
  formatUtc,
  groupByScope,
  percent,
  share,
  standing,
  untilReset,
  windowLabel,
} from "./budgets";

function budget(overrides: Partial<BudgetInfo>): BudgetInfo {
  return {
    scope: "user",
    scope_id: "lena",
    window: "day",
    limit_usd: "0.03",
    spent_usd: "0",
    window_start: "2026-10-24T00:00:00Z",
    resets_at: "2026-10-25T00:00:00Z",
    ...overrides,
  };
}

describe("formatUsd", () => {
  test.each([
    ["0.03", "$0.03"],
    ["25", "$25.00"],
    ["5.5", "$5.50"],
    ["0.000192", "$0.000192"],
    ["0.0104", "$0.0104"],
    ["0.000576000", "$0.000576"],
    ["0", "$0.00"],
    ["1234.5", "$1,234.50"],
  ])("%s is %s", (amount, shown) => {
    expect(formatUsd(amount)).toBe(shown);
  });

  test("an amount below the smallest shown is not shown as nothing", () => {
    expect(formatUsd("0.0000001")).toBe("less than $0.000001");
  });

  test("a value that is not a number is shown as it came", () => {
    expect(formatUsd("n/a")).toBe("n/a");
  });
});

describe("share", () => {
  test("is spend over limit", () => {
    expect(share("0.015", "0.03")).toBeCloseTo(0.5);
    expect(share("0.03", "0.03")).toBe(1);
    expect(share("0.04", "0.03")).toBeCloseTo(1.3333, 3);
  });

  test("is nothing when it cannot be told", () => {
    expect(share("x", "0.03")).toBe(0);
    expect(share("1", "0")).toBe(0);
    expect(share("-1", "5")).toBe(0);
  });
});

describe("standing", () => {
  test.each([
    [0, "ok"],
    [0.79, "ok"],
    [0.8, "near"],
    [0.99, "near"],
    [1, "at"],
    [1.01, "over"],
  ] as const)("%s is %s", (ratio, expected) => {
    expect(standing(ratio)).toBe(expected);
  });
});

describe("percent and barWidth", () => {
  test("never say 100 before the limit is reached", () => {
    expect(percent(0.996)).toBe(99);
    expect(percent(1)).toBe(100);
    expect(percent(1.3334)).toBe(133);
  });

  test("the bar stops at the end of the track", () => {
    expect(barWidth(0.5)).toBe(50);
    expect(barWidth(1.5)).toBe(100);
    expect(barWidth(-1)).toBe(0);
  });
});

describe("groupByScope", () => {
  test("puts the tenant first, then users, then agents, each by name with the day before the month", () => {
    const groups = groupByScope([
      budget({ scope: "agent", scope_id: "ops-agent", window: "month" }),
      budget({ scope: "user", scope_id: "olivia", window: "month" }),
      budget({ scope: "user", scope_id: "lena", window: "month" }),
      budget({ scope: "user", scope_id: "lena", window: "day" }),
      budget({ scope: "tenant", scope_id: "acme", window: "day" }),
    ]);

    expect(groups.map((group) => group.scope)).toEqual(["tenant", "user", "agent"]);
    expect(groups[1]?.budgets.map((b) => `${b.scope_id} ${b.window}`)).toEqual([
      "lena day",
      "lena month",
      "olivia month",
    ]);
  });

  test("leaves out a scope with no budget", () => {
    expect(
      groupByScope([budget({ scope: "tenant", scope_id: "acme" })]).map((g) => g.scope),
    ).toEqual(["tenant"]);
    expect(groupByScope([])).toEqual([]);
  });
});

describe("time", () => {
  test("a window ends in UTC", () => {
    expect(formatUtc("2026-10-25T00:00:00Z")).toBe("Oct 25, 00:00 UTC");
    expect(formatUtc("2026-11-01T00:00:00.000000Z")).toBe("Nov 1, 00:00 UTC");
  });

  test.each([
    [30_000, "less than a minute"],
    [5 * 60_000, "5 min"],
    [5 * 3_600_000 + 12 * 60_000, "5 h 12 min"],
    [27 * 3_600_000, "1 day 3 h"],
    [30 * 3_600_000 + 60_000, "1 day 6 h"],
    [3 * 24 * 3_600_000 + 2 * 3_600_000, "3 days 2 h"],
    [-10_000, "less than a minute"],
  ])("%s ms before the reset reads %s", (before, text) => {
    const now = Date.parse("2026-10-24T12:00:00Z");
    expect(untilReset(new Date(now + before).toISOString(), now)).toBe(text);
  });

  test("the windows have names", () => {
    expect(windowLabel("day")).toBe("a day");
    expect(windowLabel("month")).toBe("a month");
  });
});
