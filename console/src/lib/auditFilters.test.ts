import { describe, expect, test } from "vitest";
import {
  draftFromParams,
  EMPTY_DRAFT,
  filtersFromDraft,
  hasFilters,
  paramsFromDraft,
} from "./auditFilters";

describe("the audit filters in the address", () => {
  test("go out and come back as they were", () => {
    const draft = {
      ...EMPTY_DRAFT,
      tool: "bank__transfer",
      effect: "deny" as const,
      since: "2026-10-23T09:30",
    };

    const params = paramsFromDraft(draft);

    expect(params.toString()).toBe("tool=bank__transfer&effect=deny&since=2026-10-23T09%3A30");
    expect(draftFromParams(params)).toEqual(draft);
  });

  test("leave nothing in the address when nothing is set", () => {
    expect(paramsFromDraft(EMPTY_DRAFT).toString()).toBe("");
    expect(hasFilters(EMPTY_DRAFT)).toBe(false);
  });

  test("ignore a decision or a result the API does not know", () => {
    const draft = draftFromParams(new URLSearchParams("effect=maybe&outcome=ok"));

    expect(draft.effect).toBe("");
    expect(draft.outcome).toBe("ok");
  });
});

describe("the times of the filters", () => {
  test("are made absolute from the person's local time", () => {
    const local = "2026-10-23T09:30";

    const { since, until } = filtersFromDraft({ ...EMPTY_DRAFT, since: local, until: "" });

    expect(since).toBe(new Date(local).toISOString());
    expect(until).toBe("");
  });

  test("are dropped when they are not times", () => {
    expect(filtersFromDraft({ ...EMPTY_DRAFT, since: "yesterday" }).since).toBe("");
  });
});
