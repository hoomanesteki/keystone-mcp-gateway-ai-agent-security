import { describe, expect, test } from "vitest";
import { tool } from "../test/fixtures";
import { describeReason, describeScreening, groupByUpstream, sentences } from "./tools";

describe("why a tool is held", () => {
  test.each([
    ["description_changed", "The description changed"],
    ["description_changed,schema_changed", "The description changed and the input schema changed"],
    [
      "suspicious_description:hidden_unicode",
      "A new tool whose description matched a screening rule",
    ],
    ["removed_from_upstream", "The upstream no longer lists it"],
    ["disabled_by_operator", "Disabled by an operator"],
    ["something_new", "something_new"],
  ])("%s reads %s", (reason, text) => {
    expect(describeReason(reason)).toBe(text);
  });

  test("nothing is said of a tool that is not held", () => {
    expect(describeReason(null)).toBe("");
  });

  test("the screening rules are named in words", () => {
    expect(describeScreening(["hidden_unicode", "mystery"])).toEqual([
      "hidden characters",
      "mystery",
    ]);
  });
});

describe("a description in sentences", () => {
  test("is split at sentence ends and line ends", () => {
    expect(sentences("Reads a file. Returns text!\nSecond line? Yes.")).toBe(
      "Reads a file.\nReturns text!\nSecond line?\nYes.",
    );
  });

  test("keeps a text with no sentence end whole", () => {
    expect(sentences("a b c")).toBe("a b c");
  });
});

describe("the tools by upstream", () => {
  test("come in name order, upstreams and tools alike", () => {
    const groups = groupByUpstream([
      tool({ name: "mail__send_email", upstream: "mail" }),
      tool({ name: "bank__transfer", upstream: "bank" }),
      tool({ name: "bank__get_balance", upstream: "bank" }),
    ]);

    expect(groups.map((group) => group.upstream)).toEqual(["bank", "mail"]);
    expect(groups[0]?.tools.map((entry) => entry.name)).toEqual([
      "bank__get_balance",
      "bank__transfer",
    ]);
  });
});
