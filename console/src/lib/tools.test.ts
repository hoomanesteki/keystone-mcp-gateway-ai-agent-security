import { describe, expect, test } from "vitest";
import { tool } from "../test/fixtures";
import {
  describeReason,
  describeScan,
  describeScreening,
  groupByUpstream,
  sentences,
} from "./tools";

describe("why a tool is held", () => {
  test.each([
    ["description_changed", "The description changed"],
    ["description_changed,schema_changed", "The description changed and the input schema changed"],
    [
      "suspicious_description:hidden_unicode",
      "A new tool whose description matched a screening rule",
    ],
    [
      "suspicious_description:role_spoof,tool_directive score=0.70 in=input_schema.properties.note",
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
    expect(describeScreening(["role_spoof", "tool_directive"])).toEqual([
      "text that poses as the system or the assistant",
      "an instruction to call a tool or to send something to an address",
    ]);
  });

  test("the scanner's score and place are read from the reason", () => {
    expect(
      describeScan(
        "suspicious_description:role_spoof,tool_directive score=0.70 in=input_schema.properties.note",
      ),
    ).toEqual({ score: "0.70", where: "input_schema.properties.note" });
    expect(describeScan("suspicious_description:oversized score=0.00 in=description")).toEqual({
      score: "0.00",
      where: "description",
    });
  });

  test.each([
    null,
    "suspicious_description:hidden_unicode",
    "description_changed",
    "description_changed score=0.70 in=description",
  ])("%s has no score to read", (reason) => {
    expect(describeScan(reason)).toBeNull();
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
