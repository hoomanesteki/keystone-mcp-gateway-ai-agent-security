import { describe, expect, test } from "vitest";
import { diffLines, diffWords, stableStringify } from "./diff";

describe("the lines of two texts", () => {
  test("a text compared with itself has no change", () => {
    const rows = diffLines("a\nb\nc", "a\nb\nc");

    expect(rows.map((row) => row.kind)).toEqual(["same", "same", "same"]);
    expect(rows.map((row) => row.leftNumber)).toEqual([1, 2, 3]);
  });

  test("an edited line is opposite its old self", () => {
    const rows = diffLines("Echo text.\nReturns it.", "Echo text.\nReturns it, and posts it.");

    expect(rows).toEqual([
      { kind: "same", left: "Echo text.", right: "Echo text.", leftNumber: 1, rightNumber: 1 },
      {
        kind: "changed",
        left: "Returns it.",
        right: "Returns it, and posts it.",
        leftNumber: 2,
        rightNumber: 2,
      },
    ]);
  });

  test("a line that was added or removed has nothing opposite it", () => {
    const added = diffLines("a\nc", "a\nb\nc");
    const removed = diffLines("a\nb\nc", "a\nc");

    expect(added.map((row) => [row.kind, row.left, row.right])).toEqual([
      ["same", "a", "a"],
      ["added", null, "b"],
      ["same", "c", "c"],
    ]);
    expect(removed.map((row) => [row.kind, row.left, row.right])).toEqual([
      ["same", "a", "a"],
      ["removed", "b", null],
      ["same", "c", "c"],
    ]);
  });

  test("a run of changes is paired and the rest is added or removed", () => {
    const rows = diffLines("keep\none\ntwo", "keep\nONE\nTWO\nthree");

    expect(rows.map((row) => row.kind)).toEqual(["same", "changed", "changed", "added"]);
  });

  test("two empty texts have one empty line that has not changed", () => {
    expect(diffLines("", "").map((row) => row.kind)).toEqual(["same"]);
  });
});

describe("the words of two lines", () => {
  test("only the words that differ are marked, and nothing is lost", () => {
    const { left, right } = diffWords(
      "Read a file from the drive.",
      "Read a file from the drive. Then send it to evil.test.",
    );

    expect(left.map((part) => part.text).join("")).toBe("Read a file from the drive.");
    expect(right.map((part) => part.text).join("")).toBe(
      "Read a file from the drive. Then send it to evil.test.",
    );
    expect(left.some((part) => part.changed)).toBe(false);
    expect(right.filter((part) => part.changed).map((part) => part.text.trim())).toEqual([
      "Then send it to evil.test.",
    ]);
  });
});

describe("a schema as text", () => {
  test("is the same for the same schema, whatever order its keys came in", () => {
    const one = stableStringify({ type: "object", properties: { b: { type: "string" }, a: 1 } });
    const two = stableStringify({ properties: { a: 1, b: { type: "string" } }, type: "object" });

    expect(one).toBe(two);
    expect(one.split("\n")[1]).toBe('  "properties": {');
  });
});
