import { describe, expect, test } from "vitest";
import {
  formatCost,
  formatCountdown,
  formatLatency,
  isMaskedText,
  relativeTime,
  secondsLeft,
} from "./format";

describe("the countdown", () => {
  test.each([
    [897.4, "14:57"],
    [900, "15:00"],
    [62, "1:02"],
    [59.9, "0:59"],
    [5, "0:05"],
    [4500, "75:00"],
    [0, "0:00"],
    [-12, "0:00"],
  ])("writes %s seconds as %s", (seconds, text) => {
    expect(formatCountdown(seconds)).toBe(text);
  });

  test("counts from the server's figure and the time the data came", () => {
    const received = 1_000_000;

    expect(secondsLeft(120, received, received)).toBe(120);
    expect(secondsLeft(120, received, received + 30_500)).toBeCloseTo(89.5);
    expect(secondsLeft(10, received, received + 11_000)).toBeLessThan(0);
  });
});

describe("how long ago", () => {
  const now = Date.parse("2026-10-23T10:00:00Z");

  test.each([
    ["2026-10-23T09:59:55Z", "just now"],
    ["2026-10-23T09:59:30Z", "30 seconds ago"],
    ["2026-10-23T09:58:00Z", "2 minutes ago"],
    ["2026-10-23T07:00:00Z", "3 hours ago"],
    ["2026-10-20T10:00:00Z", "3 days ago"],
  ])("%s is %s", (when, text) => {
    expect(relativeTime(when, now)).toBe(text);
  });
});

describe("the figures of the audit log", () => {
  test("latency is milliseconds until it is seconds", () => {
    expect(formatLatency("12.4")).toBe("12 ms");
    expect(formatLatency("10051.040")).toBe("10.05 s");
    expect(formatLatency(null)).toBe("none");
  });

  test("a cost is free, or dollars with as many places as it needs", () => {
    expect(formatCost("0.00000000")).toBe("free");
    expect(formatCost("0.0024")).toBe("$0.0024");
    expect(formatCost("1.5")).toBe("$1.50");
  });
});

describe("what redaction leaves behind", () => {
  test.each(["[redacted]", "card [redacted:card]", "Bearer [redacted]", "[truncated]"])(
    "%s is masked",
    (text) => {
      expect(isMaskedText(text)).toBe(true);
    },
  );

  test("a cut string is masked, and plain text is not", () => {
    expect(isMaskedText(`${"a".repeat(256)}...[sha256:${"0".repeat(64)}]`)).toBe(true);
    expect(isMaskedText("invoice 4471")).toBe(false);
    expect(isMaskedText("sha256 of the invoice")).toBe(false);
  });
});
