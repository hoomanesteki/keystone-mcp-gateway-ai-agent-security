import { describe, expect, test } from "vitest";
import { traceUrl } from "./trace";

describe("the link to a trace", () => {
  test("is the Jaeger address and the trace id", () => {
    expect(traceUrl("07f3899919fa14c4bb337fe163ef209e", "http://jaeger.test:16686/")).toBe(
      "http://jaeger.test:16686/trace/07f3899919fa14c4bb337fe163ef209e",
    );
  });

  test("uses the configured address by default", () => {
    expect(traceUrl("07f3899919fa14c4bb337fe163ef209e")).toBe(
      "http://localhost:16686/trace/07f3899919fa14c4bb337fe163ef209e",
    );
  });

  test.each([null, "", "not-hex", "07f3/../admin", "07F3899919FA14C4", "0".repeat(40)])(
    "does not make a link of %s",
    (id) => {
      expect(traceUrl(id)).toBeNull();
    },
  );
});
