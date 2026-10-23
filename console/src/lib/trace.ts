import { config } from "../config";

/** A trace id is the 32 hex digits of a W3C trace context. Anything else is not put in a link. */
const TRACE_ID = /^[0-9a-f]{16,32}$/;

/** Where to read a call's trace in Jaeger, or null when the record has none. */
export function traceUrl(traceId: string | null, base: string = config.jaegerUrl): string | null {
  if (traceId === null || !TRACE_ID.test(traceId)) return null;
  return `${base.replace(/\/+$/, "")}/trace/${traceId}`;
}
