/** Seconds left on a request, from the server's count when the data arrived (`expiresInS`, at
 * `receivedAt`) and the time now, all but the first in milliseconds. The browser's clock is not
 * asked what time it is on the server, only how long ago the data came. */
export function secondsLeft(expiresInS: number, receivedAt: number, now: number): number {
  return expiresInS - (now - receivedAt) / 1000;
}

/** Seconds as minutes and seconds: `14:32`. Minutes are not wrapped into hours, so 75 minutes
 * read `75:00`. A request lives for 15 minutes, and a person decides by the minute. */
export function formatCountdown(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  return `${minutes}:${String(rest).padStart(2, "0")}`;
}

const clock = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const stamp = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/** `09:41:46` in the viewer's time zone. */
export function formatClock(iso: string): string {
  return clock.format(new Date(iso));
}

/** `Oct 23, 09:41:46` in the viewer's time zone. */
export function formatStamp(iso: string): string {
  return stamp.format(new Date(iso));
}

const relative = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** `2 minutes ago`, from an ISO time and the current time in milliseconds. */
export function relativeTime(iso: string, now: number): string {
  const seconds = Math.round((now - new Date(iso).getTime()) / 1000);
  if (seconds < 10) return "just now";
  if (seconds < 60) return relative.format(-seconds, "second");
  if (seconds < 3600) return relative.format(-Math.round(seconds / 60), "minute");
  if (seconds < 86400) return relative.format(-Math.round(seconds / 3600), "hour");
  return relative.format(-Math.round(seconds / 86400), "day");
}

/** A latency as the audit log stores it (a decimal string of milliseconds): `10.05 s`, `12 ms`. */
export function formatLatency(ms: string | null): string {
  if (ms === null) return "none";
  const value = Number(ms);
  if (!Number.isFinite(value)) return ms;
  return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${Math.round(value)} ms`;
}

/** What the scanner made of a call's output, as the audit log keeps it: the score to two places
 * and the action taken, `0.88 annotate`. Null when the output was not scanned (a rejected call, a
 * tool of Keystone's own, a scanner that is switched off). A score that is not a number is shown as
 * it came. */
export function formatScan(score: string | null, action: string | null): string | null {
  if (score === null && action === null) return null;
  const value = score === null ? null : Number(score);
  const shown = value !== null && Number.isFinite(value) ? value.toFixed(2) : (score ?? "none");
  return `${shown} ${action ?? "no action"}`;
}

/** A cost as the audit log stores it (a decimal string of US dollars): `$0.0024`, `free`. */
export function formatCost(usd: string): string {
  const value = Number(usd);
  if (!Number.isFinite(value)) return usd;
  if (value === 0) return "free";
  return `$${value.toFixed(value < 0.01 ? 4 : 2)}`;
}

/** Whether `redact` left its mark on a value: a secret, a card number, a long text that was cut. */
export function isMaskedText(text: string): boolean {
  return (
    text.includes("[redacted") ||
    text === "[truncated]" ||
    /\.\.\.\[sha256:[0-9a-f]{64}\]$/.test(text)
  );
}

/** Whether any value in arguments as the audit log keeps them was hidden or cut. This repeats the
 * server's `is_masked` for the audit page, which shows records and so has no flag to read. It
 * errs toward true, as the server's does. */
export function isMaskedValue(value: unknown, depth = 0): boolean {
  if (depth > 34) return true;
  if (typeof value === "string") return isMaskedText(value);
  if (Array.isArray(value)) return value.some((item) => isMaskedValue(item, depth + 1));
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).some(
      ([key, item]) => key.endsWith("[truncated]") || isMaskedValue(item, depth + 1),
    );
  }
  return false;
}
