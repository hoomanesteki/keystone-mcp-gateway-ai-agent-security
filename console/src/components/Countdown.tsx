import { formatCountdown } from "../lib/format";
import { Icon } from "./Icon";

/** Minutes and seconds left to decide. It turns amber in the last minute and says so at zero. */
export function Countdown({ left }: { left: number }) {
  if (left <= 0) {
    return (
      <span className="inline-flex items-center gap-1.5 font-medium text-danger-fg">
        <Icon name="clock" />
        Expired
      </span>
    );
  }
  const urgent = left <= 60;
  return (
    <span
      role="timer"
      className={`inline-flex items-center gap-1.5 tabular-nums ${urgent ? "font-semibold text-warn-fg" : "text-fg-muted"}`}
    >
      <Icon name="clock" />
      <span>{formatCountdown(left)}</span> <span className="font-normal">left</span>
    </span>
  );
}
