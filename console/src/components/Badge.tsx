import type { ReactNode } from "react";
import { Icon } from "./Icon";

export type Tone = "neutral" | "ok" | "warn" | "high" | "danger" | "critical" | "accent";

const TONES: Record<Tone, string> = {
  neutral: "bg-neutral-bg text-neutral-fg border-neutral-line",
  ok: "bg-ok-bg text-ok-fg border-ok-line",
  warn: "bg-warn-bg text-warn-fg border-warn-line",
  high: "bg-high-bg text-high-fg border-high-line",
  danger: "bg-danger-bg text-danger-fg border-danger-line",
  critical: "bg-critical-bg text-critical-fg border-transparent",
  accent: "bg-accent-soft text-accent-soft-fg border-transparent",
};

interface BadgeProps {
  tone?: Tone;
  children: ReactNode;
  title?: string;
  className?: string;
}

export function Badge({ tone = "neutral", children, title, className = "" }: BadgeProps) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs leading-4 font-medium whitespace-nowrap ${TONES[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

const RISKS = ["low", "medium", "high", "critical"] as const;
const RISK_TONES: Record<(typeof RISKS)[number], Tone> = {
  low: "neutral",
  medium: "warn",
  high: "high",
  critical: "critical",
};

/** Four bars, filled up to the level: the word says it, the bars and the color repeat it. */
function Level({ level }: { level: number }) {
  return (
    <svg viewBox="0 0 12 12" aria-hidden="true" focusable="false" className="size-3">
      {[0, 1, 2, 3].map((bar) => (
        <rect
          key={bar}
          x={bar * 3}
          y={9 - bar * 2.5}
          width="2"
          height={3 + bar * 2.5}
          rx="0.5"
          fill="currentColor"
          opacity={bar < level ? 1 : 0.3}
        />
      ))}
    </svg>
  );
}

export function RiskBadge({ risk }: { risk: string | null }) {
  const level = RISKS.indexOf(risk as (typeof RISKS)[number]);
  if (level === -1) {
    return (
      <Badge title="This tool is not in the registry, so its risk is not known">unknown risk</Badge>
    );
  }
  const name = RISKS[level] ?? "low";
  return (
    <Badge tone={RISK_TONES[name]} title={`Risk level ${level + 1} of 4`}>
      <Level level={level + 1} />
      {name}
    </Badge>
  );
}

export function TaintBadge() {
  return (
    <Badge tone="danger" title="This session has read content that an outsider could have written">
      <Icon name="alert" className="size-3" />
      tainted
    </Badge>
  );
}
