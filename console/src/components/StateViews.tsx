import type { ReactNode } from "react";
import { describeError } from "../lib/errors";
import { Button } from "./Button";
import { Icon, type IconName } from "./Icon";

interface EmptyStateProps {
  icon?: IconName;
  title: string;
  children?: ReactNode;
}

export function EmptyState({ icon = "inbox", title, children }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center rounded-lg border border-dashed border-line-strong bg-surface px-6 py-14 text-center">
      <span className="mb-4 flex size-11 items-center justify-center rounded-full bg-sunken text-fg-subtle">
        <Icon name={icon} className="size-6" />
      </span>
      <h2 className="text-base font-semibold">{title}</h2>
      {children ? <p className="mt-1 max-w-md text-fg-muted">{children}</p> : null}
    </div>
  );
}

interface ErrorStateProps {
  title: string;
  error: unknown;
  onRetry?: () => void;
}

export function ErrorState({ title, error, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="flex flex-col items-start gap-3 rounded-lg border border-danger-line bg-danger-bg px-5 py-4 text-danger-fg"
    >
      <div className="flex items-center gap-2 font-semibold">
        <Icon name="alert" className="size-5" />
        {title}
      </div>
      <p>{describeError(error)}</p>
      {onRetry ? (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          <Icon name="refresh" />
          Try again
        </Button>
      ) : null}
    </div>
  );
}

/** A grey block that holds the place of text that has not arrived. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded bg-sunken ${className}`} aria-hidden="true" />;
}

export function LoadingList({ label, rows = 2 }: { label: string; rows?: number }) {
  return (
    <div role="status" aria-busy="true" aria-label={label} className="space-y-4">
      {Array.from({ length: rows }, (_, row) => (
        <div key={row} className="space-y-3 rounded-lg border border-line bg-surface p-5">
          <Skeleton className="h-5 w-1/3" />
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-16 w-full" />
        </div>
      ))}
    </div>
  );
}

interface PageHeaderProps {
  title: string;
  children?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ title, children, actions }: PageHeaderProps) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {children ? <p className="mt-1 text-fg-muted">{children}</p> : null}
      </div>
      {actions}
    </div>
  );
}
