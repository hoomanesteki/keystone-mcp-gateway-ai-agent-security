import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "./Button";
import { Icon } from "./Icon";

interface Props {
  children: ReactNode;
  /** A new value clears a caught error, so leaving a broken page and coming back tries again. */
  resetKey?: string;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("The console failed to render", error, info.componentStack);
  }

  override componentDidUpdate(previous: Props): void {
    if (this.state.error && previous.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div
        role="alert"
        className="mx-auto mt-10 max-w-xl rounded-lg border border-danger-line bg-danger-bg p-6 text-danger-fg"
      >
        <div className="flex items-center gap-2 text-base font-semibold">
          <Icon name="alert" className="size-5" />
          This page broke
        </div>
        <p className="mt-2">
          Something went wrong while drawing it. Nothing was changed. Reloading usually fixes it.
        </p>
        <pre className="mt-3 max-h-40 overflow-auto rounded bg-surface p-3 font-mono text-xs text-fg-muted">
          {error.message}
        </pre>
        <Button
          className="mt-4"
          onClick={() => {
            window.location.reload();
          }}
        >
          <Icon name="refresh" />
          Reload
        </Button>
      </div>
    );
  }
}
