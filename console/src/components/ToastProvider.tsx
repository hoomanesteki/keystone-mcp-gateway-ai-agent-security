import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./Icon";
import { ToastContext, type ToastInput, type Toasts } from "./toast-context";

interface Shown extends ToastInput {
  id: number;
}

const SHOWN_FOR_MS = { success: 5000, info: 5000, error: 10000 } as const;

const LOOKS: Record<ToastInput["tone"], { icon: IconName; accent: string }> = {
  success: { icon: "check", accent: "text-ok-fg" },
  info: { icon: "info", accent: "text-accent-text" },
  error: { icon: "alert", accent: "text-danger-fg" },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [shown, setShown] = useState<Shown[]>([]);
  const next = useRef(1);
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer !== undefined) clearTimeout(timer);
    timers.current.delete(id);
    setShown((all) => all.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (toast: ToastInput) => {
      const id = next.current++;
      setShown((all) => [...all.slice(-3), { ...toast, id }]);
      timers.current.set(
        id,
        setTimeout(() => {
          dismiss(id);
        }, SHOWN_FOR_MS[toast.tone]),
      );
    },
    [dismiss],
  );

  useEffect(() => {
    const held = timers.current;
    return () => {
      held.forEach(clearTimeout);
      held.clear();
    };
  }, []);

  const value = useMemo<Toasts>(() => ({ push }), [push]);

  return (
    <ToastContext value={value}>
      {children}
      <div
        role="region"
        aria-label="Notifications"
        className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-88 max-w-[calc(100vw-2rem)] flex-col gap-2"
      >
        {shown.map((toast) => {
          const look = LOOKS[toast.tone];
          return (
            <div
              key={toast.id}
              role={toast.tone === "error" ? "alert" : "status"}
              className="pointer-events-auto flex items-start gap-3 rounded-lg border border-line bg-surface p-3.5 shadow-raised"
            >
              <Icon name={look.icon} className={`mt-0.5 size-5 ${look.accent}`} />
              <div className="min-w-0 flex-1">
                <p className="font-medium">{toast.title}</p>
                {toast.detail ? <p className="mt-0.5 text-fg-muted">{toast.detail}</p> : null}
              </div>
              <button
                type="button"
                onClick={() => {
                  dismiss(toast.id);
                }}
                aria-label="Dismiss"
                className="-m-1 rounded p-1 text-fg-subtle hover:bg-sunken hover:text-fg"
              >
                <Icon name="x" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext>
  );
}
