import type { ReactNode } from "react";
import { Logo } from "./Logo";

interface FullPageProps {
  title: string;
  children?: ReactNode;
  actions?: ReactNode;
}

/** The screens outside the console proper: signing in, signing out, a sign-in that failed. */
export function FullPage({ title, children, actions }: FullPageProps) {
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-xl border border-line bg-surface p-7 text-center shadow-card">
        <Logo className="mx-auto size-10" />
        <h1 className="mt-5 text-lg font-semibold tracking-tight">{title}</h1>
        {children ? <div className="mt-2 text-fg-muted">{children}</div> : null}
        {actions ? <div className="mt-6 flex justify-center gap-2">{actions}</div> : null}
      </div>
    </main>
  );
}
