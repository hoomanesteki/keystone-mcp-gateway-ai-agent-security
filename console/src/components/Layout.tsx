import { NavLink, Outlet, useLocation } from "react-router";
import { usePendingApprovals } from "../api/approvals";
import { canOpen, pagesFor, roleLabels, type PAGES } from "../auth/roles";
import { useAuthClient, useSignedIn } from "../auth/context";
import type { Session } from "../auth/types";
import { Button } from "./Button";
import { ChainStatus } from "./ChainStatus";
import { ErrorBoundary } from "./ErrorBoundary";
import { Icon, type IconName } from "./Icon";
import { Logo } from "./Logo";

const ICONS: Record<(typeof PAGES)[number]["page"], IconName> = {
  approvals: "approvals",
  audit: "audit",
  tools: "tools",
  budgets: "budgets",
  sessions: "sessions",
};

/** How many requests wait, beside the menu entry: an approver sees it from any page. */
function PendingCount() {
  const pending = usePendingApprovals();
  const count = pending.data?.length ?? 0;
  if (count === 0) return null;
  return (
    <span className="ml-auto rounded-full bg-accent px-2 text-xs leading-5 font-semibold text-accent-fg tabular-nums">
      <span aria-hidden="true">{count}</span>
      <span className="sr-only">{count} waiting</span>
    </span>
  );
}

function Sidebar({ pages }: { pages: ReturnType<typeof pagesFor> }) {
  return (
    <aside className="border-b border-line bg-surface md:sticky md:top-0 md:h-screen md:border-r md:border-b-0">
      <div className="flex items-center gap-2.5 px-4 py-3 md:px-5 md:py-5">
        <Logo />
        <div className="leading-tight">
          <div className="font-semibold">Keystone</div>
          <div className="text-xs text-fg-subtle">Console</div>
        </div>
      </div>
      <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-3 md:block md:space-y-1">
        {pages.map(({ page, path, label }) => (
          <NavLink
            key={page}
            to={path}
            className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium whitespace-nowrap text-fg-muted transition-colors hover:bg-sunken hover:text-fg aria-[current=page]:bg-accent-soft aria-[current=page]:text-accent-soft-fg"
          >
            <Icon name={ICONS[page]} className="size-[18px]" />
            {label}
            {page === "approvals" ? <PendingCount /> : null}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

function initials(name: string): string {
  const words = name.split(/\s+/).filter(Boolean);
  const first = words[0]?.charAt(0) ?? "?";
  const last = words.length > 1 ? (words[words.length - 1]?.charAt(0) ?? "") : "";
  return (first + last).toUpperCase();
}

function UserBlock({ session }: { session: Session }) {
  const client = useAuthClient();
  const roles = roleLabels(session);
  return (
    <div className="flex items-center gap-3">
      <span
        aria-hidden="true"
        className="flex size-8 items-center justify-center rounded-full bg-accent-soft text-xs font-semibold text-accent-soft-fg"
      >
        {initials(session.name)}
      </span>
      <div className="hidden leading-tight sm:block">
        <div className="font-medium">{session.name}</div>
        <div className="text-xs text-fg-subtle">
          {session.username}
          {roles.length > 0 ? ` · ${roles.join(", ")}` : ""}
        </div>
      </div>
      <Button
        variant="ghost"
        size="sm"
        aria-label="Sign out"
        onClick={() => {
          void client.signOut();
        }}
      >
        <Icon name="signOut" />
        <span className="hidden sm:inline">Sign out</span>
      </Button>
    </div>
  );
}

function Header({ session }: { session: Session }) {
  return (
    <header className="sticky top-0 z-10 flex h-14 items-center justify-between gap-4 border-b border-line bg-surface px-4 md:px-8">
      <div className="flex items-center gap-1.5 text-sm">
        <span className="text-fg-subtle">Tenant</span>
        <span className="font-medium">{session.tenant || "unknown"}</span>
      </div>
      <div className="flex items-center gap-2 sm:gap-4">
        {canOpen(session, "audit") ? <ChainStatus /> : null}
        <UserBlock session={session} />
      </div>
    </header>
  );
}

export function Layout() {
  const session = useSignedIn();
  const location = useLocation();
  return (
    <div className="min-h-screen md:grid md:grid-cols-[15rem_minmax(0,1fr)]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2 focus:shadow-raised"
      >
        Skip to content
      </a>
      <Sidebar pages={pagesFor(session)} />
      <div className="flex min-w-0 flex-col">
        <Header session={session} />
        <main
          id="main"
          tabIndex={-1}
          className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 outline-none md:px-8 md:py-8"
        >
          <ErrorBoundary resetKey={location.pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
