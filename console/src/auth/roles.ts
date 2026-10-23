import type { Session } from "./types";

export const ADMIN = "admin";
export const APPROVER = "approver";

export type Page = "approvals" | "audit" | "tools";

export const PAGES: readonly { page: Page; path: string; label: string }[] = [
  { page: "approvals", path: "/approvals", label: "Approvals" },
  { page: "audit", path: "/audit", label: "Audit" },
  { page: "tools", path: "/tools", label: "Tools" },
];

/**
 * The API makes the real decision (an approver may call the approvals routes, an admin may call
 * all of them). This only keeps the console from offering a page that would answer 403.
 */
export function canOpen(session: Session, page: Page): boolean {
  if (session.roles.includes(ADMIN)) return true;
  return page === "approvals" && session.roles.includes(APPROVER);
}

export function pagesFor(session: Session): typeof PAGES {
  return PAGES.filter((entry) => canOpen(session, entry.page));
}

export function roleLabels(session: Session): string[] {
  return [ADMIN, APPROVER].filter((role) => session.roles.includes(role));
}
