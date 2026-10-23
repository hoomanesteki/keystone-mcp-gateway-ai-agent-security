/** An arch with its keystone: the stone at the top that holds the others in place. */
export function Logo({ className = "size-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" focusable="false" className={className}>
      <rect width="32" height="32" rx="7" fill="var(--accent)" />
      <path
        d="M7 26V16a9 9 0 0 1 18 0v10"
        fill="none"
        stroke="var(--accent-fg)"
        strokeWidth="2.6"
        strokeLinecap="round"
      />
      <path d="M12.4 5.6h7.2l-1.5 7.4h-4.2z" fill="var(--accent-fg)" />
    </svg>
  );
}
