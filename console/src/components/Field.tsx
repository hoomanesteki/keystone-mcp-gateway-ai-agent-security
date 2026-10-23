import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";

const CONTROL =
  "h-9 w-full rounded-md border border-line-strong bg-surface px-3 text-fg placeholder:text-fg-subtle";

interface FieldProps {
  label: string;
  children: ReactNode;
}

function Label({ label, children }: FieldProps) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-fg-muted">{label}</span>
      {children}
    </label>
  );
}

export function TextField({
  label,
  className = "",
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return (
    <Label label={label}>
      <input className={`${CONTROL} ${className}`} {...rest} />
    </Label>
  );
}

export function SelectField({
  label,
  className = "",
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { label: string }) {
  return (
    <Label label={label}>
      <select className={`${CONTROL} ${className}`} {...rest}>
        {children}
      </select>
    </Label>
  );
}
