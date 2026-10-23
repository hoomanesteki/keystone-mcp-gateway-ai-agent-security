import { isMaskedText } from "../lib/format";
import { Icon } from "./Icon";

function show(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function Value({ value }: { value: unknown }) {
  const text = show(value);
  if (isMaskedText(text)) {
    return (
      <span className="inline-flex items-center gap-1 text-fg-subtle italic">
        <Icon name="lock" className="size-3.5" />
        {text}
      </span>
    );
  }
  return <span className="break-words whitespace-pre-wrap">{text}</span>;
}

interface ArgumentsViewProps {
  /** The arguments as the audit log shows them: secrets already masked by the server. */
  value: unknown;
  masked: boolean;
}

/** What the agent asked for. Hidden or cut values are marked, and the person is told that the call
 * runs with more than they can see. */
export function ArgumentsView({ value, masked }: ArgumentsViewProps) {
  const fields =
    typeof value === "object" && value !== null && !Array.isArray(value)
      ? Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
      : null;
  return (
    <div>
      {fields && fields.length > 0 ? (
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 font-mono text-[13px]">
          {fields.map(([key, item]) => (
            <div key={key} className="contents">
              <dt className="text-fg-subtle">{key}</dt>
              <dd className="m-0 text-fg">
                <Value value={item} />
              </dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="font-mono text-[13px] text-fg-muted">
          {fields ? "No arguments." : <Value value={value} />}
        </p>
      )}
      {masked ? (
        <p className="mt-3 flex items-start gap-2 rounded-md border border-warn-line bg-warn-bg px-3 py-2 text-[13px] text-warn-fg">
          <Icon name="alert" className="mt-0.5 size-4" />
          <span>
            Some values are hidden or cut short. The call runs with the full values, so treat what
            you cannot see as unknown.
          </span>
        </p>
      ) : null}
    </div>
  );
}
