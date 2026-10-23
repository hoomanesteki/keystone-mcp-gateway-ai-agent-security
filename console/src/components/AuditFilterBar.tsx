import { EFFECTS, OUTCOMES, hasFilters, type Draft } from "../lib/auditFilters";
import { Button } from "./Button";
import { SelectField, TextField } from "./Field";
import { Icon } from "./Icon";

interface AuditFilterBarProps {
  draft: Draft;
  onChange: (next: Draft) => void;
  onClear: () => void;
}

export function AuditFilterBar({ draft, onChange, onClear }: AuditFilterBarProps) {
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => {
    onChange({ ...draft, [key]: value });
  };
  return (
    <form
      role="search"
      aria-label="Filter the audit log"
      onSubmit={(event) => {
        event.preventDefault();
      }}
      className="mb-5 rounded-lg border border-line bg-surface p-4 shadow-card"
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-12">
        <div className="lg:col-span-4">
          <TextField
            label="User"
            value={draft.user}
            onChange={(event) => {
              set("user", event.target.value);
            }}
            placeholder="olivia"
            autoComplete="off"
          />
        </div>
        <div className="lg:col-span-4">
          <TextField
            label="Agent"
            value={draft.agent}
            onChange={(event) => {
              set("agent", event.target.value);
            }}
            placeholder="ops-agent"
            autoComplete="off"
          />
        </div>
        <div className="lg:col-span-4">
          <TextField
            label="Tool"
            value={draft.tool}
            onChange={(event) => {
              set("tool", event.target.value);
            }}
            placeholder="bank__transfer"
            autoComplete="off"
          />
        </div>
        <div className="lg:col-span-3">
          <SelectField
            label="Decision"
            value={draft.effect}
            onChange={(event) => {
              set("effect", event.target.value as Draft["effect"]);
            }}
          >
            {EFFECTS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectField>
        </div>
        <div className="lg:col-span-3">
          <SelectField
            label="Result"
            value={draft.outcome}
            onChange={(event) => {
              set("outcome", event.target.value as Draft["outcome"]);
            }}
          >
            {OUTCOMES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectField>
        </div>
        <div className="lg:col-span-3">
          <TextField
            label="From"
            type="datetime-local"
            value={draft.since}
            onChange={(event) => {
              set("since", event.target.value);
            }}
          />
        </div>
        <div className="lg:col-span-3">
          <TextField
            label="Until"
            type="datetime-local"
            value={draft.until}
            onChange={(event) => {
              set("until", event.target.value);
            }}
          />
        </div>
      </div>
      {hasFilters(draft) ? (
        <div className="mt-3 flex justify-end">
          <Button variant="ghost" size="sm" onClick={onClear}>
            <Icon name="x" />
            Clear filters
          </Button>
        </div>
      ) : null}
    </form>
  );
}
