import { useChainStatus } from "../api/audit";
import { describeError } from "../lib/errors";
import { Badge } from "./Badge";
import { Icon } from "./Icon";

/**
 * Whether the audit log can still be trusted, from `/audit/verify`: it re-computes the hash of the
 * newest records, and the chain breaks where a record was changed or taken out. A broken chain is
 * the loudest thing in the header. It is read again every minute.
 */
export function ChainStatus() {
  const chain = useChainStatus(true);
  if (chain.isPending) {
    return (
      <span role="status" aria-label="Audit chain" data-chain="checking">
        <Badge>Checking the audit chain</Badge>
      </span>
    );
  }
  if (chain.isError) {
    return (
      <span role="status" aria-label="Audit chain" data-chain="unknown">
        <Badge title={describeError(chain.error)}>Audit chain not checked</Badge>
      </span>
    );
  }
  const { ok, records, broken_seq: seq, message } = chain.data;
  if (ok) {
    return (
      <span role="status" aria-label="Audit chain" data-chain="ok">
        <Badge tone="ok" title={message}>
          <Icon name="shieldCheck" className="size-3.5" />
          Chain verified
          <span className="hidden font-normal tabular-nums sm:inline">
            ({records.toLocaleString()} records)
          </span>
        </Badge>
      </span>
    );
  }
  return (
    <span role="status" aria-label="Audit chain" data-chain="broken">
      <Badge tone="critical" title={message}>
        <Icon name="shieldAlert" className="size-3.5" />
        Chain broken{seq === null ? "" : ` at record ${seq}`}
      </Badge>
    </span>
  );
}
