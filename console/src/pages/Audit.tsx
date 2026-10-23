import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import type { AuditRecord } from "../api/types";
import { AuditFilterBar } from "../components/AuditFilterBar";
import { AuditTable } from "../components/AuditTable";
import { Drawer } from "../components/Drawer";
import { RecordDetail } from "../components/RecordDetail";
import { PageHeader } from "../components/StateViews";
import {
  draftFromParams,
  EMPTY_DRAFT,
  filtersFromDraft,
  hasFilters,
  paramsFromDraft,
} from "../lib/auditFilters";
import { useDebounced } from "../lib/useDebounced";

export function Audit() {
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = useState(() => draftFromParams(params));
  // Text is sent to the server when the person pauses, not on every key.
  const settled = useDebounced(draft, 300);
  const filters = useMemo(() => filtersFromDraft(settled), [settled]);
  const [open, setOpen] = useState<AuditRecord | null>(null);

  // The filters live in the address too, so a filtered view can be sent to someone.
  useEffect(() => {
    const wanted = paramsFromDraft(settled).toString();
    if (wanted !== params.toString()) setParams(wanted, { replace: true });
  }, [settled, params, setParams]);

  return (
    <>
      <PageHeader title="Audit">
        Every decision Keystone made, newest first. Open a tool name to see the whole record.
      </PageHeader>
      <AuditFilterBar
        draft={draft}
        onChange={setDraft}
        onClear={() => {
          setDraft(EMPTY_DRAFT);
        }}
      />
      <AuditTable
        key={JSON.stringify(filters)}
        filters={filters}
        filtered={hasFilters(settled)}
        onOpen={setOpen}
        onClear={() => {
          setDraft(EMPTY_DRAFT);
        }}
      />
      {open ? (
        <Drawer
          title={
            <>
              <span className="font-mono">{open.tool_name}</span>
              <span className="ml-2 text-sm font-normal text-fg-subtle">record {open.seq}</span>
            </>
          }
          onClose={() => {
            setOpen(null);
          }}
        >
          <RecordDetail record={open} />
        </Drawer>
      ) : null}
    </>
  );
}
