import { diffLines, diffWords, type DiffRow, type Segment } from "../lib/diff";
import type { ReactNode } from "react";

function Words({ parts, tone }: { parts: Segment[]; tone: "removed" | "added" }) {
  return parts.map((part, index) =>
    part.changed ? (
      <mark
        key={index}
        className={
          tone === "removed"
            ? "rounded-sm bg-danger-bg px-0.5 text-danger-fg"
            : "rounded-sm bg-ok-bg px-0.5 text-ok-fg"
        }
      >
        {part.text}
      </mark>
    ) : (
      part.text
    ),
  );
}

function Side({ row, side }: { row: DiffRow; side: "left" | "right" }): ReactNode {
  const text = side === "left" ? row.left : row.right;
  if (text === null) return null;
  if (row.kind !== "changed" || row.left === null || row.right === null) return text;
  const words = diffWords(row.left, row.right);
  return side === "left" ? (
    <Words parts={words.left} tone="removed" />
  ) : (
    <Words parts={words.right} tone="added" />
  );
}

function Cell({ row, side }: { row: DiffRow; side: "left" | "right" }) {
  const number = side === "left" ? row.leftNumber : row.rightNumber;
  const text = side === "left" ? row.left : row.right;
  const edited =
    row.kind === "changed" || (side === "left" ? row.kind === "removed" : row.kind === "added");
  const tint = !edited ? "" : side === "left" ? "bg-danger-bg/40" : "bg-ok-bg/40";
  return (
    <>
      <td
        className={`w-10 border-r border-line px-2 py-0.5 text-right text-fg-subtle select-none ${tint}`}
      >
        {number}
      </td>
      <td className={`px-3 py-0.5 break-words whitespace-pre-wrap ${tint}`}>
        {text === null ? <span className="sr-only">no line</span> : <Side row={row} side={side} />}
      </td>
    </>
  );
}

interface SideBySideDiffProps {
  /** What the section is, for the person reading with a screen reader. */
  label: string;
  before: string;
  after: string;
}

/** The current text on the left and the pending one on the right, line against line. The words
 * that differ inside an edited line are marked, so an addition at the end of a sentence shows. */
export function SideBySideDiff({ label, before, after }: SideBySideDiffProps) {
  const rows = diffLines(before, after);
  const changed = rows.some((row) => row.kind !== "same");
  return (
    <div className="overflow-hidden rounded-md border border-line">
      <table className="w-full table-fixed border-collapse font-mono text-[12.5px] leading-5">
        <caption className="sr-only">
          {label}: the current definition on the left, the pending one on the right
          {changed ? "" : ". They are the same."}
        </caption>
        <thead className="bg-sunken text-left font-sans text-xs text-fg-subtle">
          <tr>
            <th scope="col" colSpan={2} className="border-r border-line px-3 py-1.5 font-medium">
              Current
            </th>
            <th scope="col" colSpan={2} className="px-3 py-1.5 font-medium">
              Pending
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="align-top">
              <Cell row={row} side="left" />
              <Cell row={row} side="right" />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
