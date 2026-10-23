/** A text compared with another one, line by line, for the side by side view of a changed tool. */

export type Kind = "same" | "removed" | "added" | "changed";

export interface DiffRow {
  kind: Kind;
  /** The line in the current definition, or null where the pending one added a line. */
  left: string | null;
  /** The line in the pending definition, or null where it removed a line. */
  right: string | null;
  leftNumber: number | null;
  rightNumber: number | null;
}

export interface Segment {
  text: string;
  changed: boolean;
}

/** The longest common subsequence of two lists, as the pairs of positions that match. */
function matches<T>(a: readonly T[], b: readonly T[]): [number, number][] {
  const columns = b.length + 1;
  const table = new Uint32Array((a.length + 1) * columns);
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      table[i * columns + j] =
        a[i] === b[j]
          ? (table[(i + 1) * columns + j + 1] ?? 0) + 1
          : Math.max(table[(i + 1) * columns + j] ?? 0, table[i * columns + j + 1] ?? 0);
    }
  }
  const pairs: [number, number][] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      pairs.push([i, j]);
      i += 1;
      j += 1;
    } else if ((table[(i + 1) * columns + j] ?? 0) >= (table[i * columns + j + 1] ?? 0)) {
      i += 1;
    } else {
      j += 1;
    }
  }
  return pairs;
}

/**
 * Rows for two columns. A run of removed lines next to a run of added lines is paired up, line
 * for line, as `changed`, so an edited line sits opposite its old self. What is left over in
 * either run is `removed` or `added`.
 */
export function diffLines(before: string, after: string): DiffRow[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const rows: DiffRow[] = [];
  let i = 0;
  let j = 0;

  const flush = (stopA: number, stopB: number) => {
    const removed = a.slice(i, stopA);
    const added = b.slice(j, stopB);
    const paired = Math.min(removed.length, added.length);
    for (let k = 0; k < paired; k += 1) {
      rows.push({
        kind: "changed",
        left: removed[k] ?? "",
        right: added[k] ?? "",
        leftNumber: i + k + 1,
        rightNumber: j + k + 1,
      });
    }
    for (let k = paired; k < removed.length; k += 1) {
      rows.push({
        kind: "removed",
        left: removed[k] ?? "",
        right: null,
        leftNumber: i + k + 1,
        rightNumber: null,
      });
    }
    for (let k = paired; k < added.length; k += 1) {
      rows.push({
        kind: "added",
        left: null,
        right: added[k] ?? "",
        leftNumber: null,
        rightNumber: j + k + 1,
      });
    }
    i = stopA;
    j = stopB;
  };

  for (const [matchA, matchB] of matches(a, b)) {
    flush(matchA, matchB);
    rows.push({
      kind: "same",
      left: a[i] ?? "",
      right: b[j] ?? "",
      leftNumber: i + 1,
      rightNumber: j + 1,
    });
    i += 1;
    j += 1;
  }
  flush(a.length, b.length);
  return rows;
}

/** Words and the spaces between them, as separate tokens, so that rebuilding is exact. */
function tokens(text: string): string[] {
  return text.split(/(\s+)/).filter((token) => token !== "");
}

function segments(all: readonly string[], kept: ReadonlySet<number>): Segment[] {
  const out: Segment[] = [];
  all.forEach((text, index) => {
    const changed = !kept.has(index);
    const last = out[out.length - 1];
    if (last?.changed === changed) last.text += text;
    else out.push({ text, changed });
  });
  return out;
}

/** Which words of two lines differ, for marking inside a changed row. */
export function diffWords(before: string, after: string): { left: Segment[]; right: Segment[] } {
  const a = tokens(before);
  const b = tokens(after);
  const pairs = matches(a, b);
  return {
    left: segments(a, new Set(pairs.map(([index]) => index))),
    right: segments(b, new Set(pairs.map(([, index]) => index))),
  };
}

/** JSON with the keys in order and two spaces of indent: the same schema always reads the same. */
export function stableStringify(value: unknown): string {
  const order = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(order);
    if (typeof item === "object" && item !== null) {
      return Object.fromEntries(
        Object.entries(item)
          .sort(([x], [y]) => x.localeCompare(y))
          .map(([key, inner]) => [key, order(inner)]),
      );
    }
    return item;
  };
  return JSON.stringify(order(value), null, 2);
}
