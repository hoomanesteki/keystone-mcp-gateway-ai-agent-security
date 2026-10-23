import { useEffect, useState } from "react";

/** `value`, but only after it has stayed the same for `ms`. A text field filters a table with it
 * without asking the server on every key. */
export function useDebounced<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => {
      setSettled(value);
    }, ms);
    return () => {
      clearTimeout(timer);
    };
  }, [value, ms]);
  return settled;
}
