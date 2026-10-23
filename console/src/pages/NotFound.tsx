import { Link } from "react-router";
import { EmptyState } from "../components/StateViews";

export function NotFound() {
  return (
    <EmptyState icon="search" title="There is no page here">
      Check the address, or go back to{" "}
      <Link to="/" className="text-accent-text underline underline-offset-2">
        the start
      </Link>
      .
    </EmptyState>
  );
}
