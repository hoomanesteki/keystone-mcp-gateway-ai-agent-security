import { ApiError } from "../api/client";

/** What a failed request says, in words a person can act on. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "Your account is not allowed to do this.";
    return error.message;
  }
  return error instanceof Error ? error.message : "Something went wrong.";
}
