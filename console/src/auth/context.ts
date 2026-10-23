import { createContext, useContext, useSyncExternalStore } from "react";
import type { AuthClient, Session } from "./types";

export const AuthContext = createContext<AuthClient | null>(null);

export function useAuthClient(): AuthClient {
  const client = useContext(AuthContext);
  if (!client) throw new Error("useAuthClient needs an AuthContext above it");
  return client;
}

/** The signed-in person, or null while nobody is. Renders again when that changes. */
export function useSession(): Session | null {
  const client = useAuthClient();
  return useSyncExternalStore(client.subscribe, client.session);
}

/** For the pages that are only rendered behind `RequireAuth`. */
export function useSignedIn(): Session {
  const session = useSession();
  if (!session) throw new Error("useSignedIn was used outside RequireAuth");
  return session;
}
