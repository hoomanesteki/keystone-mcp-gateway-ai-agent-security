/** Who is signed in, from the claims of the ID token. */
export interface Session {
  username: string;
  name: string;
  email: string | null;
  tenant: string;
  /** Realm roles. The API decides what each one allows; the console only hides what it cannot use. */
  roles: readonly string[];
}

/**
 * Sign-in as the rest of the console sees it. `OidcAuth` is the real one and tests supply a fake,
 * so no page or component knows about Keycloak.
 */
export interface AuthClient {
  /** The signed-in person, or null. The same object is returned until something changes. */
  session: () => Session | null;
  subscribe: (listener: () => void) => () => void;
  /** A token the API will accept, renewed first when it is about to expire. Null if signed out. */
  accessToken: () => Promise<string | null>;
  /** Sends the browser to the sign-in page. `returnTo` is a path of this app. */
  signIn: (returnTo?: string) => Promise<void>;
  /** Finishes a sign-in on the redirect back and returns the path to open. */
  completeSignIn: () => Promise<string>;
  /** Ends the session at the identity provider, which sends the browser to /signed-out. */
  signOut: () => Promise<void>;
}
