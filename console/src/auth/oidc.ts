import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
  type User,
  type UserManagerSettings,
} from "oidc-client-ts";
import type { AuthClient, Session } from "./types";

/** An access token with less than this left is renewed before it is used. */
const RENEW_BELOW_S = 20;

export interface OidcOptions {
  authority: string;
  clientId: string;
  /** The console's own origin, for the redirect addresses. */
  origin: string;
}

const isText = (value: unknown): value is string => typeof value === "string";

/** The claims the console shows. A missing one is empty text, never a guess. */
export function sessionFromClaims(claims: Record<string, unknown>): Session {
  const username = isText(claims["preferred_username"]) ? claims["preferred_username"] : "";
  const roles = Array.isArray(claims["roles"]) ? (claims["roles"] as unknown[]).filter(isText) : [];
  return {
    username,
    name: isText(claims["name"]) && claims["name"] !== "" ? claims["name"] : username,
    email: isText(claims["email"]) ? claims["email"] : null,
    tenant: isText(claims["tenant"]) ? claims["tenant"] : "",
    roles,
  };
}

/** Only a path of this app is followed after sign-in; anything else would be an open redirect. */
export function safeReturnTo(value: unknown): string {
  if (!isText(value) || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return "/";
  }
  return value;
}

/**
 * Sign-in against Keycloak with the authorization code flow and PKCE (S256), as a public client.
 *
 * Tokens stay in memory: a reload signs in again, silently if the identity provider's own session
 * is still alive. Only the short-lived state of a sign-in in progress (the PKCE verifier) goes to
 * sessionStorage, because it has to survive the trip to the sign-in page. The access token is
 * renewed with the refresh token shortly before it expires.
 */
export function createOidcAuth(options: OidcOptions): AuthClient {
  const settings: UserManagerSettings = {
    authority: options.authority,
    client_id: options.clientId,
    redirect_uri: `${options.origin}/auth/callback`,
    post_logout_redirect_uri: `${options.origin}/signed-out`,
    response_type: "code",
    scope: "openid profile email",
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
    automaticSilentRenew: true,
    loadUserInfo: false,
    monitorSession: false,
  };
  const manager = new UserManager(settings);

  let user: User | null = null;
  let current: Session | null = null;
  let leaving = false;
  const listeners = new Set<() => void>();
  let callback: Promise<string> | null = null;
  let renewing: Promise<void> | null = null;

  const set = (next: User | null): void => {
    user = next;
    current = next ? sessionFromClaims(next.profile) : null;
    listeners.forEach((listener) => {
      listener();
    });
  };

  manager.events.addUserLoaded((loaded) => {
    set(loaded);
  });
  manager.events.addUserUnloaded(() => {
    set(null);
  });
  manager.events.addAccessTokenExpired(() => {
    set(null);
  });
  manager.events.addSilentRenewError((error) => {
    // The token is still good until it expires, so keep working; the expiry event ends it.
    console.warn("Renewing the access token failed", error);
  });

  // One renewal at a time. A failed one is not the end of the session: the token still works
  // until it expires, and the expiry event above ends the session then.
  const renew = (): Promise<void> => {
    renewing ??= manager
      .signinSilent()
      .then((renewed) => {
        if (renewed) set(renewed);
      })
      .catch((error: unknown) => {
        console.warn("Renewing the access token failed", error);
      })
      .finally(() => {
        renewing = null;
      });
    return renewing;
  };

  const usable = (minimumS: number): string | null => {
    const held = user;
    return held && (held.expires_in ?? 0) > minimumS ? held.access_token : null;
  };

  return {
    session: () => current,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    accessToken: async () => {
      if (user === null) return null;
      const fresh = usable(RENEW_BELOW_S);
      if (fresh) return fresh;
      await renew();
      return usable(0);
    },
    signIn: async (returnTo = "/") => {
      if (leaving) return;
      await manager.signinRedirect({ state: { returnTo: safeReturnTo(returnTo) } });
    },
    completeSignIn: () => {
      // Once per page load: the redirect consumes its state, and React may run the effect twice.
      callback ??= manager.signinRedirectCallback().then((signedIn) => {
        set(signedIn);
        const state = signedIn.state as { returnTo?: unknown } | undefined;
        return safeReturnTo(state?.returnTo);
      });
      return callback;
    },
    signOut: async () => {
      leaving = true;
      await manager.signoutRedirect();
    },
  };
}
