# ADR-0013: The console is a React app that signs in on its own

Status: accepted
Date: 2026-10-23

## Context

An approver leaves a page open and decides from it in seconds. A request has a clock, new ones
arrive every few seconds, and a card must disappear when someone else decides it first. An admin
filters the audit log, reads a diff of a changed tool and clicks to approve it. Both call the
admin API with a short-lived token for a person, and the token should not outlive the tab.

## Decision

**React with Vite and TypeScript, not server-rendered pages with HTMX.** The page holds state that
changes under the person's hands: a poll every 5 seconds, a card removed before the server has
answered, a countdown that ticks every second, a note someone is typing while the list refreshes.
With server-rendered fragments each of those is a special case. With TanStack Query it is a
setting. The API's own OpenAPI schema also gives the console its types (`pnpm gen:api`), which a
CI job checks against the API, so a changed route breaks the build and not a page.

**The console is a public client and signs in on its own.** It uses the authorization code flow
with PKCE (S256) against the Keycloak client `console`. A server-rendered console would be a
confidential client with a session store of its own to run and secure, and Keystone would have a
second thing that holds credentials. This way the console is static files and the admin API is the
only server it talks to.

**Tokens stay in memory.** `oidc-client-ts` keeps the user in an in-memory store. A reload signs
in again through Keycloak, and without a password prompt while the Keycloak session lives. The
only thing written to `sessionStorage` is the state of a sign-in in progress (the PKCE verifier),
which has to survive the trip to the sign-in page and is no credential. The access token lasts
five minutes and is renewed with the refresh token a minute before it expires.

**The API is called on the console's own origin.** Vite's dev server proxies `/admin` to Keystone,
so the browser makes no cross-origin request. The API's CORS rule for `KEYSTONE_CONSOLE_ORIGIN`
stays as it is, for a console served from another address.

**The menu follows the roles and the API decides.** The ID token's `roles` decide which pages are
listed: Approvals for an `approver`, all three for an `admin`. This only keeps a person from
opening a page that answers 403. Every route checks the role again (KS-604).

## Consequences

- A Node toolchain joins the repository: a second language, a build step and packages to pin
  (ADR-0002 lists them). CI has a `console` job, and the nightly run and the phase gate drive the
  console in a real browser (KS-609).
- Memory storage does not stop script running in the page from using the token while the tab is
  open. It keeps a token from being left in storage for later, which is the part of the risk that
  storage choice can change. The defence against script injection is not rendering untrusted text
  as markup: the console writes every value through React and has no `dangerouslySetInnerHTML`.
- A reload makes a round trip through Keycloak. It is quick when the session is alive and shows
  the sign-in form when it is not.
- Nothing here serves the console in production. A host for it must send a Content-Security-Policy,
  forward `/admin` to Keystone and use https; none of that exists yet.
- Signing out in one tab does not end the console in another tab until its token runs out.

## Revisit when

The console becomes mostly documents (reports, long text) where server rendering is simpler, or it
needs a production host, which means choosing a Content-Security-Policy and a place for the proxy.
