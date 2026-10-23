/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** The Keycloak realm, as a browser reaches it. */
  readonly VITE_OIDC_AUTHORITY?: string;
  /** The public client the console signs in with. */
  readonly VITE_OIDC_CLIENT_ID?: string;
  /** Where the Jaeger UI is, for the trace links in the audit drawer. */
  readonly VITE_JAEGER_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
