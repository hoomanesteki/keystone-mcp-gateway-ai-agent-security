const env = import.meta.env;

function origin(value: string): string {
  return value.replace(/\/+$/, "");
}

export const config = {
  /** The admin API, served from the console's own origin (the dev server proxies `/admin`). */
  apiBase: "/admin/api/v1",
  oidcAuthority: origin(env.VITE_OIDC_AUTHORITY ?? "http://localhost:8180/realms/keystone"),
  oidcClientId: env.VITE_OIDC_CLIENT_ID ?? "console",
  jaegerUrl: origin(env.VITE_JAEGER_URL ?? "http://localhost:16686"),
  /** Each policy id has a heading in this page, so `#<id>` opens the policy's explanation. */
  policyDocsUrl:
    "https://github.com/hoomanesteki/keystone-mcp-gateway-ai-agent-security/blob/main/docs/policies.md",
} as const;
