# keystone-mcp-gateway-ai-agent-security
Self-hosted security gateway for AI agents. One MCP endpoint in front of all your tools, with OIDC identity, Cedar policy, human approvals, prompt-injection defense, sandboxed code, budgets and a tamper-evident audit log.

## Status

Under construction, built one story at a time. Phases 0 to 3 are in place: Keystone serves one
MCP endpoint and routes every tool call through a fixed interceptor pipeline to its upstreams, HTTP
or stdio. Callers sign in with an OIDC token (Keycloak locally), see only their own tenant's tools,
and never hold an upstream credential: Keystone keeps it encrypted and adds it to the call itself.
The policy, approval, scanner, rate limit and metering slots are still stubs, so Keystone does not
decide what a signed-in caller may do yet. `make demo` shows it working.

- Progress per story: [docs/progress.md](docs/progress.md)
- The plan and every acceptance criterion: [docs/PLAN.md](docs/PLAN.md)
- Local stack, ports and settings: [docs/runbook.md](docs/runbook.md)

Released under the MIT licence (see `LICENSE`).
