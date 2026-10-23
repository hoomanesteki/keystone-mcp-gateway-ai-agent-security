# keystone-mcp-gateway-ai-agent-security
Self-hosted security gateway for AI agents. One MCP endpoint in front of all your tools, with OIDC identity, Cedar policy, human approvals, prompt-injection defense, sandboxed code, budgets and a tamper-evident audit log.

## Status

Under construction, built one story at a time. Phases 0 to 4 are in place: Keystone serves one
MCP endpoint and routes every tool call through a fixed interceptor pipeline to its upstreams, HTTP
or stdio. Callers sign in with an OIDC token (Keycloak locally), see only their own tenant's tools,
and never hold an upstream credential: Keystone keeps it encrypted and adds it to the call itself.
Cedar policies kept in files decide every call and every tool list, as allow, deny or require
approval, with the ids of the policies that decided as the reasons. A bad edit is refused when the
files are reloaded and the old rules stay in force, and `keystone policy test` checks the rules
against cases in CI. The approval, scanner, rate limit and metering slots are still stubs, so a
call that needs a person's approval is refused until Phase 6. `make demo` shows it working.

- Progress per story: [docs/progress.md](docs/progress.md)
- Writing policies: [docs/policies.md](docs/policies.md)
- The plan and every acceptance criterion: [docs/PLAN.md](docs/PLAN.md)
- Local stack, ports and settings: [docs/runbook.md](docs/runbook.md)

Released under the MIT licence (see `LICENSE`).
