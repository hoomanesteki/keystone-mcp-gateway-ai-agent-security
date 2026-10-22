# keystone-mcp-gateway-ai-agent-security
Self-hosted security gateway for AI agents. One MCP endpoint in front of all your tools, with OIDC identity, Cedar policy, human approvals, prompt-injection defense, sandboxed code, budgets and a tamper-evident audit log.

## Status

Under construction, built one story at a time. Phase 0 (repo, CI, local stack, docs) and the
Phase 1 proxy core are in place: Keystone serves one MCP endpoint, routes every tool call through
a fixed interceptor pipeline and forwards it to four demo upstreams. The pipeline's slots are
stubs, so there is no authentication, policy or approval yet. `make demo` shows it working.

- Progress per story: [docs/progress.md](docs/progress.md)
- The plan and every acceptance criterion: [docs/PLAN.md](docs/PLAN.md)
- Local stack, ports and settings: [docs/runbook.md](docs/runbook.md)

Released under the MIT licence (see `LICENSE`).
