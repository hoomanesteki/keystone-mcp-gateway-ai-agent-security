# keystone-mcp-gateway-ai-agent-security
Self-hosted security gateway for AI agents. One MCP endpoint in front of all your tools, with OIDC identity, Cedar policy, human approvals, prompt-injection defense, sandboxed code, budgets and a tamper-evident audit log.

## Status

Under construction, built one story at a time. Phases 0 to 7 are in place: Keystone serves one
MCP endpoint and routes every tool call through a fixed interceptor pipeline to its upstreams, HTTP
or stdio. Callers sign in with an OIDC token (Keycloak locally), see only their own tenant's tools,
and never hold an upstream credential: Keystone keeps it encrypted and adds it to the call itself.
Cedar policies kept in files decide every call and every tool list, as allow, deny or require
approval, with the ids of the policies that decided as the reasons. A bad edit is refused when the
files are reloaded and the old rules stay in force, and `keystone policy test` checks the rules
against cases in CI. A call the policy sends to approval is held until a person decides it, runs
only with the arguments that were approved, and only once. Every call leaves a row in a hash-chained
audit log, and an admin API and a web console show the approval queue, the audit trail and the tool
list.

Tool output is scanned for prompt injection by seven rules and a classifier, and an output that
looks like an injection taints the session. Under the Rule of Two, a session that has read
untrusted and sensitive data asks a person before it does anything outside, and a tainted session
asks before any outside action and is refused critical tools outright. New tool descriptions are
screened too. How well the detector does, measured on data it was not tuned on, is in
[docs/results.md](docs/results.md), including where it fails. The sandbox for code, the rate limit
and the budgets are still stubs (Phase 8). `make demo` shows the proxy working, and
`make demo-attack` shows a planted attack with and without Keystone.

- Progress per story: [docs/progress.md](docs/progress.md)
- Writing policies: [docs/policies.md](docs/policies.md)
- What was measured, with dates and commits: [docs/results.md](docs/results.md)
- The plan and every acceptance criterion: [docs/PLAN.md](docs/PLAN.md)
- Local stack, ports and settings: [docs/runbook.md](docs/runbook.md)

Released under the MIT licence (see `LICENSE`).
