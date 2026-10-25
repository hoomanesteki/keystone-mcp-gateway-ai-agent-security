# Policies

Keystone decides every tool call and every tool listing with [Cedar](https://www.cedarpolicy.com)
policies kept in files. Settings and commands are in the Policies section of `docs/runbook.md`.

## How a decision is made

Two sets of policies are asked in order, and the answer is one of three: allow, deny, or require
approval.

```mermaid
flowchart TD
    A[tool call] --> B{access set}
    B -->|a forbid matches, or no permit does| D[deny]
    B -->|a permit matches, no forbid does| C{approval set}
    C -->|a permit matches| R[require approval]
    C -->|none matches| OK[allow]
```

- **The access set** is standard Cedar. A call is denied unless some `permit` matches and no
  `forbid` does. The reasons of a deny are the `@id` of the forbids that matched, or
  `default-deny` when nothing allowed the call.
- **The approval set** is asked only when access allowed, and holds `permit` policies only. If one
  matches, the call needs a person's approval, and the matching ids are the reasons. If none
  matches, the call is allowed, and the reasons are the access permits that allowed it. A call
  that needs approval is held for a person, and runs only if one approves it, with the arguments
  that were approved and once (the runbook's Approvals section says how). The policy decides it
  again when it runs, so a rule tightened in between refuses it.
- **A tool listing** stops after the access set. A tool the caller may not use is not listed, and
  a tool that needs approval still is.
- **Everything else is a deny.** A policy that fails to evaluate in either pass, a context the
  schema refuses, a tenant with no policies, or any exception gives a deny with the reason
  `policy-error`, and the cause goes to the log. Cedar skips a policy that errors, so without this
  rule a broken `forbid` would not forbid. With no rule that allows anything, every call is denied
  (`default-deny`).

Every policy needs `@id("kebab-case-name")`. The id is what the audit log shows as the reason, so
a decision can be read by a person. Ids are unique within a tenant's rules, and `default-deny`,
`policy-error` and `no-decision` are taken.

## Where the files go

```
policies/
  schema.cedarschema          the one schema
  default/access/*.cedar      rules for every tenant
  default/approval/*.cedar
  demo/access/*.cedar         the demo upstreams' rules; read when policy.include_demo is on
  demo/approval/*.cedar
  acme/approval/*.cedar       rules for the tenant with the id acme
  acme/access/*.cedar
```

A tenant's access set is `default/` plus `demo/` (if on) plus its own directory, and so is its
approval set. A rule that every tenant needs goes in `default/`. A directory or file Keystone
would never read, such as `aproval/` or `base.cdar`, stops the load, because a rule that does not
load is a rule someone believes is in force.

## What a policy can read

### Entities

| Name | Attributes | Member of |
|---|---|---|
| `Keystone::User::"<tenant>:<user>"`, the caller | `tenant` | `Keystone::Group::"<group>"` for each of the caller's groups |
| `Keystone::Tool::"<name>"`, for example `bank__transfer` | `tenant`, `risk` (`"low"`, `"medium"`, `"high"`, `"critical"`), `risk_level` (1 to 4), `tags` (a set of strings) | `Keystone::Upstream::"<id>"` |
| `Keystone::Upstream::"<id>"` | `tenant` | |

The user id includes the tenant, so one user id in two tenants is two users. Actions are
`Keystone::Action::"call_tool"` and `Keystone::Action::"list_tool"`. Tags are `reads_untrusted`,
`reads_sensitive`, `external_effect` and `code_exec`.

### Context

| Field | Type | Meaning |
|---|---|---|
| `agent_id` | String | The agent the caller works through |
| `agent_trust` | String | `"low"`, `"standard"` or `"high"`, from the agent config |
| `session_flags` | Set of String | What the session has read: `reads_untrusted` and `reads_sensitive`, added from the tags of a tool after a call that returned without an error |
| `session_tainted` | Bool | Whether an output the session read scored as an injection (0.85 and up). Once true, it stays true |
| `call_count` | Long | Calls that returned without an error in the session |
| `hour_utc` | Long | The hour of the call, 0 to 23 |
| `args` | record | Facts extracted from the call's arguments: `amount`, `recipient_domain`, `path`, `count`, each optional |

A listing has no session, so `session_flags` is empty, `session_tainted` is false and
`call_count` is 0 there.

`args` holds only what the tool's `extract` config asks for. `extract: {amount: "$.amount |
cents"}` on the transfer tool makes `context.args.amount` the amount in cents. Because an argument
can be missing or unreadable, every field of `args` is optional, and a policy must test it with
`has` before reading it. The runbook lists the pipes (`int`, `cents`, `domain`, `lower`, `len`).

## Five policies to copy

Each of these validates against the schema, which a test checks.

**1. Let a group use one upstream, up to high risk.** `finance` may list and call the bank tools,
but only inside its own tenant.

```cedar
@id("finance-uses-the-bank")
permit (
  principal in Keystone::Group::"finance",
  action in [Keystone::Action::"list_tool", Keystone::Action::"call_tool"],
  resource in Keystone::Upstream::"bank"
)
when { resource.tenant == principal.tenant && resource.risk_level <= 3 };
```

**2. Keep a tool closed at night.** A `forbid` beats every permit, so this holds whatever else
allows the call.

```cedar
@id("no-transfers-at-night")
forbid (
  principal,
  action == Keystone::Action::"call_tool",
  resource == Keystone::Tool::"bank__transfer"
)
when { context.hour_utc < 6 || context.hour_utc >= 20 };
```

**3. Ask for approval above a limit.** This is the demo rule in `policies/demo/approval/bank.cedar`.
The transfer tool's extractor gives the amount in cents, so 500 is 50000. A transfer of exactly 500
goes through, and one of 500.01 asks. When the amount could not be read, the rule asks as well: a
rule that stays silent when it does not know lets the unusual call through.

```cedar
@id("approve-transfer-over-500")
permit (
  principal,
  action == Keystone::Action::"call_tool",
  resource == Keystone::Tool::"bank__transfer"
)
when { if context.args has amount then context.args.amount > 50000 else true };
```

**4. Ask for approval of mail to other domains.** This is acme's rule in
`policies/acme/approval/mail.cedar`. The domain is missing when the recipient is not one plain
address (two recipients, a display name), and a missing domain counts as outside. The rule names
the tool; without that, "no domain" would be true of every other tool and send all of them to
approval.

```cedar
@id("external-email-needs-approval")
permit (
  principal,
  action == Keystone::Action::"call_tool",
  resource == Keystone::Tool::"mail__send_email"
)
when { if context.args has recipient_domain then context.args.recipient_domain != "acme.test" else true };
```

**5. Give an untrusted agent no side effects.** An agent that is not listed in the config gets the
trust `low` when `auth.allow_unknown_agents` is on. This keeps it from any tool tagged
`external_effect`, whoever the user is.

```cedar
@id("low-trust-agents-have-no-side-effects")
forbid (principal, action == Keystone::Action::"call_tool", resource)
when { context.agent_trust == "low" && resource.tags.contains("external_effect") };
```

## The policies Keystone ships

Every id below is a heading, so a reason in the audit log or in an approval request has a page to
go to: `docs/policies.md#<id>`. The console links its reasons here, and a test fails when a
shipped policy has no heading. The pack is in `policies/`; `include_demo` (on in compose) adds
the demo rules.

### same-tenant-low-medium

A permit in `default/access/base.cedar`. Any caller may list and call a tool of low or medium
risk in the caller's own tenant. Nothing else is allowed by this one: a high or critical tool
needs one of the next two.

### operators-high

A permit in `default/access/base.cedar`. Members of the `operators` group may list and call high
risk tools of their own tenant, such as a bank transfer or sending mail.

### admins-critical

A permit in `default/access/base.cedar`. Members of the `admins` group may list and call critical
risk tools of their own tenant.

### deny-cross-tenant

A forbid in `default/access/base.cedar`. No caller uses a tool of another tenant, whatever else
allows it. A forbid beats every permit, so this holds for the rules a tenant adds as well.

### rule-of-two

A rule of the approval set in `default/approval/rule_of_two.cedar`. An agent session should not
combine three things without a person in the loop: it processes untrusted input, it has access to
sensitive data, and it changes state or sends data out. The first two are what the session has
read, the flags `reads_untrusted` and `reads_sensitive`, which the gateway adds from the tags of
the tools it called. The third is the tool being called, with the tag `external_effect`. When the
session has both flags and the tool has the tag, the call needs a person's approval. It applies at
every risk level, to every tenant, and it does not look at the arguments: an internal mail sent
after the agent read an email asks as well. The tag is what counts, so a tool that changes
something must carry `external_effect` in the upstream's config, and a tool that reads must carry
the tag of what it reads. The local stack tags every tool of its demo upstreams
(`deploy/keystone.compose.yaml`): reading mail, a file or the transactions of an account is a read
of untrusted and of sensitive text (a transaction's description is written by whoever paid), fetching
a page is a read of untrusted text, and sending mail, writing a file and making a transfer are
external effects. A tool with no tag is invisible to the rule: a session that reads through it has
no flags, and a call that changes something through it is not asked about.

### untrusted-then-external-effect

A rule of the approval set in `default/approval/rule_of_two.cedar`, added by KS-991 (ADR-0018). A
session that has read untrusted text (the flag `reads_untrusted`) asks before any tool with the tag
`external_effect`, whatever else it read and whatever the arguments are. `rule-of-two` waits for the
second flag, sensitive data, and the red team showed that the attacks that landed in C2 never got
it: a web page is a read of untrusted text only, and phishing a colleague or overwriting a config
file needs nothing sensitive. This rule closes that gap and costs approvals: a harmless task that
reads a page and then writes a file or sends mail now asks once. A tenant that accepts that risk
turns the rule off for itself in the config, because a `forbid` in a tenant's approval set cannot
remove a permit (the loader refuses a forbid there):

```yaml
tenants:
  - id: acme
    name: Acme Corp
    exclude_default_policies: [untrusted-then-external-effect]
```

Only the id of a rule in a shared approval set can be listed; the loader refuses any other id, and
an id of the access set above all. The other tenants keep the rule.

### tainted-external-effect

A rule of the approval set in `default/approval/rule_of_two.cedar`. A session is tainted when an
output it read scored as an injection. A tainted session has been steered once already, so it asks
before any tool with the tag `external_effect`, even when it never touched sensitive data. This is
the rule that holds when the agent obeys the injection: the email forwarded to an outside address
waits for a person.

### deny-critical-when-tainted

A forbid in `default/access/rule_of_two.cedar`. A tainted session never calls a critical tool,
whoever the caller is and whatever else permits it (`admins-critical`, a rule a tenant added). It
is a forbid and not an approval, because nothing a person reads on an approval card can make a
critical action in a steered session safe. A tool listing is not affected, since a listing has no
session. A call that was approved before the taint is decided again when it runs, and this rule
refuses it then.

### approve-transfer-over-500

A rule of the approval set in `demo/approval/bank.cedar`. A transfer over 500 needs a person's
approval, and so does one whose amount could not be read. The limit is in cents (50000), because
the transfer tool's extractor reads cents. Example 3 above shows it.

### external-email-needs-approval

A rule of the approval set in `acme/approval/mail.cedar`. A message to anyone outside
`acme.test` needs a person's approval, and so does one whose recipient domain could not be read.
It is scoped to `mail__send_email`. Example 4 above shows it.

## Reasons Keystone writes itself

Some reasons are not policies. They have headings for the same reason.

### default-deny

No permit matched, so the call was refused. The access set denies unless some permit allows.

### policy-error

A policy failed to evaluate, or the context did not fit the schema, or the tenant has no
policies. The call is refused and the cause goes to the log. Cedar skips a policy that errors, so
without this a broken forbid would not forbid.

### no-decision

The call reached the end of the pipeline with no decision, which a call must never do. It is
refused (KS-191).

### virtual-tool

The call is to one of Keystone's own tools (`keystone__await_approval`, `keystone__whoami`). They
are not tools of an upstream, so the policy is not asked. A reason of the form `approval:<id>`
ends the reasons of a call that ran on an approval, and names it.

## Testing policies

A policy change is checked like code. Cases in `tests/policy_cases/*.yaml` say who calls what and
which decision the policies must give, and `keystone policy test` runs them through the same
loader and engine the gateway uses:

```yaml
# a policy case
- name: support cannot transfer
  tenant: acme
  principal: {user: alice, groups: [support], agent: support-agent, trust: standard}
  tool: {name: bank__transfer, risk: high, tags: [external_effect]}
  args: {amount: 90000}
  session: {flags: [], tainted: false}
  expect: deny
  expect_reasons: [default-deny]
```

`args` are the facts a policy reads (`context.args`), as the extractors give them: cents for the
transfer tool. To test the extractors with the policies, give the call's own `arguments` and the
tool's `extract` instead, as the cases for the transfer and mail rules do. `expect_reasons` is
optional. A case can also set `action: list_tool`, `tool.tenant` (a tool of another tenant), the
`hour` (0 to 23), the session's `call_count`, and the principal's `roles`. A key that is not in
this list is an error, so a typo cannot weaken a case.

```bash
uv run keystone policy test policies tests/policy_cases --coverage
```

It prints one row per case and exits 1 if any case decides differently, or the policies or the
cases cannot be read. `--coverage` also lists every policy that no case matched, and fails: a
policy is matched when it is among the reasons of a decision. The `policy` job of CI runs this on
every push, so a pull request that flips a decision fails there, naming the case, and a rule added
without a case is listed. The shipped cases are in `tests/policy_cases/`.

## Reloading

Edit the files, then `keystone policy reload` (or `POST /admin/api/v1/policies/reload`, or SIGHUP
to the process). A set with any problem is refused with every problem named, and the rules in
force stay in force. The version of the set in force is the sha256 of its files, and every audit
record names it.

## Common mistakes

**Reading a field of `args` without `has`.** The validator refuses it, because the field may be
missing. The load fails and names the file and the policy.

```cedar-error
@id("amount-over-limit")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { context.args.amount > 50000 };
```

Write `context.args has amount && context.args.amount > 50000`, or the `if ... then ... else`
form of example 3 when "unknown" should be treated as a yes.

**Comparing a number with text.** `amount` is a Long. Compare it with `50000`, not `"50000"`.

```cedar-error
@id("amount-as-text")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { context.args has amount && context.args.amount > "50000" };
```

**Writing a limit in the wrong unit.** This loads, and it asks for approval above 500 cents, which
is 5.00, because the extractor gives cents. Check the extractor of the tool before you write a
number.

```cedar-mistake
@id("approve-transfer-over-500")
permit (principal, action == Keystone::Action::"call_tool", resource == Keystone::Tool::"bank__transfer")
when { context.args has amount && context.args.amount > 500 };
```

**A rule that is silent when it does not know.** `has amount && ...` is false when the amount is
missing, so a transfer whose amount could not be read is not asked about. For a limit, prefer the
`if ... else true` form.

**A `forbid` in the approval set.** The approval set can ask for approval and cannot block, so a
forbid there is refused when the files load. Put it in `access/`.

```cedar-error
// approval/block-everything.cedar
@id("block-everything")
forbid (principal, action, resource);
```

**A permit that forgets the tenant.** `permit (principal in Keystone::Group::"finance", action,
resource)` would let finance use another tenant's tools if one ever appeared. The default pack
ends with `deny-cross-tenant`, a forbid that covers this, but a permit should still say
`resource.tenant == principal.tenant`.

**A group tested with `==`.** A user is in a group through `principal in Keystone::Group::"x"`. A
group is not a principal, so `principal == Keystone::Group::"x"` is refused when the files load.

```cedar-error
@id("group-by-equality")
permit (principal == Keystone::Group::"finance", action, resource);
```

**Expecting a listing to see the session.** `list_tool` has no session, so a policy that reads
`context.session_tainted` for `list_tool` sees `false`. Use `call_tool` for rules about the
session.

**A rule in `default/` for one tenant.** Everything in `default/` applies to every tenant. A rule
for one tenant goes in the directory named for it.
