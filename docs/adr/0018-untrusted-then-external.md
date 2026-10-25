# ADR-0018: A session that read untrusted text asks before any external effect

Status: accepted
Date: 2026-10-24

## Context

The Rule of Two (plan section 3.5) asks a person when a session has read untrusted text (A), has
read sensitive data (B) and calls a tool with an external effect (C). The red team of KS-902
measured what that leaves open. With the naive agent against C2, 8 of 48 attacks landed (16.7%,
95% interval 8.7% to 29.6%), and all 8 read a web page first. A page is a read of untrusted text
and of nothing sensitive, so the session had A and not B, and `rule-of-two` did not ask. The other
rule that looks at the session, `tainted-external-effect`, needs the scanner to score an output at
0.85, and the highest page that landed scored 0.82. Three of the four goals need no sensitive data
to succeed: overwriting a config file (3 of 12 landed), phishing a colleague (2 of 12) and a
transfer of 450 to an account the page names (3 of 12). Only forwarding a mail needs B, and it was
the goal that never landed.

Three ways to close it were on the table (docs/progress.md, "Found"): ask about any external effect
after an untrusted read, count the tools a session could call and not only the ones it has called,
or lower the taint threshold. The third was ruled out because a threshold chosen by looking at 8
attacks is tuned to them, and the second needs a notion of "could call" that the tags do not have.
The first is a product decision about what the gateway asks, so it is a rule and not a tuning.

## Decision

A new default approval rule, `untrusted-then-external-effect`, in
`policies/default/approval/rule_of_two.cedar`:

```cedar
@id("untrusted-then-external-effect")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { resource.tags.contains("external_effect")
       && context.session_flags.contains("reads_untrusted") };
```

It asks for a person's approval when the session has the flag `reads_untrusted` and the tool has the
tag `external_effect`, whatever the arguments and whatever else the session read. `rule-of-two` and
`tainted-external-effect` stay as they are, and the reasons of a request add up (a mail to an
outside address after reading a poisoned mail names four). The rule is every tenant's.

## What it costs

Measured with the same agent, scenarios and approver as the baseline (docs/results.md, red team;
the old rows are kept, labelled with the commit they were run at):

| | Before (`aaee3811d301`) | After (`050b15fd102a`) |
|---|---|---|
| Attacks landed in C2 | 8 of 48 (16.7%) | 0 of 48 (0.0%, 95% up to 7.4%) |
| Benign utility | 12 of 12 | 12 of 12 |
| Utility under attack | 48 of 48 | 48 of 48 |
| Approvals requested per run | 0.92 | 1.05 |
| Harmless runs where a person was asked | 3 of 12 | 3 of 12 |

The extra 0.13 requests per run are the 8 attacks that used to land, now held. The 12 harmless
tasks asked exactly as often as before: the three that read and then act (`bank_pay`, `files_brief`
and `mail_reply`) already read sensitive data and `rule-of-two` asked about them, and the card now
names two rules. That is a property of this suite and not a promise. The three web tasks only
read, so no harmless task in it reads a page and then acts, which is the case the rule adds. A
deployment where agents read a web page or an inbox and then send, write or pay will see a request
for each such session, and a person who approves them by habit gives the rule back. The approver
here is an oracle that is right every time, so the table says what the rule stops and not how a
tired reader behaves.

It does not make the agent safe. The rule holds a call for a person, it does not read it; a tool
with no `external_effect` tag is invisible to it, as to `rule-of-two`; and a session that read
untrusted text through a tool with no `reads_untrusted` tag has no flag. The tags in the config are
what the rule is worth.

## How a tenant relaxes it

A `forbid` in a tenant's directory cannot remove a permit of the approval set (the loader refuses
a forbid there, because an approval policy may ask and never block), and Cedar has no way to
subtract a rule. The supported way is to name the rule in the config:

```yaml
tenants:
  - id: acme
    name: Acme Corp
    exclude_default_policies: [untrusted-then-external-effect]
```

The loader checks the list. An id that is not a policy of a shared approval set is an error, and so
is an id of the access set, because those rules keep tenants apart and a config line must not turn
one off. The tenant's approval pass then ignores that id among the reasons; the other tenants keep
the rule, and the policy version (the hash of the files) is not changed by the config.
Tests: `tests/unit/test_policy_exclusion.py`.

## Consequences

- The default pack has three approval rules about a session. The policy cases cover each (67 cases,
  coverage complete) and six existing tests that listed the reasons of an approval list the new id.
- C1 of the red team is still the stack without the Rule of Two policies: its copy of `policies/`
  drops `rule_of_two.cedar`, which now holds the new rule, so C1 is the same as before and its new
  run (0 of 60 outcomes differ) agrees.
- A later phase that adds an LLM agent will show how a model behaves with the rule. Until then the
  M1 target (0%) is met by the naive agent in C2 and says nothing of the other agent.
