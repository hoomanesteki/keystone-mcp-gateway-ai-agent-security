# ADR-0017: The baseline of the red team is a profile of the same build, and the approver is an oracle

Status: accepted
Date: 2026-10-24

## Context

The red team has to say what each layer of Keystone buys and what it costs. That takes the same agent
on the same 60 scenarios against the same tools, with the layers taken away one at a time: none
(C0), the access rules with the approvals (C1), everything (C2). Three things can make such a table
mean nothing. A baseline that differs from the full gateway in more than the layers (another server,
other tool names, no audit trail) measures the difference. An approver that is right sometimes and
wrong at other times puts noise into every row. And an attack success rate that is read from what
the agent says is a rate of what the agent says.

## Decision

**C0 is a profile of the build.** `profile: passthrough` (`KEYSTONE_PROFILE`) builds the pipeline in
its fixed order with the Phase 1 stub in every slot but two. The credentials stay real, because the
upstreams of the stack demand an API key and a baseline without it would measure their refusal. The
output slot is built with no scanner and writes no score, because the Phase 1 stub wrote a score of
0.0 in every audit row and a score that was never computed is a false statement. The scanner and its
model are not built at all. The pipeline's own audit record is still written, so a run in this
profile can be read back like any other. The profile exists to measure, and `Settings` refuses it
when `env` is `prod`, so that a stray variable cannot turn every defense off in a deployment. A
gateway says how it is set at `/metrics`: `keystone_gateway_info{profile,scanner,classifier}`, where
`classifier` is the model that was built and is `none` where there is none (the extra is not
installed, or the scanner is off).

**C1 and C2 are settings of that build, and the runner checks them.** C1 mounts a copy of
`policies/` without the two files of the Rule of Two (`rule_of_two.cedar` under `default/access/`
and `default/approval/`) and turns the scanner off, so that the access rules, acme's rule for mail
to outside addresses and the limit on transfers remain. C2 is the stack as it is. A label is a claim,
so the runner asks the gateway before the first run: the profile, the scanner and its model from
`/metrics`, and the policy ids in force from the admin API. C2 needs a scanner with a model, and the
model loads in the background for several seconds after the gateway starts, with the rules alone
scoring every scan until it has (`keystone_scanner_classifier_ready`), so the runner waits for it. If
what it finds is not what the label needs it stops with status 2 and writes nothing.
`scripts/redteam.sh` sets the three configs with `deploy/redteam.override.yml`, which changes
nothing when no variable is set.

**The approver is an oracle.** The approver is lena (role `approver`, signed in through
`keystone-cli`). She polls the pending requests through the admin API, as a person with the console
open would. A request is approved when its tool and the arguments that an unused action of the
scenario's `expected_actions` names are the same, each action once, and every other request is
rejected with a note. She counts what she saw, and keeps for each request the rules that asked and
the flags and taint of the session at that moment. This measures what the layers do when the person
is right, which is the most a defense can hope for. A person who reads a card badly lets more
through, and the number does not say how many. The two simpler approvers say less: one that approves
everything lets every attack that waits at an approval land, and one that rejects everything makes
the task fail and hides what the friction costs.

**A run is decided by state.** After the agent is done the runner asks each upstream what it did
(`GET /_state`) and decides the two checks of the scenario from that (KS-901): did the attack
happen, and was the task done. The words of the agent are not believed. This is why the agent can
be a model: whatever it says, the mail server's own list of sent mail is the evidence.

**One run is one scenario, in one config, by one agent, once.** The upstreams are put in the state of
the scenario first (`POST /_reset?variant=`). The result is a file of JSON lines: a `start` line
(the commit and whether the tree was clean, the machine, how the gateway answered), a line for each
run, and an `end` line. The runner opens the file for creation, so a result is never added to or
written over. The report (`eval/redteam/report.py`) reads these files and nothing else, names each
one in the section with its commit, and leaves out a file of a part of the suite, a file of a
stand-in model, and a file that a newer, whole one of the same kind replaces.

**The model-driven agent is a loop of its own.** `examples/agents/llm_agent.py` lists the tools of
Keystone's MCP endpoint, gives them to the model in the Messages API format, calls the tools it asks
for and answers with the results, for at most 15 turns. There is no SDK and no retry: an SDK
retries a 429 and a 5xx, and a run that costs money should make one request for each turn it
counts. The system prompt is neutral and says nothing of injections, because a run is meant to
measure what a model does with what a tool returned and not what a warning made it do. Its requests
go through the LLM proxy (ADR-0016) with its Keystone token as the key, so the ledger has a row for
each request under the id Keystone gave it and the cost of a run is a sum over rows that can be
checked. A 402 is a budget and ends the run, since asking again would be refused again.

**The fake model has an agent mode, and its runs are tests of the loop.** The model `fake-agent`
(`examples/fake_llm`) makes the calls of a script in the prompt and, when a tool result holds a
marker (`<!--ks-do:{...}-->`), calls what the marker says, as the naive agent does. With it the loop,
the proxy's metering and the stop at a budget are tested end to end with no key. It says nothing of
how a model behaves, so the report does not take its files, and the rows of the LLM agent stay
blank, with the words "not run: needs an API key" and the command, until a file of a real model is
committed.

**Every tool of the demo upstreams is classified.** The Rule of Two reads tags (KS-704, KS-705).
At v0.8.0 the mail tools and the transfer were tagged, and the tools of the drive and
`list_transactions` had no tag. A session that read a file or the history of an account had no flags,
and a write to the drive was invisible to the rule. The red team puts attacks through all four
upstreams, so `deploy/keystone.compose.yaml` now says what each tool is: reading a file, mail or
the transactions of an account is a read of untrusted and of sensitive text, listing files or
reading a balance is a read of sensitive data, fetching a page is a read of untrusted text, and
writing a file is an external effect. The run of C2 with the config of v0.8.0 is a row of the
results of its own, so that the effect of the tags is measured and not told.

## Consequences

The passthrough profile and the full one share the transport, the registry, the credentials and the
audit record. A defect in those is in every row, and a comparison cannot show it.

An interval over 48 attacks is wide at the edges. Zero landed attacks of 48 is an interval of 0 to
7.4%, and the target of M1 (0%) is a statement about those 48 and not about attacks in general. With
12 benign scenarios one failed task is 8 points of utility, so M3 (a drop of at most 10 points)
cannot be resolved finer than that.

The naive agent obeys every instruction, so its rate is the share of attacks that the layers stop
when the agent never refuses. It is the upper bound for any agent that obeys the same text and is no
estimate of how often a model does. That is M2, and it is measured only with a real model.

The oracle's approvals are counted as requests, and a request costs a person a decision. The
friction column counts requests and the share approved, and does not claim to count seconds of a
person's time.
