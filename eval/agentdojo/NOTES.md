# AgentDojo with Keystone's output defense

KS-904. [AgentDojo](https://github.com/ethz-spylab/agentdojo) runs an agent on user tasks in simulated
environments while an attacker plants instructions in what the tools return, and says how often the
agent still did the user's task (utility) and how often it did the attacker's (security). This
directory puts Keystone's output scan in front of the model in an AgentDojo pipeline, so that the
benchmark can say how much of an attack the scan stops. It has not been run: it needs a model, and
there is no API key on the machine that built it. The rows below are blank for that reason.

## What it measures

Only the scanner and its action. AgentDojo calls its tools in the benchmark's own process, so there
is no MCP session, no principal, no tool tags and no approval for Keystone to see. The policies, the
approvals, the Rule of Two, the budgets and the rate limits do not take part, and the red-team suite
(`docs/results.md`, "Red team") is where those are measured. A number from here is the number of the
scan at the place AgentDojo's own detectors sit, nothing more.

The element is `eval/agentdojo/keystone.py`. For each tool result of the last turn it sends the
text to `POST /admin/api/v1/scan` of a running Keystone, which runs the scan and the action a call
through the gateway would get (the rules, the model, and `scanner.actions` for the risk), and it gives
the model what Keystone answers:

| Action | What the model is given |
|---|---|
| `pass` (score under 0.5) | the result, byte for byte |
| `annotate` | the result between `<<<untrusted>>>` markers, with a warning in front |
| `redact` | the result with hidden characters and links that carry data cut out |
| `block` | `[keystone:KS_OUTPUT_BLOCKED] output withheld (score ..., rules: ...)` in its place |

`--risk` is the risk Keystone gives every tool of the run, and with the default `scanner.actions` a
text that scores as an injection is annotated for `low` and `medium` (the default), redacted for
`high` and blocked for `critical`. AgentDojo does not say which of its tools change anything, so this
is a choice of the run, and the row says which. The route changes nothing, writes no audit record
and taints no session. If it cannot be reached or answers anything but 200 the run stops, because a run
that went on without the defense would report a number for something else.

## Version

- AgentDojo `0.1.35` from PyPI, benchmark `v1.2.2`. The adapter was written against that package and
  `run.py` says so if another is installed.
- `v1.2.2` has 4 suites and 97 user tasks. With the injection tasks that is 949 pairs: workspace 40
  tasks and 14 injection tasks (560 pairs), banking 16 and 9 (144), slack 21 and 5 (105), travel 20
  and 7 (140). Counted from the installed package.
- Pipeline: `AgentPipeline([SystemMessage, InitQuery, llm, ToolsExecutionLoop([ToolsExecutor,
  Keystone, llm])])`. This is where AgentDojo puts its own `transformers_pi_detector`, which uses the
  same ProtectAI model as Keystone's classifier, so the two can be compared on one model.
- AgentDojo's command line cannot take a defense that is not in its fixed list, so `run.py` builds
  the pipeline AgentDojo builds for a model with no defense and adds the element to its tools loop.

## The command

The gateway needs the scanner on and its model loaded (about 7 seconds after it starts):

```
make up
curl -s localhost:8080/metrics | grep -E 'keystone_gateway_info|classifier_ready'
```

A key for the provider of the model goes in the variable AgentDojo reads for it (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY` and so on). Then, for one suite and one model (`--model` is a value of AgentDojo's
`ModelsEnum`, such as `gpt-4o-2024-05-13`):

```
export OPENAI_API_KEY=<key>
SUITE=workspace; MODEL=gpt-4o-2024-05-13; ATTACK=important_instructions

# no attack, no defense: the utility of the model
uv run --with agentdojo==0.1.35 python -m eval.agentdojo.run --suite $SUITE --model $MODEL --no-defense

# attack, no defense: the baseline
uv run --with agentdojo==0.1.35 python -m eval.agentdojo.run --suite $SUITE --model $MODEL --attack $ATTACK --no-defense

# attack, Keystone's scan in front of the model
uv run --with agentdojo==0.1.35 python -m eval.agentdojo.run --suite $SUITE --model $MODEL --attack $ATTACK

# attack, AgentDojo's own detector, for a row to compare with
uv run --with agentdojo==0.1.35 python -m agentdojo.scripts.benchmark -s $SUITE --model $MODEL \
    --attack $ATTACK --defense transformers_pi_detector --benchmark-version v1.2.2
```

`run.py` prints the utility, the attacks that succeeded and, for the Keystone run, how many tool
results the scan saw and what it did with them. The logs of AgentDojo are in `runs/`. With no key
it stops at once, with status 2 and a line that begins `no pipeline for <model>: OpenAIError:
Missing credentials`.
A full run of one suite is one call of the model for each step of each of its tasks (40 user tasks
alone, and 560 pairs with the attack, in workspace), so set a spend limit on the provider's side
before it starts.

## Results

Nothing here is measured. Each row is filled in by running the commands above and copying the
numbers `run.py` prints, with the date, the commit and the model.

| Suite | Model | Attack | Defense | Utility, no attack | Utility, attacked | Attacks that succeeded |
|---|---|---|---|---|---|---|
| workspace | | important_instructions | none | not run: needs an API key | not run: needs an API key | not run: needs an API key |
| workspace | | important_instructions | Keystone scan | not run: needs an API key | not run: needs an API key | not run: needs an API key |
| workspace | | important_instructions | transformers_pi_detector | not run: needs an API key | not run: needs an API key | not run: needs an API key |

## What is tested without a model

`tests/unit/test_agentdojo_adapter.py` gives the element messages in the shape AgentDojo makes and
a Keystone that is a handler behind `httpx.MockTransport`: what the model is given for each action,
that only the results of the last turn are scanned, that a result with no text is not sent, that a
scan which cannot be made stops the run, and where the element goes in the loop.
`tests/integration/test_admin_scan.py` runs the route against a real app: the action for each risk,
the admin role, a body that is refused, no scanner, and no audit record and no taint. The element
was also run once inside AgentDojo 0.1.35 itself, with a scripted model in place of a real one: the
real `ToolsExecutor` made the tool message, the element replaced a poisoned result with Keystone's
refusal before the model was asked again, and a harmless result came through as it was. That run is
not kept as a test, because it needs the package, which the repository does not depend on.
