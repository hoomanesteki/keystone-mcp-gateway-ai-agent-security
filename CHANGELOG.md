# Changelog

Commit subjects since v0.0.1, grouped by release tag, with the short hash at the end of each line. Merge and release commits are left out.

## v1.0.0 (2026-10-25)

### Features

- defense: flag with the rules first, then ask the model (`030b552`)
- eval: sweep the joins on dev, report the scanner as it was and is (`6eb2e45`)
- eval: add the red-team scenarios and let the upstreams load them (`5b79d37`)
- gateway: add the passthrough profile and report how it is set (`6f53244`)
- examples: add a model-driven agent and a fake model for it (`872e863`)
- eval: add the red-team runner, the oracle approver and the report (`8e12a24`)
- eval: record the scanner's scores of each run and show them (`a501b4d`)
- eval: say what the numbers mean in the red-team section (`94a3284`)
- eval: compare the repeat runs of a config in the red-team report (`f425234`)
- eval: count the flagged documents among the attacks that landed (`ce7922f`)
- gateway: say which model the scanner has and when it has loaded (`4d28386`)
- eval: add the performance harness and its matrix (`b0d3850`)
- eval: record the limits, and where in a run the failures were (`a2472b1`)
- eval: record the performance run and what it found (`e130e50`)
- eval: add the scan route and the AgentDojo adapter (`ff217f4`)
- policy: ask before an external effect after an untrusted read (`61136dd`)
- deploy: terraform reference deployment for AWS (`b2cbac1`)
- telemetry: count what the model did for each scan (`9a1df4f`)
- eval: report one-session rows, the model's share, the last run (`4ad1759`)

### Fixes

- eval: find the session of a run by its calls and not by the clock (`aaee381`)
- eval: keep what the matrix measured and wait for the runs that last (`c99b045`)
- eval: leave failed calls out of the percentiles, with their cause (`aaa1688`)
- eval: read the tokenizer by name so the type check needs no extra (`e2457ba`)
- gateway: share one blocking redis pool of 500 connections (`a58666b`)
- defense: skip a busy classifier and spare the event loop's core (`e63b17f`)
- metering: limit calls to tools that do not exist (`a596fed`)

### Performance

- telemetry: open no span for a hook that does nothing (`672c705`)
- identity: keep an opened upstream credential for 60 seconds (`0b73a24`)
- gateway: build the input schema validator once per schema (`a9986bb`)
- registry: read a tool's status without a transaction (`6f69dfb`)
- eval: record the run after the load fixes, M6 not measured (`ca9b582`)

### Tests

- defense: give the load-once test a place for each of its scans (`0b1d587`)
- audit: look for the card as sent, not four digits a hash can hold (`0342865`)
- audit: wrap the comment to the line limit (`ea5c88f`)
- site: count the axis end of the recall chart as a scale (`eb05f90`)

### Documentation

- repo: give the readme the numbers of the run after KS-992 (`3722d8b`)
- eval: publish the detector numbers of the rules-first join (`163c547`)
- eval: describe the red-team scenarios and mark KS-901 done (`38e4aac`)
- eval: publish the red-team numbers of the naive agent (`186fe7e`)
- eval: publish the red-team runs made with the model loaded (`bf675a0`)
- eval: record the AgentDojo adapter and its blank result rows (`d78892e`)
- record the gate of the proof half of phase 9 (`db9aa76`)
- eval: name the C2 runs made before KS-991 (`09a8a4c`)
- eval: rename the C1 runs made before KS-991 (`050b15f`)
- eval: measure the red team again with the new rule (`ffb993c`)
- record KS-991 and the decision behind it (`5a154b8`)
- record the decisions of the load fixes in ADR-0019 (`1b066e0`)
- site: add the project page and its Pages workflow (`701431b`)
- repo: rewrite the readme around results and a quick start (`3ed2893`)
- repo: rewrite the contributing guide with setup and how-tos (`325f555`)
- repo: open the runbook with getting started and daily tasks (`eb58d10`)
- repo: state the misses and the setup gaps the review found (`5f47ca4`)

### Chores

- smoke: add the phase 9 smoke that runs phases 0 to 8 (`45b6985`)

## v0.8.0 (2026-10-23)

### Features

- sandbox: run agent code in a hardened container (`7f30376`)
- registry: store built-in and containerized upstreams (`4efa8fb`)
- sandbox: serve run_python and run_shell as governed tools (`26f72b9`)
- gateway: run stdio servers in containers (`dcc8a47`)
- metering: limit the rate of calls with token buckets in Redis (`20077d7`)
- metering: record spend in a ledger and stop calls over a budget (`6d23eb2`)
- metering: cost a model request from the provider's own count (`a6c07e3`)
- metering: proxy model requests with identity and budgets (`e99c67d`)
- deploy: add the fake model API and the proxy to the local stack (`1846fd1`)
- admin: filter the audit log by session (`1390ff5`)
- console: add the budgets and sessions pages (`5b5bc88`)

### Fixes

- sandbox: list containers without inspecting each one (`9be903d`)
- deploy: compare the fastest of three refusals with the 50 ms bound (`9361492`)

### Tests

- sandbox: accept an empty port map from a Linux daemon (`9920ae7`)
- metering: make the master key of the settings tests when they run (`e6903e2`)

### Documentation

- sandbox: record the design, the pins and how to run it (`20fbbfe`)
- sandbox: describe the tools, the container transport and the pins (`0c83ec9`)
- metering: describe the rate limits and what they leave out (`403b39c`)
- metering: record why Redis is a copy and the ledger is the record (`beb70b1`)
- metering: describe the LLM proxy and what it leaves out (`f47dcb5`)
- console: describe the budgets and sessions pages (`e00feeb`)
- repo: say in the README what Phase 8 added (`45c42f5`)
- repo: record what the Phase 8 gate found (`a9a029c`)
- repo: say why the Phase 2 bound was met when it was set (`a1c2657`)
- repo: add the phase 8 gate report (`41944e7`)

### CI

- security: allow the published dev key in one test file's history (`91e16f8`)

## v0.7.0 (2026-10-23)

### Features

- eval: add planted injections, a web upstream and a naive agent (`0440bc3`)
- defense: add the scanner rules, text extraction and settings (`9b9caeb`)
- defense: add the classifier behind the rules as an optional extra (`86c9789`)
- defense: add output actions and a scanner that cannot crash a call (`e6d8024`)
- gateway: scan outputs, remember flags and taint the session (`d5a1050`)
- policy: add the Rule of Two as ordinary Cedar policies (`53b13db`)
- defense: read tool descriptions and schema fields with the scanner (`7bbdb4e`)
- console: show the rules and the score that held a tool (`3854f16`)
- eval: build the detector dataset and check it by hash (`7c1c8b5`)
- eval: score the detector and compute its metrics (`a055e7d`)
- eval: tune the thresholds on the dev split (`59f2296`)
- eval: write the detector report from the test split (`ff2f28a`)
- eval: make the report say only what its records show (`1e796bc`)

### Fixes

- gateway: merge session updates instead of saving whole copies (`57d0acf`)
- deploy: keep the model download in a build cache (`98c695e`)
- eval: say why the 300 ms row is a weak number (`0ce72d0`)

### Tests

- eval: download the datasets and run the model in the slow suite (`d5d61cd`)

### Documentation

- gateway: record the session merge rules in ADR-0015 (`54324cb`)
- eval: describe the injection fixtures and mark KS-708 done (`43cf04e`)
- defense: record the scanner rules in ADR-0011 and the spike (`c4e0004`)
- defense: record the classifier in ADR-0011 and the spike (`4acaf4d`)
- deploy: record the size and build time of the scanner image (`753879d`)
- defense: record the output actions and fault rules in ADR-0011 (`18dc8b6`)
- deploy: record the build cache of the model and the rebuild time (`f7027a9`)
- defense: record the output slot, the flags and the new metrics (`bfea8e1`)
- defense: record the Rule of Two, the attack demo and the await fix (`1475388`)
- defense: record the description screening and the progress (`d46a288`)
- eval: add the first measured detector numbers (`a458373`)
- eval: record how to run the evaluation and what it found (`097cddf`)
- repo: add the phase 7 gate report and the detector follow-up story (`b0ecd9d`)

### CI

- ci: allow the classifier names in the gitleaks config (`9334fc1`)
- nightly: evaluate the rules on 200 samples of the dev split (`1e0805f`)

## v0.6.0 (2026-10-23)

### Features

- approvals: add the approval service and its table (`f5a5384`)
- approvals: hold a call for a person and run it once approved (`ae39a84`)
- gateway: serve keystone__await_approval and keystone__whoami (`4a43b22`)
- admin: add the approvals routes and the webhook notifier (`860f7e9`)
- console: add the console with sign-in and a menu by role (`cf30825`)
- console: add the approvals queue (`480f3fe`)
- console: add the audit explorer and the chain badge (`cb799fa`)
- console: add the tool registry with a side by side change review (`8995ffa`)
- console: put the page and the waiting count in the tab title (`a783bc8`)

### Fixes

- gateway: check a held call again before its approval is used (`5ab67ff`)
- approvals: flag masked arguments and keep fewer of them (`6a60cc8`)
- console: make the blocks of a card groups, not landmarks (`1edb1e4`)
- console: sign in once when calls are refused together (`960e32d`)

### Tests

- approvals: build the fake api key at run time (`e4d211f`)
- repo: find the TypeScript tests the plan names (`2586f70`)
- console: approve a pending transfer in a real browser (`ac625fc`)
- console: check accessibility in the browser test (`e62fc62`)

### Documentation

- admin: declare the 404 and 503 answers, document the smoke (`c650e71`)
- approvals: record the re-check and what approvals do not do (`c2f54b4`)
- console: record the console decisions, pins and how to run it (`a15ec08`)
- policy: give every shipped policy id a heading (`db911bb`)
- console: describe the approvals page and mark KS-606 done (`bf7b636`)
- console: describe the audit and tools pages (`e9ccee9`)
- console: describe the browser test and mark KS-609 done (`8897da7`)
- console: note the accessibility check and the console commands (`8fd9ebf`)
- repo: put CONTRIBUTING back as plan section 5.8 has it (`5b310d4`)
- console: add the console to the troubleshooting table (`cadd87c`)
- console: say which address the console must be opened at (`12960bb`)
- console: say exactly which sizes and themes were looked at (`fadf6b2`)
- console: note the gate run and tidy the console runbook (`5e4e69b`)
- repo: add the phase 6 gate report and the session merge fix story (`2b6698b`)

### CI

- console: add the console job and run the browser test nightly (`d3e3ab7`)

### Build

- repo: run the console steps in ci-local (`cb3c441`)

## v0.5.0 (2026-10-23)

### Features

- audit: chain audit records by hash and write them in batches (`0954a10`)
- audit: mask the arguments in the audit log and digest the original (`06ae644`)
- audit: verify the chain, export the log and restrict the app role (`4c53ceb`)
- telemetry: trace each tool call from the agent to the upstream (`9ddfd56`)
- telemetry: count calls and time every stage with bounded labels (`326300c`)
- deploy: ship a grafana dashboard for the keystone metrics (`e1a10df`)
- admin: add the read endpoints and tool actions to the api (`2a786b2`)
- admin: cap the verify endpoint at 100,000 records (`700619b`)

### Refactoring

- admin: move the tool actions out of the cli (`19f7c9c`)

### Tests

- repo: read the audit log from postgres in the phase 1 and 4 smokes (`f2b25f0`)
- audit: add a script that measures the audit writer (`879f86d`)
- audit: assemble the private key block in the redaction test (`2f3e4c2`)
- gateway: keep the health probe out of the credential test (`2a9a8c7`)
- repo: add the phase 5 smoke and read the log over the api (`3f3c400`)
- audit: show that a hash taken before the round trip is caught (`1524545`)

### Documentation

- audit: record the chain, the writer and failing closed in ADR-0009 (`5b308b5`)
- audit: describe what the log keeps of a call's arguments (`c4f4967`)
- audit: describe verify, export and the database roles (`2a72c2f`)
- telemetry: describe tracing and what the sdk allows in _meta (`1bcd008`)
- telemetry: describe the metrics and the dashboard (`9827793`)
- admin: describe the admin api and record ks-507 (`57605d1`)
- admin: add the phase 5 smoke to the runbook, note the verify cap (`eb0f024`)
- repo: add the phase 5 gate report (`171d693`)

### Build

- deps: add prometheus-client for the metrics registry (`3c9d6f3`)
- deps: add the OpenTelemetry packages for tracing (`a99e822`)
- deploy: send spans from the compose stack to jaeger (`d798c1c`)
- deploy: scrape keystone from prometheus every 5 seconds (`201a301`)

## v0.4.0 (2026-10-22)

### Features

- policy: add the Cedar schema and the entity and context builders (`f32e146`)
- policy: load, check and version the policy files (`a4ab4b7`)
- admin: reload the policies through the admin API and the CLI (`f1548f2`)
- policy: decide a call in two passes and fail closed (`6ffacef`)
- policy: extract typed facts from a call's arguments (`82e125f`)
- gateway: decide every call and every tool listing by policy (`7061666`)
- policy: ask for approval of large transfers and outside mail (`6a51e85`)
- policy: check policy cases like code and report coverage (`db62f4c`)

### Fixes

- gateway: fail at once when an upstream refuses the credential (`14d938c`)
- gateway: replace credentials an upstream echoes in a result (`cadf80c`)

### Tests

- policy: pin the cedarpy behavior the policy engine relies on (`a0a9368`)
- gateway: cover the policy slot, the filtered list and I6 (`c1ef1cc`)
- repo: add the phase 4 smoke and its end-to-end test (`fd10aa9`)

### Documentation

- gateway: describe the two gate 3 fixes and mark them done (`78e4448`)
- policy: record what the cedarpy spike found (`03b23a0`)
- policy: mark ks-402 done and record what it settled (`5b842be`)
- policy: describe policy loading and reloading, mark ks-403 done (`bf15ae7`)
- policy: record the engine latency and mark ks-404 done (`efecbc5`)
- policy: describe extractors and mark ks-405 done (`6ad170d`)
- gateway: describe how calls and listings are decided (`26c68ec`)
- policy: write the policy guide and describe the default pack (`54578e8`)
- policy: describe policy testing and record the latency (`4224016`)
- repo: describe phases 0 to 4 in the readme status (`c91e486`)
- policy: say where the engine returns allow (`7db818f`)
- repo: add the phase 4 gate report (`b974853`)

### CI

- ci: allow one made-up key in the upstream client test in gitleaks (`d47cfaf`)
- ci: run the policy cases on every push (`bbea3e0`)

### Build

- deps: add cedarpy for the policy engine (`47ebf4f`)
- deploy: mount policies in compose and copy them into the image (`221626b`)
- repo: run the policy cases in make gate and make ci-local (`434bba0`)

## v0.3.0 (2026-10-22)

### Features

- identity: add the Keycloak realm for local sign-in (`18480e9`)
- identity: validate bearer tokens and build a principal from them (`ab78ac5`)
- identity: give each agent a trust level from the config (`110bce5`)
- identity: require a bearer token on /mcp and bind sessions to it (`d28e58d`)
- identity: add the credential vault and the cred commands (`9d2a408`)
- gateway: add upstream credentials to a call just before dispatch (`4272130`)
- gateway: keep tenants apart and refuse tokens for unknown ones (`94497fd`)

### Tests

- identity: add an in-process IdP for tests (`2fe4c1b`)

### Documentation

- identity: describe the realm and mark ks-301 and ks-302 done (`f62f9ba`)
- identity: document token checks and agents (`0509f00`)
- identity: document sign-in, issuer settings and session binding (`7a7bca2`)
- identity: describe credentials and mark ks-305 done (`98a70c0`)
- identity: describe credential injection and mark ks-306 done (`33dd906`)
- identity: describe tenants and mark ks-307 done (`e1e5273`)
- repo: describe phases 0 to 3 in the readme status (`9b79375`)
- repo: add the phase 3 gate report and two fix stories (`ed10a55`)

### CI

- ci: run the end-to-end tests every night (`8cc83fd`)
- ci: allow one gitleaks false positive in the jwt module (`345a145`)
- ci: allow the fake keys in the vault tests in gitleaks (`806f3c2`)

### Build

- deploy: turn on sign-in in compose, sign smokes in as olivia (`73f1fc9`)
- deploy: require API keys on the demo upstreams in compose (`3c27803`)
- deploy: add the globex tenant, its drive and the phase 3 smoke (`8ad558b`)

## v0.2.0 (2026-10-22)

### Features

- registry: add upstream, tool and session tables and repos (`08e4d4a`)
- registry: refuse upstream URLs that point inside the network (`74c2796`)
- registry: load upstreams from config and add the upstream CLI (`ea43bbe`)
- registry: sync tool definitions from every upstream (`77f7334`)
- registry: add registry sync and upstream sync commands (`9178c2d`)
- gateway: tell open sessions when a tenant's tool list changes (`706230c`)
- gateway: probe upstreams and refuse calls to one that is down (`41e4c8f`)
- registry: hold a changed tool definition until it is approved (`101f769`)
- gateway: keep session state in Redis with a durable Postgres row (`224cf30`)
- gateway: run stdio MCP servers as child processes (`e44e470`)

### Fixes

- gateway: refuse to dispatch without an allow decision (`9957f3f`)
- gateway: close an evicted upstream client after its last call (`d4f4d6c`)
- gateway: put the rejection meta on the mcp result as well (`dfd9a22`)
- registry: judge IPv4-mapped addresses by the IPv4 address inside (`344fa98`)
- registry: keep a quarantined tool quarantined when it vanishes (`1d63247`)

### Documentation

- repo: mark ks-191 to ks-193 done and note the result meta (`b5f8678`)
- repo: mark ks-201 done (`31c1338`)
- repo: mark ks-202 done and document upstreams in the runbook (`a49e16f`)
- repo: mark ks-203 done and describe syncing in the runbook (`fc3fff4`)
- repo: mark ks-204 and ks-209 done and document health (`1a05389`)
- repo: mark ks-205 and ks-206 done and document pinning (`c6dbb1d`)
- repo: mark ks-207 done and describe sessions in the runbook (`dc95825`)
- repo: mark ks-208 done and document stdio upstreams (`e58a7b5`)
- repo: note the quarantine fix in the ks-205 row (`3d1314f`)
- repo: add the phase 2 gate report (`c69928a`)

### CI

- ci: rerun after service containers failed to start (`ca54b4d`)

### Build

- deploy: add a stdio upstream to compose and the phase 2 smoke (`6e04609`)

## v0.1.0 (2026-10-21)

### Features

- gateway: add core types, rejection errors, ids and canonical json (`2df63ff`)
- registry: add tool name helpers for the upstream__tool scheme (`135e5a4`)
- audit: add the in-memory audit sink and a no-op tracer (`f2de797`)
- gateway: run every tool call through an interceptor pipeline (`27642ab`)
- repo: add the mail, files, bank and echo demo upstreams (`6b0043a`)
- deploy: run the four demo upstreams in compose from one image (`7192132`)
- gateway: add the upstream client and a pool keyed by credentials (`883fd31`)
- gateway: add settings for upstreams and the dev principal (`6e7db5e`)
- gateway: serve the proxy at /mcp through the pipeline (`36bfbb4`)
- gateway: name the call in the _meta of every result (`e3b386e`)
- repo: add the scripted agent and the phase 1 demo script (`36dbd7d`)
- gateway: add a dev-only endpoint for the audit count (`3af59b1`)
- deploy: add the keystone service to the compose stack (`c88e8c8`)
- repo: add make demo and the phase 1 smoke script (`a5e8ec2`)

### Tests

- gateway: keep a minimal proxy round trip from the mcp spike (`f5564d1`)
- gateway: add the demo_upstreams fixture and the upstream tests (`6bb5939`)
- gateway: compare direct and gateway results, add i1 and i2 (`306dcfd`)

### Documentation

- gateway: write up the mcp proxy spike and adrs 0003, 0005, 0007 (`6a038bb`)
- repo: mark ks-102 done in the progress table (`711ea95`)
- repo: mark ks-103 done in the progress table (`fa8b005`)
- repo: describe the demo upstreams and mark ks-104 done (`6dd59b7`)
- repo: mark ks-105 done in the progress table (`9d03283`)
- gateway: describe the mcp endpoint and mark ks-106 done (`0c2ec6e`)
- repo: describe make demo and mark ks-107 and ks-108 done (`898b9df`)
- gateway: record the inspector check in the spike page (`56e5c1b`)
- repo: add the phase 1 gate report and three fix stories (`1c4f54e`)

### Build

- gateway: add the mcp sdk 2.3.0 and pin it (`0ccd7d0`)
- gateway: add jsonschema and its type stubs (`3d28b7a`)

## v0.0.1 (2026-10-21)

The foundation: repository scaffold, the compose stack, CI and the contributor rules. Its commits are not listed.

