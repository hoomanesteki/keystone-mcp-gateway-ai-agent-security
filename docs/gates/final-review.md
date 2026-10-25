# Final review before v1.0.0

Decision: no high finding is open.
Branch: `fix/ks-993-final-review`, story KS-993.

Two reviews read the site, the docs and the code. 28 findings came back, 5 of them repeats of another, so there are 23 distinct ones. Fixes are in commit `7a87990` (site, README, results) and commit `15d9748` (code, console, threat model). I checked each against the files before changing anything. All 23 reproduced.

Resolutions: fixed, or accepted with a reason.

## High

| # | Finding | Resolution |
|---|---|---|
| H1 | The site latency chart and caption quote the run from before KS-992 (13.8 / 23.8 ms, a classifier at 531.7 / 895.4 ms). Reported twice. | Fixed in `7a87990`. The chart is redrawn from `perf-2026-10-24b.json`: p50 +8.6 ms, p95 +11.7 ms at 1 KB, both within target. The classifier panel says it was not measured, because the model scored none of the scans. |
| H2 | "It slows down under load" quotes +2695.0 ms and 3.2% failed. Reported twice. | Fixed in `7a87990`: +1987.9 ms at p50, none of 4,000 calls failed, and the 88 calls a second ceiling of one event loop. `test_site_quotes_the_current_performance_run` recomputes the site figures from the raw file and fails if the old ones come back. |

## Medium

| # | Finding | Resolution |
|---|---|---|
| M1 | The scorecard marks one-session M5 as a pass; the Performance section says not met. Reported twice. | Fixed in `7a87990`. The scorecard rows are labelled "M5, diagnostic" and say M5 itself stays fail. `eval/perf/report.py` gives the one-session verdict per payload ("1 KB met; 8 KB not met"), so both tables agree. |
| M2 | The site says thresholds were chosen on the dev split. | Fixed in `7a87990`. It says the join, window and weight were picked on dev, the thresholds are the configured defaults, and recall is read at 5% false positive rate on test. |
| M3 | "Run it in 5 minutes" has no measurement. Reported twice. | Fixed in `7a87990`. The time is gone. The text gives the measured 20 minute first build and the 30 second cold start from the README, and says the 10 minute check (M9) is not run. |
| M4 | No timeouts on Redis and Postgres calls on the hot path. | Fixed in `15d9748`. `redis_socket_timeout_s` (5), `redis_connect_timeout_s` (2), `db_connect_timeout_s` (5), `db_command_timeout_s` (60). A timeout is a store error, which the slots already turn into a refusal. In the runbook and `.env.example`. I did not add an overall pipeline deadline: the call hold for an approval is meant to last minutes. |
| M5 | The admin API shows a session it could not read as untainted with no flags. | Fixed in `15d9748`. The failure is logged and the item carries `session_state` (live, ended, unavailable). The console card says the flags are not known. Tests: `test_a_session_that_cannot_be_read_is_not_shown_as_clean` and a console test. `tainted` stays a boolean (false when the state is not live), so older readers do not break. |
| M6 | The Rule of Two text and Venn diagram omit the untrusted-then-external ask. | Fixed in `7a87990`. The text names the exception and links ADR-0018; the Venn marks the A and C overlap as "ask". |
| M7 | Site links point to `blob/main`, which is still v0.8.0. | Accepted. `pages.yml` runs on `main` only, so the site goes live with the v1.0.0 merge, when ADR-0018 and the results exist there. Linking a tag that does not exist yet would break sooner. |
| M8 | The README lists KS-906 as open. Reported twice. | Fixed in `7a87990`. KS-906 and KS-993 are moved to done; KS-995 and KS-996 are named as accepted gaps. |
| M9 | The threat model is not linked from the site or the README. | Fixed in `7a87990`. The limits section and the footer of the site link `docs/threat-model.md`; the README "What it does not do" list does too. |

## Low

| # | Finding | Resolution |
|---|---|---|
| L1 | The results text says a failed call is timed; another sentence says it is left out. | Fixed in `7a87990`. Checked `eval/perf/stats.py` and the JSON: failed calls are in `failed_ms` and absent from `latencies_ms` (passthrough 1 KB: 3,805 and 195). The wrong sentence is corrected in `report.py` and `results.md`; the test says what it reads. |
| L2 | 1.05 approvals a run is credited to one rule. | Fixed in `7a87990`: "Keystone with every layer asked for 1.05 approvals a run". |
| L3 | A scanner score of 0.88 for the demo email has no source. | Fixed in `7a87990`: "0.85 or more", as the README says. |
| L4 | README rows M5 and M6 have no Source cell. | Fixed in `7a87990`. |
| L5 | M7 says I1 passes at every gate. | Fixed in `7a87990` (README and results): passed at the gates of phases 1 to 8; it did not exist at phase 0; the phase 9 gate has not run. |
| L6 | The upstream result size limit runs after the SDK holds the whole response. | Accepted, in the threat model (`15d9748`). The limit protects the agent and the scanner; the memory held is an accepted risk. The table rows now say "measured after the SDK has parsed the result". A byte cap in the transport is not built. |
| L7 | The threat model says each limit has a test at the limit and one byte past it, and three do not. | Fixed in `15d9748`: `test_the_header_count_limit_is_exact`, `test_the_header_byte_limit_is_exact` and `test_the_result_byte_limit_is_exact`, using hand-built scopes so that no client adds headers. |
| L8 | The credential cache keeps a changed credential for up to 60 s. | Accepted, in the threat model (`15d9748`) with the way out: `KEYSTONE_CREDENTIAL_CACHE_TTL_S=0`, or an invalidation message from the CLI. |
| L9 | `POST /policies/reload` is open to an admin of any tenant. | Accepted, in the module docstring and the threat model (`15d9748`). The policy set is one for the process; a platform role for the two global routes is after v1. |
| L10 | Two architecture SVGs use the marker id `ah`. | Fixed in `7a87990`: the narrow one uses `ahn`. I could not check the render on a phone here. |
| L11 | The site says eleven steps; the README says nine slots. | Fixed in `7a87990`: nine slots, with the dispatch and the audit row shown unnumbered. |
| L12 | Enabling GitHub Pages is not in the deferred list. | Fixed in `docs/progress.md`: a Deferred row with the command, marked needs gh auth. |

## Checks

`make check` (ruff, mypy, policy cases, unit, integration, invariants) and the console checks ran on the branch; the results and the CI run are in the merge message on dev. `tests/integration/test_sandbox_runner.py::test_every_hardening_flag_is_set_on_the_container` failed once in the full run (a Docker `sandbox_remove_failed` APIError) and passed in the run of its file and in the repeat of the full run.

## Audit after v1.0.0

Story KS-998. Thirteen readers went through the code, the tests, the deployment files, the console and the docs area by area, and one ran the stack end to end. They came back with 68 findings: 4 high, 21 medium, 43 low. I read every high and medium one against the code. The low ones (wording, naming, a missing log field) are left for later. Of the 25, 22 were real and are fixed in the four `fix/ks-998-*` branches; three are accepted with a reason. The fixes ship in v1.0.1.

| Finding | Severity | Resolution |
|---|---|---|
| A tool quarantined for a suspicious description was released when the upstream changed it and then changed it back: the change reason overwrote the screening reason, and the revert looked like a change taken back. | High | Fixed in `fix/ks-998-registry-defense`. The screening verdict stays with the tool; only approve-change releases it. Test: created suspicious, changed, reverted, still quarantined. |
| `redact` ran the rules on the raw text while the scanner matched on the normalized view, so a zero-width character inside a markdown image left a working exfiltration link after the hidden character was cut. | High | Fixed in `fix/ks-998-registry-defense`. Redaction cuts hidden characters first and runs the leak rules again on the normalized text; a leak that only shows there drops the block. |
| The sandbox stdin feeder set the shared socket timeout to none, so a run given stdin that went quiet was never stopped by `timeout_s` and its container lived until the reaper. | High | Fixed in `fix/ks-998-gateway`. The feeder sends under the poll timeout in a retry loop. Socketpair tests. |
| The ECS task without a certificate set env prod with an http base URL, and Keystone refused to start behind a healthy load balancer. | High | Fixed in `fix/ks-998-ops-console`. Without a certificate the task runs in dev mode and the README says so; an http URL with a certificate fails `terraform plan`. |
| A JWKS answer with no usable key replaced the cached keys, so a brief empty set from the identity provider turned into 401 for every caller for a minute, and anyone could trigger the refresh. | Medium | Fixed in `fix/ks-998-identity-tests`. Such an answer counts as a failed fetch and the old keys stay. |
| The key cache had no maximum age, so a key withdrawn from the JWKS stayed trusted while every token named a cached kid. | Medium | Fixed in `fix/ks-998-identity-tests`. `oidc_jwks_max_age_s` (default 600) refetches the set; a shorter Cache-Control max-age is honoured. |
| Migration 0006 decided prod from `KEYSTONE_ENV` alone, so `env: prod` in the YAML file still got the development password for `keystone_app`; a missing password printed a traceback. | Medium | Fixed in `fix/ks-998-identity-tests`. The migration reads the env the settings resolved; `db upgrade` and `serve --migrate` print `error:` and exit 1. |
| A registry lookup that failed (Postgres down after the cache expired) left the handler as a raw exception: driver text to the agent and no audit record. | Medium | Fixed in `fix/ks-998-gateway`. The lookup is guarded and refused through the pipeline with `KS_UPSTREAM_ERROR`; listing returns an empty list. |
| Argument validation ran before the rate limit slot, so an agent looping on invalid arguments to a real tool was never limited (the hole KS-992 closed for made-up names). | Medium | Fixed in `fix/ks-998-gateway`. Every refusal before the slots takes a token. |
| Closing an upstream client while another task was connecting left the fresh session open, and the pool's shutdown waited on it forever. | Medium | Fixed in `fix/ks-998-gateway`. `aclose` takes the lock and `_client` re-checks closed after connecting. |
| The `tool` label of the call counter was forced to `unknown` only for `TOOL_NOT_FOUND`, and a rate-limited made-up name filled the bounded set. | Medium | Fixed in `fix/ks-998-gateway`. The label is decided by the tool, not the refusal code. |
| The shielded read added in KS-997 capped every whole model answer at `DRAIN_S` (5 s); a slow answer was cut and booked at zero. | Medium | Fixed in `fix/ks-998-gateway`. The read runs under `llm_proxy.timeout_s`; `DRAIN_S` only bounds the drain after a caller left. |
| A definition change seen while a tool was operator-disabled was thrown away, so `enable` put the changed definition live without review. | Medium | Fixed in `fix/ks-998-registry-defense`. The change is held as pending and `enable` points the operator to approve-change. |
| `disable` on a tool removed by its upstream overwrote the reason, after which `enable` revived a tool nobody serves. | Medium | Fixed in `fix/ks-998-registry-defense`. An already disabled tool keeps its reason. |
| A card number followed by a space and one to three digits was stored unmasked: the regex took the longer run, Luhn failed, nothing was retried. | Medium | Fixed in `fix/ks-998-registry-defense`. A 13 to 19 digit Luhn window slides over each digit run. |
| `keystone.example.yaml` gave the files upstreams no tags, so `write_file` was a medium tool with no external effect and the Rule of Two never asked about it. | Medium | Fixed in `fix/ks-998-registry-defense`. The example carries the same tool blocks as the compose config. |
| `keystone_config_yaml` in the Terraform module was never delivered to the task, so a deployed Keystone could only serve an empty tool list. | Medium | Fixed in `fix/ks-998-ops-console`. The YAML is stored in SSM and read from `KEYSTONE_CONFIG_YAML`; upstreams inside the VPC are allowed. |
| The load balancer's 60 s idle timeout cut a held approval wait, so the agent got a 504 instead of the approval id. | Medium | Fixed in `fix/ks-998-ops-console`: `idle_timeout = 360`. |
| Compose published every port on all interfaces, so a laptop on a shared network exposed Postgres, Redis and the Keycloak admin console. | Medium | Fixed in `fix/ks-998-ops-console`. Ports bind to `BIND_ADDRESS`, default loopback. |
| The approvals list stopped polling in a background tab, which is where the tab title count was meant to be seen. | Medium | Fixed in `fix/ks-998-ops-console`: the poll continues in the background, with a test. |
| The two Redis pool tests from KS-992 carried the `services` marker in `tests/unit`, so no CI job collected them. | Medium | Fixed in `fix/ks-998-identity-tests`. They live in `tests/integration`. |
| Two wall-clock latency budgets (p95 under 5 ms) ran in the unit job and failed on a loaded runner. | Medium | Fixed in `fix/ks-998-identity-tests`. They are `slow` and the gate runs them; a 50 ms smoke stays in the unit job. |
| After a hold, the approval slot compares the re-decided effect, not the reasons, so an approval given before the session was tainted still covers the call. | Medium | Accepted. The approval binds tool, arguments, session and user. Binding it to the policy reasons is a design change for a later version; risk 4 tools are refused outright when tainted (I8). |
| The countdown on the other approval cards moved back by up to the poll interval after a decision. | Medium | Accepted for now. Display only; the server decides expiry. |
| The red team's oracle approver stopped on a token error instead of trying again at the next pass. | Medium | Accepted for now. Eval tooling that only runs with an API key. |
