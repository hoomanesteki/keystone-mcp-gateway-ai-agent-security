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
