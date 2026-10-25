# Threat model

What can go wrong at the gateway, what stops it, and which test fails if the stop is removed.
Every link below is `file::function`, and `tests/unit/test_threat_model.py` fails when one of
them does not exist. Where nothing stops a threat, it is listed under accepted risks with the
reason, not left out.

## What is defended

Keystone sits between an agent and the tool servers it calls. The agent is not trusted: its
input can be steered by text it reads (a mail, a web page), so anything it asks for may be an
attacker's request. The tool servers are not trusted to stay as they were: a description or a
result can change. The operators who run the gateway and its database are trusted.

Out of scope: a compromised host, a compromised identity provider, and a stolen operator
account. The last one is why approvals bind to arguments and why the audit log is append-only.

## Threats (STRIDE)

| Threat | What stops it | Proven by |
|---|---|---|
| Spoofing: an agent uses another user's token on an existing session | The session is bound to tenant, user and agent when it opens. A different principal gets 403, an unknown session id gets 404. | `tests/integration/test_mcp_auth.py::test_token_swap_on_session_rejected`, `tests/integration/test_mcp_auth.py::test_session_bound_to_principal`, `tests/integration/test_mcp_auth.py::test_a_session_nobody_bound_is_never_adopted_by_whoever_asks_first` |
| Spoofing: a forged or replayed JWT | Signature check against the issuer's keys, an algorithm allowlist (RS256 and ES256), and `iss`, `aud`, `exp`, `iat` and `sub` required. | `tests/unit/test_jwt.py::test_alg_none_rejected`, `tests/unit/test_jwt.py::test_hs256_confusion_rejected`, `tests/unit/test_jwt.py::test_a_changed_payload_is_refused`, `tests/unit/test_jwt.py::test_expired_rejected`, `tests/unit/test_jwt.py::test_wrong_audience_rejected`, `tests/unit/test_jwt.py::test_wrong_issuer_rejected` |
| Tampering: an audit row is edited or removed | Each row hashes the one before it. `keystone audit verify` finds the break. The app's database role can insert and select, not update or delete. | `tests/integration/test_audit_verify.py::test_verify_detects_tampering`, `tests/integration/test_audit_verify.py::test_verify_detects_deleted_row`, `tests/integration/test_audit_verify.py::test_app_role_cannot_update` |
| Tampering: a tool's description or schema changes upstream | The definition is hashed. A change quarantines the tool until an operator approves it, and a poisoned description is held on first sight. | `tests/integration/test_pinning.py::test_changed_description_quarantines`, `tests/integration/test_pinning.py::test_a_changed_schema_quarantines_with_its_own_reason`, `tests/integration/test_pinning.py::test_poisoned_tool_quarantined_on_first_sync` |
| Repudiation: "the agent did it on its own" | Every call writes one record with user, agent, session, decision, policy reasons and the digest of the original arguments (see I2). | `tests/integration/test_audit_rows.py::test_the_audit_row_shows_the_decision_and_its_reasons`, `tests/unit/test_audit_chain.py::test_a_record_names_the_decision_the_refusal_and_the_reason` |
| Information disclosure: a credential reaches the agent or a log | The key is injected on the server side and never sent to the agent. A key an upstream echoes back is replaced in the result. The log scrubber masks secret keys and registered values. | `tests/integration/test_cred_injection.py::test_agent_never_receives_credential`, `tests/integration/test_result_scrubbing.py::test_the_key_comes_back_redacted_in_text_and_structured_content`, `tests/unit/test_logging.py::test_a_registered_secret_is_replaced_wherever_it_appears`, `tests/unit/test_logging.py::test_scrubber_redacts_secret_str_under_any_key` |
| Information disclosure: one tenant sees another's data | A tenant is on every entity. A principal cannot list or call another tenant's tool, and the default `deny-cross-tenant` policy refuses a call that crosses. | `tests/integration/test_tenants.py::test_an_unknown_tool_and_another_tenants_tool_look_the_same`, `tests/integration/test_tenants.py::test_a_request_cannot_name_another_tenant`, `tests/unit/test_policy_engine.py::test_the_shipped_pack_decides_as_the_plan_says` |
| Information disclosure: exfiltration after the agent reads untrusted text | The session records what it has read. The scanner taints a session that read an injection. The Rule of Two and `untrusted-then-external-effect` ask a person before an external effect. | `tests/integration/test_rule_of_two.py::test_untrusted_and_sensitive_then_external_requires_approval`, `tests/integration/test_rule_of_two.py::test_tainted_external_effect_requires_approval`, `tests/integration/test_taint.py::test_injected_email_taints_session`, `tests/integration/test_redteam_checks.py::test_attack_checks_detect_goal` |
| Denial of service: a runaway agent | Token-bucket rate limits, spend budgets, upstream timeouts, a 1 MiB argument limit, a 2 MiB request body limit, 16 KiB of headers, and at most 256 content blocks or 16 MiB in an upstream result. | `tests/integration/test_ratelimit.py::test_burst_over_capacity_rejected`, `tests/integration/test_budgets.py::test_budget_blocks_before_dispatch`, `tests/integration/test_upstream_client.py::test_timeout_maps_to_upstream_timeout`, `tests/unit/test_pipeline.py::test_arguments_over_one_megabyte_are_rejected`, `tests/unit/test_limits.py::test_a_body_at_the_limit_passes_and_one_byte_more_is_refused`, `tests/unit/test_limits.py::test_too_many_headers_are_refused`, `tests/unit/test_limits.py::test_a_result_with_too_many_content_blocks_is_refused` |
| Elevation: code run by a tool escapes its container | No network, read-only root, non-root user, dropped capabilities, and limits on processes, memory, CPU and time. | `tests/integration/test_sandbox_runner.py::test_every_hardening_flag_is_set_on_the_container`, `tests/integration/test_sandbox_runner.py::test_no_network`, `tests/integration/test_sandbox_runner.py::test_readonly_root`, `tests/integration/test_sandbox_runner.py::test_timeout_kills`, `tests/integration/test_sandbox_runner.py::test_memory_limit` |
| Elevation: SSRF through upstream registration | An upstream URL that resolves to a private, loopback or link-local address is refused unless the operator allows it. | `tests/unit/test_ssrf.py::test_blocks_private_ranges`, `tests/unit/test_ssrf.py::test_the_two_addresses_from_the_story_are_refused_by_default`, `tests/unit/test_ssrf.py::test_numeric_host_spellings_are_resolved_like_the_http_client_would` |
| Elevation: an approval is reused for different arguments | An approval is bound to the digest of the arguments, to the tenant, tool, session and user, and is single use with an expiry. | `tests/integration/test_approvals_service.py::test_consume_requires_matching_digest`, `tests/integration/test_approvals_service.py::test_consume_single_use`, `tests/integration/test_approvals_service.py::test_an_expired_approval_cannot_be_consumed`, `tests/integration/test_approval_interceptor.py::test_digest_mismatch_never_dispatches` |

## Invariants

The tests in `tests/invariants/` run at every phase gate.

| ID | Invariant | Proven by |
|---|---|---|
| I1 | No tool call reaches an upstream without an `allow` decision recorded first | `tests/invariants/test_i1_decision_before_dispatch.py::test_i1`, `tests/invariants/test_i1_decision_before_dispatch.py::test_i1_a_decision_that_is_not_allow_stops_the_call` |
| I2 | Every `tools/call`, rejected ones included, writes exactly one audit record | `tests/invariants/test_i2_one_audit_per_call.py::test_i2`, `tests/invariants/test_i2_one_audit_per_call.py::test_i2_concurrent_calls` |
| I3 | A canary secret never appears in logs, spans, audit rows, errors or results | `tests/invariants/test_i3_canary.py::test_i3` |
| I4 | A quarantined or disabled tool is never listed and never dispatched | `tests/invariants/test_i4_quarantine.py::test_i4` |
| I5 | A principal never lists or calls another tenant's tools | `tests/invariants/test_i5_tenants.py::test_i5` |
| I6 | With an empty policy set, every call is denied | `tests/invariants/test_i6_default_deny.py::test_i6`, `tests/invariants/test_i6_default_deny.py::test_i6_through_the_gateway` |
| I7 | A call that needs approval never dispatches without a matching, unexpired, unused approval | `tests/invariants/test_i7_approvals.py::test_i7`, `tests/invariants/test_i7_approvals.py::test_i7_an_approval_is_used_by_one_of_two_calls_that_present_it_together` |
| I8 | A tainted session never dispatches a critical-risk tool | `tests/invariants/test_i8_taint.py::test_i8`, `tests/invariants/test_i8_taint.py::test_i8_the_taint_survives_every_attempt_to_clear_it` |

## Input limits

Each limit is enforced where the data first arrives, and has a test at the limit and one byte past it.

| Input | Limit | Where | Proven by |
|---|---|---|---|
| Request body to `/mcp` | 2 MiB, 413 above | `gateway/limits.py` | `tests/unit/test_limits.py::test_a_body_at_the_limit_passes_and_one_byte_more_is_refused`, `tests/unit/test_limits.py::test_a_chunked_body_is_counted_as_it_arrives` |
| Request headers | 16 KiB in total and 100 headers, 431 above | `gateway/limits.py` | `tests/unit/test_limits.py::test_headers_over_the_byte_limit_are_refused`, `tests/unit/test_limits.py::test_too_many_headers_are_refused` |
| Tool arguments | 1 MiB as canonical JSON | `gateway/pipeline.py` | `tests/unit/test_pipeline.py::test_arguments_over_one_megabyte_are_rejected` |
| Content blocks in an upstream result | 256 | `gateway/dispatch.py` | `tests/unit/test_limits.py::test_a_result_with_too_many_content_blocks_is_refused` |
| An upstream result | 16 MiB | `gateway/dispatch.py` | `tests/unit/test_limits.py::test_a_result_over_the_byte_limit_is_refused` |
| Text the scanner reads | `scanner.max_scan_chars`, 200,000 by default, both ends | `defense/scanner.py` | `tests/unit/test_scanner.py::test_a_long_text_is_read_at_both_ends_and_says_so` |
| Approval note | 500 characters | `admin/schemas.py`, `approvals/service.py` | `tests/unit/test_limits.py::test_an_approval_note_is_cut_and_the_api_refuses_a_longer_one` |
| Arguments kept in an audit row | strings over 2,048 characters cut, 16 KiB per row | `audit/redact.py` | `tests/unit/test_redact.py::test_truncates_long_values` |

Properties that hold for any input (500 examples each): the extractors never raise, `redact` is
idempotent, `canonical_json` does not depend on key order and survives a round trip, and tool
name parsing raises only `ValueError`. They are in `tests/unit/test_fuzz.py`.

## Accepted risks

| Risk | Why I accept it | What would close it |
|---|---|---|
| SSRF through DNS rebinding. The URL is checked when an upstream is registered, so a name that resolves to a public address then and a private one later passes. | Pinning the resolved address means a custom transport under the MCP client, with TLS names handled by hand. I did not find a way to do that in half a day that I would trust. A network policy that blocks private ranges from the gateway closes it in production. | KS-995 |
| The LLM proxy is outside the policy engine, is not rate limited and writes no `audit_events` row (ADR-0016). Its record is the ledger row, the span and the log line. Budgets are its limit. | The proxy exists to meter model spend. A policy on models is a Cedar schema change that v1 does not make. | A schema change and a policy pack, after v1 |
| The proxy's check is an estimate, not a reservation. Requests in flight together can overshoot a budget by a little (ADR-0014, ADR-0016). | A reservation needs a second write on the hot path. The overshoot is bounded by the number of requests in flight. | A reservation step |
| The Docker socket is mounted into the gateway container for the sandbox and for container stdio upstreams. It is root on the host. | Both features need to start containers. The compose file says "local and single-host use only" beside the mount, and `KEYSTONE_SANDBOX_ENABLED=false` removes the need. The AWS deployment turns the sandbox off. | A separate runner service with its own host |
| The audit hash chain proves the log is consistent with itself. Someone who can rewrite the whole table can rewrite every hash, and deleting the newest rows leaves a shorter chain that still verifies (ADR-0009). | The app role cannot update or delete, which covers a compromised gateway. An attacker with the database owner role is outside this model. | Publish the latest hash somewhere the attacker cannot write (KS-996) |
| The classifier behind the scanner often does not answer within its 300 ms wait in the container, so the rules decide alone (ADR-0019). | Measured, not tuned. The rules and the Rule of Two do not depend on it. | A longer wait, a smaller model, or a model in its own process |
| An image with a hidden instruction is not read: the scanner counts image blocks and skips them. | Multimodal injection is on the list after v1. | An image-aware detector |
| The image scan lists twelve OpenStack Keystone CVEs against this package, which shares the name. | They do not apply. Each is in `.trivyignore.yaml` with its reason. | Renaming the package |

## Gaps that need code

| Row | Gap |
|---|---|
| KS-995 | Pin the resolved address of an upstream for the life of its connection. |
| KS-996 | Publish the head of the audit chain outside the database. |
