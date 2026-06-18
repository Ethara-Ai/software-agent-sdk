# Drift Ledger — executable Bucket-D conformance

Every Bucket-D guarantee in `CRUCIBLE.md` maps to one or more executable
conformance tests. A row is `Implemented` ONLY with a passing negative-control
test. `D-COVERAGE-GAP` rows are non-operative and **cap the disposition** until
wired. Editing `CRUCIBLE.md` and re-running reconciles the harness through this
ledger — never silently.

| # | Guarantee (CRUCIBLE §) | Module | Conformance test | Status |
|---|---|---|---|---|
| 1 | Scope sentinel refuses on mismatch (0.5) | `policy.assert_scope_approved` | `test_scope_sentinel.py::test_mismatch_refuses` | Implemented |
| 2 | Severity map total; unknown→MEDIUM (1.4) | `policy.map_severity` | `test_policy_severity.py::test_unknown_fails_closed` | Implemented |
| 3 | Required-instr finding never < MEDIUM (1.4) | `policy.map_severity` | `test_policy_severity.py::test_required_floor` | Implemented |
| 4 | cluster_fingerprint excludes line (1.4) | `models.cluster_fingerprint` | `test_fingerprint.py::test_survives_reformat` | Implemented |
| 5 | issue_instance_id per-instance multiset (1.4) | `models.issue_instance_id` | `test_fingerprint.py::test_multiset_ordinal` | Implemented |
| 6 | CVSS v3.1 base recompute (R4) | `cvss.base_score` | `test_cvss.py::test_known_vectors` | Implemented |
| 7 | R1 recall: omitted issue caught | `recall.check_recall` | `test_negative_controls.py::test_a_omitted_issue` | Implemented |
| 8 | R2 span: fabricated span caught (4 cases) | `verifier.rule_r2_spans` | `test_negative_controls.py::test_b_fabricated_span_*` | Implemented |
| 9 | R3: blocked/timeout cited caught | `verifier.rule_r3_completed_runs` | `test_negative_controls.py::test_c_blocked_run_cited` | Implemented |
| 10 | R1: empty all-SHIP with gaps caught | `verifier` | `test_negative_controls.py::test_d_empty_all_ship` | Implemented |
| 11 | R4: wrong cvss_base + bad CWE caught | `verifier.rule_r4_cvss` | `test_negative_controls.py::test_e_wrong_cvss` | Implemented |
| 12 | R3-state: dirty tree / unpinned DB caps | `verifier.rule_r3_state` | `test_negative_controls.py::test_f_dirty_tree` | Implemented |
| 13 | R6 vocabulary + tally sum | `verifier.rule_r6_vocabulary` | `test_negative_controls.py::test_r6_*` | Implemented |
| 14 | Disposition cap: producer can't exceed gate | `verifier.verify` | `test_negative_controls.py::test_disposition_cap` | Implemented |
| 15 | Verifier never OK on invariant violation | `verifier.verify` | `test_self_fuzz.py::test_fuzz_never_false_ok` | Implemented |
| 16 | report_claim untraceable → HIGH+HOLD (1.5) | `domain.report_claim_artifact_check` | `test_domain.py::test_untraced_claim` | Implemented |
| 17 | dataset_leakage NOT_APPLICABLE coverage (1.5) | `domain.dataset_leakage_check` | `test_domain.py::test_dataset_na_manifest` | Implemented |
| 18 | reward_provenance capability-only record (1.5) | `domain.reward_provenance_check` | `test_domain.py::test_reward_capability_only` | Implemented |
| 19 | rollout_integrity capability-only record (1.5) | `domain.rollout_integrity_check` | `test_domain.py::test_rollout_capability_only` | Implemented |
| 20 | Signed artifact-closure manifest (1.10) | `verifier._provenance_gate_wired` | — (spec-only) | **D-COVERAGE-GAP — caps SHIP** |
| 21 | Trusted-run-environment + signer chain (1.10) | `verifier._provenance_gate_wired` | — (spec-only) | **D-COVERAGE-GAP — caps SHIP** |
| 22 | dataset_leakage MinHash on real train/test (1.5) | `domain.dataset_leakage_check` | — (no scored dataset in scope) | Not applicable (no surface) |
| 23 | multimodal_dataset_leakage (1.5) | — | — (no scored media in scope) | Not applicable (no surface) |
| 24 | Crashed scanner fails closed (1.2 runner) | `tools._looks_fatal` | `test_tool_runner.py::test_*_is_fatal` | Implemented |

## Reconciliation rule

When `CRUCIBLE.md` changes the required-instrument set, `scope.yaml` changes,
which invalidates `scope.approved` and forces a fresh Phase-0.5 sign-off. New
guarantees append rows here marked honestly (`Implemented` only with a passing
test). A previously-`Implemented` row that loses its test reverts to
`D-COVERAGE-GAP` and re-caps the disposition.
