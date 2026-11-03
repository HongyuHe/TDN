# Construction workflow scripts

This directory contains the active tools for theory construction, evidence provision and workflow coordination. Run the commands from the TDN repository root. The [workflow](../../workflows/construction.md) defines the agents' responsibilities and stopping conditions.

New evidence requests use the [MCP server](../../mcp/README.md), which exports JSON into `data/evidence/` for Lean import commands. The generation commands below reproduce earlier construction runs. Several of their target modules were retired by the formalization-value assessment. Run those recipes in a checkout of the corresponding historical revision; they must not recreate retired modules in the active theory. Their parser entry points import shared code from `mcp/tdn_evidence/parsers/`.

| Location | Purpose |
| --- | --- |
| `import_*.py`, `analyze_topology.py`, `audit_gray_paths.py`, `bind_domains.py` | Validate observations and generate Lean evidence modules |
| `validate_evidence.py`, `native_runtime.py`, `loaded_policy.py`, `source_paths.py` | Shared evidence parsing and path resolution |
| `initialize_register.py`, `update_register.py`, `refresh_contributions.py`, `reconcile_dependencies.py` | Maintain requirement targets, contributions and dependencies |
| `run_validation.py`, `check_register_claims.py`, `review_coverage.py`, `finalize_validation.py`, `write_reports.py` | Run the proof checks and produce scoped reports |
| `record.py`, `sync_agents.py`, `promote_snapshots.py`, `check_run.py`, `summarize_run.py` | Preserve checkpoints, exchange evidence and track the run |
| start_continuation.py, collect_continuation.py, handoff_continuation.py, audit_continuation.py, integrate_continuation.py | Create isolated workspaces, preserve versions, validate handoffs and audits, and integrate with conflict checks |
| [evidence/](evidence/README.md) | Build images, generate profiles, deploy emulations, collect snapshots and run protocol experiments |

The shared `record.py` preserves nested history through manifest references. Both the validation runner and coordinator use that implementation.

## Run supervised v3.1 construction

`start_v31.py` creates a new UTC-stamped run, preserves the current source checkpoint, and prepares a Constructor workspace under `/tmp`. The workspace contains the active theory, permitted source requirements, current campaign evidence, and pinned Lean dependencies. Repository history and the archived theory are excluded. The generated execution wrapper denies access to the original project and Codex directories. Agents must use that wrapper for filesystem commands; the tool service itself is not confined by the wrapper.

```sh
python3 scripts/construction/start_v31.py
```

The supervisor launches the independent Constructor with GPT-6.1 Sol at `xhigh`. After the Constructor compiles a complete 24-specification candidate, `prepare_interpretation.py` freezes its sources and uses `export_spec_definitions.lean` to export the actual compiled definitions. Each fresh GPT-6.1 Sol interpreter at `high` receives only those definitions and their dependencies. The supervisor retains the source-to-RG mapping outside the interpreter workspace.

```sh
python3 scripts/construction/prepare_interpretation.py \
  --run v3.1-TIMESTAMP \
  --workspace /tmp/tdn-v3.1-TIMESTAMP/constructor \
  --round 1
```

`mcp_session.py` calls the real evidence server through its stdio MCP interface. Run it with the MCP package environment and a trusted configuration. Its request file contains an array of tool calls or resource reads. Each response, including failures, is saved to a new JSONL file. A failed tool call produces a nonzero client exit code. A collection request can set `wait_complete` to keep the session open while recording status polls. Subsequent requests can refer to a named result through `$result.ID.field`.

```sh
uv run --frozen --project mcp python scripts/construction/mcp_session.py \
  --config inputs/evidence-mcp.json \
  --requests inputs/requests.json \
  --output outputs/mcp/session-001.jsonl
```

The workflow defines uncapped interpretation rounds and separate proof-validation rounds. Full clause coverage, kernel checks, meaningful assumptions, and reusable general proofs are required for PASS. A failing eleventh proof-validation round ends the run with its remaining work recorded. All new records stay under the new run directory.

`export_proof_audit.lean` reads a newline-separated list of fully qualified theorem names from `TDN_PROOF_NAMES`. After a successful build, it writes their compiled assumptions, conclusions, transitive TDN dependencies, and axioms to the path in `TDN_PROOF_AUDIT`. The command rejects missing names, definitions supplied as proofs, and axioms beyond Lean's three permitted foundational axioms. The supervisor still reviews whether the assumptions justify the source requirements and whether concrete observations establish them.

```sh
TDN_PROOF_NAMES=outputs/proof-names.txt \
TDN_PROOF_AUDIT=outputs/proof-audit.json \
lake env lean scripts/construction/export_proof_audit.lean
```

`export_spec_definitions.lean` records each specification's readable form and complete internal Lean expressions, including implicit arguments. Rebuild the accepted frozen source and the proof candidate with the same pinned dependencies before comparing those exports. `check_proof_submission.py` checks the 24-target mapping, the compiled general proofs, their evidence dependencies, and changes to the accepted definitions. The checker reports whether the accepted export contains the complete expressions. Older exports remain usable but compare only their recorded fields. The supervisor reviews clause coverage and assumptions separately.

`checkpoint_proof_attempts.py` archives completed attempts with their logs and hash-checked source checkpoints. It excludes unfinished attempts and creates a new archive without replacing an earlier one. `record_agent_messages.py` preserves the actual agent prompts and replies for the selected run interval.

## Validate the active theory

```sh
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/check_configuration_records.py
lake env lean scripts/construction/audit_axioms.lean
```

The [scope guide](../../docs/theory_scope.md) and [76-group scope register](../../specs/proof_scope.json) describe the current theory. The direct-check command validates the migrated configuration and recorded-operation clauses without generating Lean code. Its JSON output includes the checked claims and input hashes.

## Replay the historical continuation

Run from the repository root. Set both workspace-relative paths explicitly. The derived current manifest selects the immutable Evidence v7 case ledger with all 59 representative cases. The original input manifest and previous run remain unchanged.

~~~sh
export TDN_INPUT_MANIFEST=data/construction/2026-10-24T014455Z/source_paths_current.json
export TDN_OUTPUT_DIR=data/construction/2026-10-24T014455Z

python3 scripts/construction/record_attempt.py --label local-current-build -- lake build
python3 scripts/construction/record_attempt.py --label local-current-axioms -- lake env lean scripts/construction/audit_axioms.lean
python3 scripts/construction/record_attempt.py --label local-current-python-tests -- python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/construction/record_attempt.py --label local-all-lean-tests -- python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/record_attempt.py --label local-current-map -- python3 scripts/construction/refresh_progress.py
python3 scripts/construction/record_attempt.py --label local-current-case-coverage -- python3 scripts/construction/review_coverage.py
~~~

Run dependent commands only after their predecessors succeed. The axiom audit must follow the build. An interrupted or failed build cannot support a final axiom result. The record_attempt tool records the exact command, working directory, toolchain, source checkpoint and failure status. Its output path is configurable through TDN_OUTPUT_DIR or --run-dir.

The recorder also captures command-target Lean, Python and JSON files, including temporary fixtures under the run's output directory. It follows literal `tdn_data` JSON references relative to each Lean file. Use `--input path/to/file` for additional inputs consumed through scripts or environment variables. Missing referenced inputs are listed explicitly. The checkpoint preserves the copied bytes and avoids duplicate entries when input paths overlap.

The older run_validation tool remains available for its original selected input set. It does not regenerate every continuation module. Use the current generators below and retain the commands recorded in the current run's experiment attempt files for other scoped imports. Regeneration remains part of the active completion work; the checks above do not claim whole-document compliance.

## Regenerate mixed mechanisms

These commands rebuild the six final routed pairings and the separate bridged opaque-Ethernet case. The generators validate manifest hashes, raw command bindings, complete operational inventories, epochs and local forwarding settings before writing Lean facts.

~~~sh
python3 scripts/construction/generate_pairing_configs.py --bundles data/snapshots/2026-10-24T014455Z/pairings-v7 --output TDN/Evidence/FreshPairingConfigs.lean --reports "$TDN_OUTPUT_DIR/pairing-execution-v7"
python3 scripts/construction/generate_pairing_checks.py --reports "$TDN_OUTPUT_DIR/pairing-execution-v7" --output TDN/Evidence/FreshPairingStackChecks.lean
python3 scripts/construction/generate_pairing_configs.py --bundles data/snapshots/2026-10-24T014455Z/bridged-macsec-v8 --output TDN/Evidence/FreshBridgedMACsecConfig.lean --reports "$TDN_OUTPUT_DIR/bridged-macsec-execution-v8"
python3 scripts/construction/generate_pairing_checks.py --reports "$TDN_OUTPUT_DIR/bridged-macsec-execution-v8" --config-module TDN.Evidence.FreshBridgedMACsecConfig --output TDN/Evidence/FreshBridgedMACsecChecks.lean
python3 scripts/construction/generate_mixed_suite.py --reports "$TDN_OUTPUT_DIR/pairing-execution-v7" --bridged-reports "$TDN_OUTPUT_DIR/bridged-macsec-execution-v8" --traces "$TDN_OUTPUT_DIR/mixed-traces"
lake build TDN.Evidence.FreshMixedDeliverySuite
python3 -m unittest discover -s tests -p test_pairing_execution.py
~~~

Wrap each regeneration/build/test command with record_attempt.py and a distinct label when preserving a new iteration. The mixed suite includes both directions for all six pairings and both directions with zero, one and two protected VLAN tags. General layer and event-order proofs remain unchanged between applications.

## Continuation importer and test inventory

The current test suite includes the raw execution/family importers, original-versus-normalized policy correspondence, physical placement and OS binding, administration API permissions, EAP/MACsec runtime, IPv6 header gates, DNS/PF state, PMTU and mixed mechanisms. Use the full unittest discovery command above to avoid silently omitting newly added fixtures. Lean regression files under tests need their recorded lake env lean commands separately.

The refresh_progress tool maintains current declaration locations and hashes. The reconcile_current_status tool updates reviewed canonical dispositions. The refresh_completion_assessment tool refreshes all 76 groups while preserving earlier assessment/register bytes by hash. Those status tools do not manufacture a completed proof from a successful build. Source-passage reconciliation, concrete assumptions and actual applications remain required.

## Preserve historical evidence

The snapshots and source checkpoints under `artifacts/` retain their original paths, content and hashes. References inside those historical records describe the commands that actually ran. Current commands use this directory. The [relocation record](../../data/construction/script-organization/relocation.json) maps the previous locations to the active tools.

Specification preprocessing remains in `scripts/preprocess`. Prior-work property extraction remains in `scripts/extract_prior_work_properties.py`.

## Regenerate current loaded-mode and response applications

The exact recorded commands also appear in the run experiment records. Use distinct record_attempt labels for each invocation.

~~~sh
python3 scripts/construction/import_vpn_modes.py data/snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z --namespace FreshBaselineVPNModes --output TDN/Evidence/FreshBaselineVPNModes.lean --report "$TDN_OUTPUT_DIR/fresh-baseline-vpn-modes.json"
python3 scripts/construction/import_vpn_modes.py data/snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1 --namespace FreshSharedVPNModes --output TDN/Evidence/FreshSharedVPNModes.lean --report "$TDN_OUTPUT_DIR/fresh-shared-vpn-modes.json"
python3 scripts/construction/import_family_execution.py data/snapshots/2026-10-24T014455Z/families-v13/families-444 --namespace Family444V13 --output TDN/Evidence/FreshFamily444V13.lean --report "$TDN_OUTPUT_DIR/family444-v13-execution.json"
python3 scripts/construction/generate_execution_witness.py "$TDN_OUTPUT_DIR/family444-v13-execution.json" --module TDN.Evidence.FreshFamily444V13 --namespace Family444V13 --source-port HA:red --destination-port HB:red --output TDN/Evidence/FreshFamily444V13Witness.lean --trace "$TDN_OUTPUT_DIR/family444-v13-positive-trace.json"
python3 scripts/construction/generate_family_response_guards.py "$TDN_OUTPUT_DIR/family444-v13-execution.json" --module TDN.Evidence.FreshFamily444V13 --namespace Family444V13 --output TDN/Evidence/FreshFamily444V13ResponseGuards.lean --trace "$TDN_OUTPUT_DIR/family444-v13-positive-trace.json" --witness-module TDN.Evidence.FreshFamily444V13Witness
python3 scripts/construction/generate_guarded_response_execution.py "$TDN_OUTPUT_DIR/family444-v13-positive-trace.json" --namespace Family444V13 --guard-module TDN.Evidence.FreshFamily444V13ResponseGuards --output TDN/Evidence/FreshFamily444V13ResponseExecution.lean
lake build
python3 scripts/construction/refresh_progress.py
python3 scripts/construction/close_verified_configuration_scopes.py
python3 scripts/construction/reconcile_source_passages.py
python3 scripts/construction/refresh_completion_assessment.py
python3 scripts/construction/check_register_claims.py
lake env lean "$TDN_OUTPUT_DIR/RegisterClaims.lean"
~~~

The last command type-checks closed applications of the actual registered specifications. Completion metadata does not replace that check or source/evidence review. The current RG022 completion concerns complete explicitly named fixed configurations. RG005 has a closed physical-separation specification while embedded Components List qualifiers remain separately unfulfilled.

The isolated Construction workspace intentionally omits preprocessing and prior-work scripts. Full Python discovery there records three import errors for those absent modules. The coordinator runs the complete root suite in the authorized root environment. Do not copy excluded historical inputs into the isolated workspace to make those unrelated modules load.

## Regenerate receiving-boundary and optional service applications

Run these commands through record_attempt.py with distinct labels. The mixed-boundary generator consumes the validated pairing reports and positive traces generated above.

~~~sh
python3 scripts/construction/generate_mixed_boundaries.py
python3 scripts/construction/import_admin_sessions.py --deployment data/snapshots/2026-10-24T014455Z/role-admin-deploy-v4 --effective data/snapshots/2026-10-24T014455Z/role-admin-effective-v3 --matrix data/snapshots/2026-10-24T014455Z/role-admin-matrix-v3 --output TDN/Evidence/FreshAdministratorSessions.lean --report "$TDN_OUTPUT_DIR/fresh-administrator-sessions.json"
python3 scripts/construction/import_optional_screening.py --bundle data/snapshots/2026-10-24T014455Z/utility-v4/screen-existing --output TDN/Evidence/FreshOptionalScreening.lean --report "$TDN_OUTPUT_DIR/fresh-optional-screening.json"
lake build
python3 scripts/construction/run_lean_tests.py
python3 -m unittest discover -s tests -p test_admin_sessions.py
python3 -m unittest discover -s tests -p test_optional_screening.py
~~~

The mixed applications permit arbitrary inward bodies and require actual receiving decryption at each selected component. The administration application covers retained successful service requests under the reviewed TLS/handler contract. The screening application checks placement for the two selected existing routers. Human administration duties, additional screening alternatives and other requirement clauses remain separately accounted.

## Regenerate final MACsec, clock and byte-flow contributions

The following commands consume accepted local artifacts. They perform no collection or remote action. Set TDN_INPUT_MANIFEST and TDN_OUTPUT_DIR as shown above. Preserve each command through record_attempt.py.

~~~sh
TDN_SNAP=data/snapshots/2026-10-24T014455Z
python3 scripts/construction/import_macsec_runtime.py "$TDN_SNAP/eap-tls-forward-v18" "$TDN_SNAP/eap-tls-reverse-v18" --namespace FinalMACsecRuntime --output TDN/Evidence/FinalMACsecRuntime.lean --report "$TDN_OUTPUT_DIR/final-macsec-runtime.json"
python3 scripts/construction/import_macsec_algorithms.py "$TDN_SNAP/eap-tls-forward-v18" "$TDN_SNAP/eap-tls-reverse-v18" --bindings "$TDN_SNAP/hostap-kdf-bindings-v4" --runtime "$TDN_SNAP/final-hostap-runtime-v4" --vectors "$TDN_SNAP/hostap-kdf-vectors-v3" --output TDN/Evidence/FinalMACsecAlgorithms.lean --report "$TDN_OUTPUT_DIR/final-macsec-algorithms.json"
python3 scripts/construction/import_macsec_protection.py "$TDN_SNAP/eap-tls-forward-v18" "$TDN_SNAP/eap-tls-reverse-v18" --bindings "$TDN_SNAP/hostap-kdf-bindings-v4" --runtime "$TDN_SNAP/final-hostap-runtime-v4" --callback "$TDN_SNAP/hostap-auth-lowest-pn-v5" --output TDN/Evidence/FinalMACsecProtection.lean --report "$TDN_OUTPUT_DIR/final-macsec-protection.json"
python3 scripts/construction/import_macsec_key_servers.py "$TDN_SNAP/eap-tls-forward-v18" "$TDN_SNAP/eap-tls-reverse-v18" --output TDN/Evidence/FinalMACsecKeyServers.lean --report "$TDN_OUTPUT_DIR/final-macsec-key-servers.json"
python3 scripts/construction/import_macsec_key_sources.py "$TDN_SNAP/eap-tls-forward-v18" "$TDN_SNAP/eap-tls-reverse-v18" --bindings "$TDN_SNAP/hostap-kdf-bindings-v4" --runtime "$TDN_SNAP/final-hostap-runtime-v4" --source-dir "$TDN_OUTPUT_DIR/evidence/runtime/hostap-source" --output TDN/Evidence/FinalMACsecKeySources.lean --report "$TDN_OUTPUT_DIR/final-macsec-key-sources.json"
python3 scripts/construction/import_clock_corrections.py --red "$TDN_SNAP/independent-Red-clocks-v3" --gray "$TDN_SNAP/independent-Gray-clocks-v3" --output TDN/Evidence/FreshClockCorrections.lean --report "$TDN_OUTPUT_DIR/fresh-clock-corrections.json"
python3 scripts/construction/generate_native_response_isolation.py
python3 scripts/construction/generate_received_domain_checks.py
python3 scripts/construction/generate_byte_domain_checks.py
lake build
python3 scripts/construction/run_lean_tests.py
python3 -m unittest discover -s tests -p 'test_macsec*.py'
python3 -m unittest discover -s tests -p test_clock_corrections.py
python3 scripts/construction/check_register_claims.py
lake env lean "$TDN_OUTPUT_DIR/RegisterClaims.lean"
~~~

The MACsec results distinguish configured protection, negotiated algorithms, reported CKN lengths and fixed-configuration key sources. The clock result covers measured improvements after actual adjustments. The byte-flow model permits arbitrary simultaneous packets, repeated partitions and mixed-packet plaintext assembly before continued forwarding. Every result retains its source and backend assumptions. The complete physical-interface, encrypted assembly, response and other-case obligations remain in the all-76 assessment.

## Regenerate the recorded audit-copy contribution

~~~sh
python3 scripts/construction/import_audit_offload.py data/snapshots/2026-10-24T014455Z --output TDN/Evidence/FreshAuditOffload.lean --report "$TDN_OUTPUT_DIR/fresh-audit-offload.json"
python3 -m unittest discover -s tests -p test_audit_offload.py
~~~

Wrap each command in record_attempt.py. The proof covers every byte position in one frozen source copy and transfers that coverage through one observed service restart. Recurring offload, rotation, calendar retention and power failure remain distinct obligations.

## Regenerate combined response and byte applications

~~~sh
python3 scripts/construction/generate_encrypted_response_guards.py --module TDN.Evidence.FreshFamily444V13ResponseExecution --namespace Family444V13 --output TDN/Evidence/FreshEncryptedResponseGuards.lean --trace "$TDN_OUTPUT_DIR/family444-v13-positive-trace.json"
python3 scripts/construction/generate_uniform_responses.py --report "$TDN_OUTPUT_DIR/family444-v13-execution.json" --module TDN.Evidence.FreshEncryptedResponseGuards --namespace Family444V13 --output TDN/Evidence/FreshUniformResponses.lean --trace "$TDN_OUTPUT_DIR/family444-v13-positive-trace.json" --scope-report "$TDN_OUTPUT_DIR/family444-v13-response-component-scope.json"
python3 scripts/construction/generate_native_response_isolation.py
python3 scripts/construction/generate_received_domain_checks.py
python3 scripts/construction/generate_byte_domain_checks.py
python3 scripts/construction/generate_byte_response_checks.py
~~~

Wrap each generator in record_attempt.py. The native generators use the already imported shared and baseline observations and recheck their local conditions in Lean. Run the full build, all standalone Lean tests and the axiom audit afterward.

## Regenerate provisioning execution locations

~~~sh
python3 scripts/construction/import_provisioning_locations.py data/snapshots/2026-10-24T014455Z/eap-tls-forward-v18 data/snapshots/2026-10-24T014455Z/eap-tls-reverse-v18 --output TDN/Evidence/FreshProvisioningLocations.lean --report "$TDN_OUTPUT_DIR/fresh-provisioning-locations.json"
python3 -m unittest discover -s tests -p test_provisioning_locations.py
~~~

The records identify worker execution. They cannot satisfy component-owned key and CSR generation. Preserve that counterexample and the unperformed repair separately from successful command order and certificate-path observations.

The component-byte response generator is scripts/construction/generate_component_byte_response_checks.py. Run it through record_attempt.py with TDN_OUTPUT_DIR set to the current run, then build FreshComponentByteResponses and run every standalone Lean regression with run_lean_tests.py. The generator reuses current imported native inventories and checks all component owners.

## Validate native fragment filtering and nft hooks

Preserve each command through record_attempt.py. The native execution importer now calls native_nft_correspondence before generating facts. Its mutation suite checks complete hook inventories, raw rules, policies and namespace/PID bindings. The fragment generator reuses the current native modules.

~~~sh
python3 scripts/construction/generate_fragment_header_checks.py
python3 scripts/construction/generate_byte_layer_order_checks.py
python3 -m unittest discover -s tests -p test_native_nft_correspondence.py
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/refresh_progress.py
python3 scripts/construction/refresh_completion_assessment.py
python3 scripts/construction/check_register_claims.py
lake env lean "$TDN_OUTPUT_DIR/RegisterClaims.lean"
lake env lean scripts/construction/audit_axioms.lean
~~~

The exact local-source and native correspondence review is fragment-header-nft-review.md in the selected output directory. The imported hook facts are fixed-state observations. Encrypted reassembly remains a separate connection in the completion assessment.

## Mixed per-byte and additional local evidence checks

Run the following commands through record_attempt.py with the current run environment. These commands use only retained public artifacts.

~~~sh
python3 scripts/construction/generate_mixed_byte_checks.py
python3 -m unittest discover -s tests -p test_classical_ike.py
python3 -m unittest discover -s tests -p test_nested_sizing.py
python3 -m unittest discover -s tests -p test_macsec_options.py
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/refresh_progress.py
python3 scripts/construction/refresh_completion_assessment.py
python3 scripts/construction/check_register_claims.py
lake env lean "$TDN_OUTPUT_DIR/RegisterClaims.lean"
lake env lean scripts/construction/audit_axioms.lean
~~~

The mixed generator applies one per-byte stack/order theorem to seven configurations and retains eighteen nonempty useful paths. AuthenticatedAssembly remains a general conditional contribution with explicit plaintext projection, all-producer coverage and initial-history assumptions. Classical IKE, nested sizing and optional MACsec features retain their exact configuration and implementation scopes in their current-run review files.

## Session and source-attempt validation

Run these local commands through record_attempt.py with the current run environment. The IKE importer tests cover reciprocal negotiated session facts. The source-attempt ledger records exact assignments and leaves full obligation coverage open until a complete subclause audit exists.

~~~sh
python3 -m unittest discover -s tests -p test_ike_contexts.py
python3 scripts/construction/build_attempt_ledger.py
python3 scripts/construction/refresh_completion_assessment.py
~~~

AuthenticatedAssembly requires a complete publication history or an explicitly safe seeded history. CiphertextTransit supplies the non-cryptographic path substitution proof. Their standalone regressions run through run_lean_tests.py along with every other current Lean regression.

## Revised practical-proof stopping audit

The revised user goal requires a meaningful positive partial application for each practically eligible group. The all-group classification is in practical-provability-review.json. The original full-clause queue is preserved separately. Cross-accounted source clauses are identified explicitly; the report does not count complete independent specifications.

Use the current relative run paths and retain each command through record_attempt.py:

~~~sh
export TDN_OUTPUT_DIR=data/construction/2026-10-24T014455Z
export TDN_INPUT_MANIFEST=data/construction/2026-10-24T014455Z/source_paths_current.json
python3 scripts/construction/refresh_progress.py
python3 scripts/construction/build_practical_provability.py
python3 scripts/construction/refresh_completion_assessment.py
python3 scripts/construction/check_register_claims.py
python3 scripts/construction/check_practical_proofs.py --root . --register "$TDN_OUTPUT_DIR/practical-provability.json" --output "$TDN_OUTPUT_DIR/PracticalProofDependencies.lean"
lake build
lake env lean "$TDN_OUTPUT_DIR/RegisterClaims.lean"
lake env lean "$TDN_OUTPUT_DIR/PracticalProofDependencies.lean"
lake env lean scripts/construction/audit_axioms.lean
python3 scripts/construction/run_lean_tests.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/construction/audit_continuation.py --workspace . --run 2026-10-24T014455Z --output "$TDN_OUTPUT_DIR/validation/final-source-audit.json" --require-current-map
~~~

The isolated Construction workspace intentionally omits three preprocessing/prior-work dependencies. Its full discovery records those import errors; the coordinator runs the complete suite in the active root. No test is silently skipped. The standalone Lean runner discovers every current tests/*.lean file.

The final partial-clause imports include import_routing_processes.py, import_vpn_observed_clauses.py, import_unused_interfaces.py, import_red_time_placement.py, import_recorded_operations.py and import_placement_clauses.py. Their exact bundle/output command lines are retained in the current run's experiment records. check_clause_role_bindings.py rechecks the actual Gray Firewall indices and reciprocal Outer peers used by the address and OUTPUT clause proofs. Every new parser's mutation suite is included in Python discovery. Source-only bridges reuse earlier imported facts; they do not invent new observations.

The final retained clause facts can be regenerated with the following inputs. Wrap each command with record_attempt.py and a distinct label.

~~~sh
TDN_SNAP=data/snapshots/2026-10-24T014455Z
python3 scripts/construction/import_routing_processes.py --inventory "$TDN_SNAP/native-all-process-inventory-v3" --bundles "$TDN_SNAP/native-baseline-20261024T015000Z" "$TDN_SNAP/native-shared-four-levels-20261024T015300Z-coverage-v1" --output TDN/Evidence/FreshRoutingProcesses.lean --report "$TDN_OUTPUT_DIR/fresh-routing-processes.json"
python3 scripts/construction/import_vpn_observed_clauses.py "$TDN_SNAP/native-shared-four-levels-20261024T015300Z-coverage-v1" --public "$TDN_SNAP/native-public-auth-bindings-20261024T020200Z" --output TDN/Evidence/FreshVPNObservedClauses.lean --report "$TDN_OUTPUT_DIR/fresh-vpn-observed-clauses.json"
python3 scripts/construction/import_unused_interfaces.py "$TDN_SNAP/native-shared-four-levels-20261024T015300Z-coverage-v1" --output TDN/Evidence/FreshUnusedInterfaces.lean --report "$TDN_OUTPUT_DIR/fresh-unused-interfaces.json"
python3 scripts/construction/import_red_time_placement.py --clocks "$TDN_SNAP/independent-Red-clocks-v3" --setup "$TDN_SNAP/freebsd-native-integration-v3" --output TDN/Evidence/FreshRedTimePlacement.lean --report "$TDN_OUTPUT_DIR/fresh-red-time-placement.json"
python3 scripts/construction/import_recorded_operations.py --base "$TDN_SNAP" --output TDN/Evidence/FreshRecordedOperations.lean --report "$TDN_OUTPUT_DIR/fresh-recorded-operations.json"
python3 scripts/construction/import_placement_clauses.py
python3 scripts/construction/check_clause_role_bindings.py
~~~

The final RG069 application uses the actual retained Auditor log rotation:

~~~sh
python3 scripts/construction/import_auditor_rotation.py --base data/snapshots/2026-10-24T014455Z --derived "$TDN_OUTPUT_DIR/evidence/derived-auditor-rotation-v1" --output TDN/Evidence/FreshAuditorRotation.lean --report "$TDN_OUTPUT_DIR/fresh-auditor-rotation.json"
python3 -m unittest discover -s tests -p 'test_auditor_rotation_*.py'
~~~

The current criterion counts 53 positive partial groups and 23 currently unsupported groups. RG075's optional placement theorem remains available but does not count as a security requirement. RG069 uses exact observed log-prefix preservation, not a method-permission theorem standing in for human review.
