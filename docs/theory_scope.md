# Active theory scope

TDN now concentrates formal proofs on network behavior that requires reasoning across packets, paths, or sequences of operations. The [scope assessment](../specs/proof_scope.json) selected 24 requirement groups for those arguments. The other current positive contributions use direct checks over saved records. All 76 source requirements remain in [the catalog](../specs/requirement_groups.md).

The [machine-readable scope register](../specs/proof_scope.json) records the decision and reason for every RG. Each retained proof entry names its general result and a concrete application. The register describes partial contributions; it does not claim complete satisfaction of any whole RG.

## What changed

- Removed 130 Lean modules that supported routine comparisons, organizational placeholders, or earlier evidence applications superseded by the retained models. The active tree contains 184 modules, including 59 reusable semantics modules.
- Removed standalone theories for power-use records, configuration readbacks, credential-file ordering, audit-copy bookkeeping, inventory comparisons, approvals, and other clauses whose current contribution is a direct record comparison.
- Kept the packet execution, routing/filter interaction, encryption-layer order, domain isolation, topology cuts, reassembly, generated replies, mixed IPsec/MACsec behavior, authentication admission, and selected cover-traffic proofs.
- Kept local Lean checks required by those proofs. For example, MACsec protection flags and installed-association coverage still support the general emission theorem. The separate negotiated-algorithm comparison now runs in Python.
- Reduced the administration module to the retained RG-047 session-authentication argument. The optional management model remains independent of the core packet-protection proofs.
- Moved the small TRANSEC applicability record into its own retained target module. Its former component-inventory module is no longer needed.
- Replaced eight standalone Lean tests for retired models with direct-check regression cases. The packet and authentication tests remain. `tests/ProofScope.lean` checks that every retained RG mapping resolves.

The general proofs keep their parameters and assumptions. Snapshots still supply data, witnesses, and local checks. The changes remove unused proof machinery without weakening the retained packet or path conclusions.

## Current requirement decisions

| Decision | Groups | Meaning |
| --- | ---: | --- |
| General proof | 24 | Retain the behavioral argument and its required evidence checks. |
| Direct check | 29 | Check the assessed finite-record clause outside Lean. |
| External assurance or unsupported capability | 22 | Keep the requirement and limitation in the catalog. |
| Permission | 1 | RG-075 has no mandatory claim to prove. |

Each decision applies to the contribution assessed in the supplied report. RG-023 illustrates the distinction: the current lifetime-number comparison uses a direct check. A future requirement proof about reauthentication before rekeying would require reasoning about protocol actions. The scope register retains that possible extension.

## Retained behavioral contributions

| RG | Requirement area | General result |
| --- | --- | --- |
| RG-007 | Two independent encryption layers and allowed tunnel pairings | `TDN.Targets.every_black_byte_has_ordered_encryption_path` |
| RG-008 | Connectivity restricted to the same security level | `TDN.Targets.delivered_domain_from_local_checks` |
| RG-012 | Separate authentication and management for security levels | `TDN.Targets.separate_authentication_and_management_of_scoped_material` |
| RG-013 | Gray Firewalls on all paths needing level separation | `TDN.Paths.no_firewall_free_crossing` |
| RG-014 | Gray addressing supports security-level filtering | `TDN.Targets.gray_addressing_of_separated_ranges_and_named_rules` |
| RG-015 | MACsec encapsulation and standalone encapsulator obligations | `TDN.Targets.carrier_step_wraps_the_exact_input_body` |
| RG-021 | VPN private-key access confinement | `TDN.AccessControl.absent_path_is_denied` |
| RG-024 | MACsec authentication alternatives and AS scope | `TDN.KeySources.executions_have_only_authenticated_sources` |
| RG-027 | MACsec key generation, key-server selection, and rollover | `TDN.Targets.eap_key_sources_disable_pre_shared_fallback` |
| RG-028 | MACsec mandatory protection parameters | `TDN.LinkProtection.every_emitted_frame_is_encrypted` |
| RG-029 | Inner encryption and decryption cannot be bypassed | `TDN.Execution.inbound_crossing_requires_local_decryption` |
| RG-030 | Outer encryption and decryption cannot be bypassed | `TDN.Execution.inbound_crossing_requires_local_decryption` |
| RG-032 | TRANSEC under the stated deployment conditions | `TDN.CoverTraffic.all_executions_have_bounded_queues_and_fixed_records` |
| RG-033 | Packet sizing to control fragmentation | `TDN.Targets.NestedSizing.all_sizes_fit_each_interface` |
| RG-034 | Outer Firewall placement for untrusted Black transport | `TDN.Targets.outer_firewall_placement_from_local_checks` |
| RG-035 | Permitted protocols and peers at encryption and firewall boundaries | `TDN.Targets.accepted_nonloopback_output_has_peer_destination` |
| RG-037 | Outer-component third-party contact restrictions | `TDN.Targets.nonpeer_local_output_is_blocked` |
| RG-038 | IP header and multicast filtering | `TDN.PacketPolicy.accepted_immediate_header` |
| RG-039 | Outer Gray-interface allowlist and default denial | `TDN.Targets.accepted_named_peer_addresses_share_level` |
| RG-040 | Gray Firewall allowlist and cross-level denial | `TDN.Targets.different_level_addresses_are_denied` |
| RG-047 | Administrator authentication and individual credentials | `TDN.Targets.administrator_authentication_from_admitted_operations` |
| RG-054 | Interoperable components across communicating sites | `TDN.Targets.successful_ethernet_peer_restores_header` |
| RG-056 | Approved physical paths out of Red Networks | `TDN.Targets.red_egress_crosses_inner_from_attachment_cut` |
| RG-074 | Redundant component and load-balancing permission | `TDN.Paths.no_firewall_free_crossing` |

The snapshot application for each row is listed in `specs/proof_scope.json`. The selected model and evidence assumptions remain part of each result. In particular, the proofs do not establish cryptographic secrecy or universal correspondence with Linux merely by compiling.

## Direct checks and their evidence

`scripts/construction/check_configuration_records.py` performs 25 comparisons covering the 29 migrated contributions. Several RGs share a comparison. The command reads the preserved JSON records, checks their hashes against `data/evidence/manifest.json`, and reports each precise claim. It also validates the captured role readbacks through the existing raw-evidence parser and checks that selected test-result files are readable.

| Checks | Related RGs |
| --- | --- |
| Selected algorithm choices, VPN modes, certificate flags and uniqueness, lifetime bounds, MACsec options | 001, 016–020, 022, 023, 025, 026 |
| OS and hardware separation, peer CA availability, process inventories, unused interfaces, time-source placement | 004, 005, 010, 031, 036, 041, 042 |
| Captured forwarding-rule lists, DNS guard structure, supplied independent Inner-to-Outer paths | 011, 043, 053 |
| AW assignments and power observations, TLS versions, credential issuance ordering, role readbacks | 044–046, 048, 058, 068 |
| Saved offload journal, log rotation, test-result files | 062, 069, 072 |

These comparisons rely on Python and the evidence parsers for correctness. A passing result establishes only the named claim over the supplied records. A hash detects changes relative to the retained manifest; the manifest does not certify that the observations faithfully describe a real device. Raw collection, complete inventories, and the connection to implementation behavior still need justification.

RG-011 reuses the existing generic first-match filter reasoning. Its direct check verifies the raw-bound DROP defaults and captured rule lists. RG-043 checks the specific deny-prefix structure, and RG-053 checks the supplied finite paths. Their reports state those limited checks explicitly.

## Build and inspect the result

Run from the repository root:

```sh
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/check_configuration_records.py
python3 -m unittest discover -s tests -p test_configuration_records.py -v
lake env lean scripts/construction/audit_axioms.lean
```

The direct-check command prints JSON and exits unsuccessfully if any comparison fails or an input is missing. Empty inventories fail the migrated comparisons. Regression tests exercise changed cipher settings, invalid lifetimes, shared AW assignments, weakened DNS rules, journal gaps and truncation, and changed evidence hashes.

The all-theorem audit rejects dependencies beyond Lean’s standard logical axioms. `tests/ProofScope.lean` checks all retained general results and applications. A static import check also rejects references to retired modules, even if an old compiled file remains in a local build cache.

## Validation of the simplification

The clean staged-source validation on 2026-10-31 passed the 902-job Lean build, all 20 active Lean regression files, the saved-snapshot and BIRD import examples, and all 20 MCP tests. The 25 direct checks passed, covering the 29 migrated RG contributions. Ten focused Python tests check rejection cases, scope accounting, and module separation. The axiom audit checked 4,437 imported theorem declarations, including generated helper declarations, and found no dependencies beyond Lean’s three permitted logical axioms.

Before publication, 356 comments were removed from the Lean modules while preserving the two file-level introductions. A source comparison confirmed that the removal left all non-whitespace code tokens unchanged. The library guide’s source-line links were updated. Existing Lean tactic-style warnings remain.

The historical Python importer suite also uses archived run inputs outside the core checkout. The current validation commands above exercise the retained theory, direct checks, and MCP import path.

## Historical records

The earlier construction registers and HTML audits preserve the results of their recorded revisions. Their 53-group contribution count and source links describe those revisions. Use `specs/proof_scope.json` for the active scope. The full source requirements, saved observations, JSON evidence, parser implementations, and historical checkpoints remain available.

The retired module and test names are recorded in `specs/proof_scope.json`. The prior source is recoverable from Git and the existing construction history. Historical importer recipes may generate retired modules, so the construction tools guide limits those recipes to the corresponding historical checkout. New work follows the revised scope in `workflows/construction.md`.
