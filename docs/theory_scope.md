# Active theory scope

TDN now concentrates formal proofs on network behavior that requires reasoning across packets, paths, or sequences of operations. The [scope assessment](../specs/proof_scope.json) selected 24 requirement groups for those arguments. The other current positive contributions use direct checks over saved records. All 76 source requirements remain in [the catalog](../specs/requirement_groups.md).

The [machine-readable scope register](../specs/proof_scope.json) records the decision and reason for every RG. Each retained proof entry names its general result and a concrete application. Nineteen of the 24 selected groups now have reviewed proofs of every clause of their instantiated specifications. Five groups retain supporting results and are deferred by the user. The [current review record](../data/publication/v3.3/verdict.json) gives the accepted scopes and assumptions.

## Current construction result

The accepted groups are RG-007, RG-012, RG-013, RG-014, RG-021, RG-024, RG-027, RG-028, RG-029, RG-030, RG-032, RG-033, RG-034, RG-035, RG-037, RG-038, RG-039, RG-040 and RG-047. Each result has a reusable general theorem and checked applications. The theorem states the required assumptions explicitly; snapshot-specific records and finite checks live in `TDN/Deployments`.

The November 4 continuation completed four groups. RG-035 connects boundary filters to native processing and physical-frame observations. RG-039 proves the Outer Gray-interface allowlist. RG-040 proves the Gray Firewall allowlist and cross-level denial. RG-033 connects packet preparation, native processing and emitted sizes to the configured interface limits. Earlier applications were rechecked after shared model changes.

The five deferred groups are RG-008, RG-015, RG-054, RG-056 and RG-074. Their existing lemmas remain available. The user requested stopping after RG-007 passed review and releasing v3.3. Deferral does not classify those requirements as fundamentally unprovable.

### How RG-007 connects two protection layers to packet processing

`msc_nested_layer_protection` requires the declared Inner and Outer tunnel pairing throughout a protected Red payload’s execution. Gray transmission carries the Inner layer. Black transmission and reception carry Outer around Inner. Inner encryption precedes Outer encryption. Successful cross-Black delivery reaches the selected destination after Outer decryption and then Inner decryption. The specification also includes model coverage, endpoint placement, authentication-service conditions and independent key contexts.

`nested_layer_protection_from_local_checks` proves those clauses from initial-state and individual-step conditions. The proof tracks named tunnels through every finite sequence of device operations. General arguments about adding and removing protection layers establish the required encryption and decryption order. The theorem contains no concrete device names or snapshot dependencies.

Two checked applications use the same theorem. The native IPsec application covers every Red packet request allowed by the imported source records on four networks. The mixed application covers both Red networks with Inner IPsec and Outer MACsec. Imported routes, filters, directional SAs, interface identities and public authentication records provide the local facts. Separate successful executions carry nonempty traffic through 44 native steps and 28 mixed steps in each direction. A further mixed theorem connects the full specification to the captured two-sided bridge policy for every represented frame.

The applications require an explicit relation stating that the two layers use independent keys. Distinct key identifiers do not prove cryptographic independence. The native application also takes the stated GCM implementation interface. Both models hold the captured installed associations fixed and cover admitted Red payloads. Public certificate validation, faithful collection and correspondence with Linux remain explicit assumptions. Optional administration does not gate these packet proofs.

The v3.3 continuation also completed MACsec authentication under RG-024, mandatory MACsec protection under RG-028, Inner no-bypass behavior under RG-029 and Outer no-bypass behavior under RG-030. Their general theorems and exact application assumptions are retained in the current publication records.

### How RG-033 connects packet sizes to evidence

`msc_packet_size_configuration` contains five requirements. The execution model must cover the deployment. Its size calculations must correspond to the represented packets. Transmissions at Inner Gray interfaces, Outer Black interfaces and applicable Gray Firewall external interfaces must avoid further fragmentation. Every required interface must have a sizing record. Those records must satisfy the selected IPv4 or IPv6 configuration conditions and any selected Inner objective.

`complete_canonical_IPsec_packet_sizing` proves those five requirements from explicit conditions. Source processing converts application data into packets and accounts for fragmentation or stream segmentation. Device processing follows the recorded routes, ordered filters, IPsec policies, installed associations and bridge rules. The recorded forwarding guards block oversized packets after reassembly, before ESP adds its headers and encryption overhead. General proofs track the resulting size bounds through every finite execution. The emitted-byte model then accounts for the headers and encryption overhead at transmission.

The baseline application has four Red source entries and 12 required external interfaces. The shared application has eight Red source entries and 26 required external interfaces. Both import their complete interface and processing records. Finite Lean checks validate source attachments, unique identities, bridge endpoints, tunnel bindings, interface coverage and size limits. Those checks supply the general theorem's conditions. Separate checked examples follow nonempty HTTP traffic through the recorded processing rules to both an Inner Gray wire and an Outer Black wire. A stored `encodedSize` value is an upper bound set to the interface ceiling; the separate transmission proof establishes that actual represented bytes fit that ceiling.

The accepted applications select IPv4 MTU configuration and leave the optional IR-2 Inner objective unselected. Packet encoding includes modeled header fields and length calculations. The encryption primitive supplies its stated length and decoding assumptions. Checksums and unused header fields are initialized to zero, so the constructed bytes do not establish byte-for-byte replay of a captured transmission. Public SA records bind identities and transform parameters. Private-key validity, cryptographic guarantees and faithful Linux execution remain explicit implementation assumptions.

The projection preserves device-local interfaces through `Zone.local`. Local addresses belong to their recorded device, so separate namespaces can each contain loopback addresses. Ordinary Gray infrastructure must have at least one Gray interface and only Gray or local interfaces. Optional administration remains independent of the core packet proofs.

## Current requirement decisions

| Decision | Groups | Meaning |
| --- | ---: | --- |
| General proof | 24 | Retain the behavioral argument and its required evidence checks. |
| Direct check | 29 | Check the assessed finite-record clause outside Lean. |
| External assurance or unsupported capability | 22 | Keep the requirement and limitation in the catalog. |
| Permission | 1 | RG-075 has no mandatory claim to prove. |

Each decision applies to the contribution assessed in the supplied report. RG-023 illustrates the distinction: the current lifetime-number comparison uses a direct check. A future requirement proof about reauthentication before rekeying would require reasoning about protocol actions. The scope register retains that possible extension.

## General results and supporting contributions

| RG | Requirement area | General result |
| --- | --- | --- |
| RG-007 | Two independent encryption layers and allowed tunnel pairings | `TDN.Requirements.Msc.nested_layer_protection_from_local_checks` |
| RG-008 | Connectivity restricted to the same security level | `TDN.Requirements.delivered_domain_from_local_checks` |
| RG-012 | Separate authentication and management for security levels | `TDN.Requirements.Msc.key_and_management_separation_from_scoped_inventory` |
| RG-013 | Gray Firewalls on all paths needing level separation | `TDN.Requirements.Msc.gray_firewall_path_coverage_from_edge_inventory_and_rule_atoms` |
| RG-014 | Gray addressing supports security-level filtering | `TDN.Requirements.Msc.gray_addressing_from_ip_and_link_endpoint_rules` |
| RG-015 | MACsec encapsulation and standalone encapsulator obligations | `TDN.Requirements.carrier_step_wraps_the_exact_input_body` |
| RG-021 | VPN private-key access confinement | `TDN.Requirements.Msc.vpn_private_key_confinement_from_interface_steps` |
| RG-024 | MACsec authentication alternatives and AS scope | `TDN.Requirements.Msc.macsec_authentication_from_local_checks` |
| RG-027 | MACsec key generation, key-server selection, and rollover | `TDN.Requirements.Msc.macsec_key_generation_from_checked_records` |
| RG-028 | MACsec mandatory protection parameters | `TDN.Requirements.Msc.macsec_protection_from_local_checks` |
| RG-029 | Inner encryption and decryption cannot be bypassed | `TDN.Requirements.Msc.inner_tunnel_no_bypass_from_outbound_and_inbound_checks` |
| RG-030 | Outer encryption and decryption cannot be bypassed | `TDN.Requirements.Msc.outer_tunnel_no_bypass_from_local_checks` |
| RG-032 | TRANSEC under the stated deployment conditions | `TDN.Requirements.Msc.transec_conditions_from_checked_installations` |
| RG-033 | Packet sizing to control fragmentation | `TDN.Requirements.Msc.complete_canonical_IPsec_packet_sizing` |
| RG-034 | Outer Firewall placement for untrusted Black transport | `TDN.Requirements.outer_firewall_placement_from_local_checks` |
| RG-035 | Permitted protocols and peers at encryption and firewall boundaries | `TDN.Requirements.Msc.device_boundary_interface_filtering_from_checks` |
| RG-037 | Outer-component third-party contact restrictions | `TDN.Requirements.Msc.third_party_services_from_disabled_features_and_rule_checks` |
| RG-038 | IP header and multicast filtering | `TDN.Requirements.Msc.ip_and_link_header_filtering_from_inventory_and_rule_atoms` |
| RG-039 | Outer Gray-interface allowlist and default denial | `TDN.Requirements.Msc.outer_gray_IPsec_policy_from_native_checks` |
| RG-040 | Gray Firewall allowlist and cross-level denial | `TDN.Requirements.Msc.gray_firewall_allowlist_from_native_IPsec_checks` |
| RG-047 | Administrator authentication and individual credentials | `TDN.Requirements.Msc.administrator_authentication_from_local_admission_and_credential_checks` |
| RG-054 | Interoperable components across communicating sites | `TDN.Requirements.successful_ethernet_peer_restores_header` |
| RG-056 | Approved physical paths out of Red Networks | `TDN.Requirements.red_egress_crosses_inner_from_attachment_cut` |
| RG-074 | Redundant component and load-balancing permission | `TDN.Waypointing.waypointing_of_edge_invariant` |

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

The all-theorem audit accepts Lean’s standard logical axioms and re-evaluated closed `native_decide` results. The [trust policy](proof_trust.md) includes Lean’s compiler and runtime, the C compiler, and LLVM when used. Other axioms are rejected. `tests/ProofScope.lean` checks all retained general results and applications. A static import check also rejects references to retired modules, even if an old compiled file remains in a local build cache.

## Historical validation of the October 31 simplification

The clean staged-source validation on 2026-10-31 passed the 902-job Lean build, all 20 active Lean regression files, the saved-snapshot and BIRD import examples, and all 20 MCP tests. The 25 direct checks passed, covering the 29 migrated RG contributions. Ten focused Python tests check rejection cases, scope accounting, and module separation. The axiom audit checked 4,437 imported theorem declarations, including generated helper declarations, and found no dependencies beyond Lean’s three permitted logical axioms.

Before publication, 356 comments were removed from the Lean modules while preserving the two file-level introductions. A source comparison confirmed that the removal left all non-whitespace code tokens unchanged. The library guide’s source-line links were updated. Existing Lean tactic-style warnings remain.

The historical Python importer suite also uses archived run inputs outside the core checkout. The current validation commands above exercise the retained theory, direct checks, and MCP import path.

## Historical records

The earlier construction registers and HTML audits preserve the results of their recorded revisions. Their 53-group contribution count and source links describe those revisions. Use `specs/proof_scope.json` for the active scope. The full source requirements, saved observations, JSON evidence, parser implementations, and historical checkpoints remain available.

The retired module and test names are recorded in `specs/proof_scope.json`. The prior source is recoverable from Git and the existing construction history. Historical importer recipes may generate retired modules, so the construction tools guide limits those recipes to the corresponding historical checkout. New work follows the revised scope in `workflows/construction.md`.
