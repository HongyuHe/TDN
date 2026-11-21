# Active theory scope

<!-- BEGIN review status -->
TDN v3.4 selects 10 requirement groups. General proofs for 10 have passed review under their stated assumptions.

- The baseline deployment satisfies the full connectivity requirement. Lean checks 4 intended delivery paths.
- The shared deployment preserves forwarding isolation and violates the inherited physical-separation duty because `V31F_I_A4` and `V31F_O_A1` share a host. Lean checks 8 intended delivery paths.

[Current verdict](../data/publication/v3.4/verdict.json). [Source clauses, interpretations and evidence](../specs/requirement_clauses.md).
<!-- END review status -->

| What the proofs cover | Active requirements |
| --- | --- |
| Protected Red traffic on Black links and delivery within a security level | RG-007, RG-008 |
| Gray and Outer Firewall placement | RG-013, RG-034 |
| Preventing encryption and decryption bypass at the Inner and Outer boundaries | RG-029, RG-030 |
| Allowed boundary traffic, IP headers, multicast, and Gray firewall rules | RG-035, RG-038, RG-039, RG-040 |

The [scope register](../specs/proof_scope.json) identifies each active specification, general result and example. The [formalization map](../specs/requirement_formalizations.md) links all 76 source groups to their current Lean definitions or catalog conditions. The [November 11 record](../data/publication/v3.3/verdict.json) preserves the review of the earlier selection.

## How the source is organized

[MscRequirements.lean](../TDN/Requirements/MscRequirements.lean) defines the ten targets. Network models describe the steps a device can take. General theorems in [Requirements](../TDN/Requirements/) use those steps to prove properties across possible paths and packets. Files in [Deployments](../TDN/Deployments/) check the facts for a specific deployment and apply the general theorem.

The other 66 groups retain their source text and catalog conditions. RG-008 refers to the catalog when it requires included networks and referenced solutions to satisfy their applicable duties. The library also retains packet-size, authentication and encapsulation definitions used by selected packet proofs. For RG-054, the catalog calls for testing each selected tunnel between the actual peers in both directions.

### How RG-007 connects two protection layers to packet processing

`nested_layer_protection` requires the declared Inner and Outer tunnel pairing throughout a protected Red payload’s execution. Gray transmission carries the Inner layer. Black transmission and reception carry Outer around Inner. Inner encryption precedes Outer encryption. Successful cross-Black delivery reaches the selected destination after Outer decryption and then Inner decryption. The specification also includes model coverage, endpoint placement, authentication-service conditions and independent key contexts.

`nested_layer_protection_from_local_checks` proves those clauses from initial-state and individual-step conditions. The proof tracks named tunnels through every finite sequence of device operations. General arguments about adding and removing protection layers establish the required encryption and decryption order. The theorem contains no concrete device names or snapshot dependencies.

Two checked applications use the same theorem. The native IPsec application covers every Red packet request allowed by the imported source records on four networks. The mixed application covers both Red networks with Inner IPsec and Outer MACsec. Imported routes, filters, directional SAs, interface identities and public authentication records provide the local facts. Separate successful executions carry nonempty traffic through 44 native steps and 28 mixed steps in each direction. A further mixed theorem connects the full specification to the captured two-sided bridge policy for every represented frame.

The applications require an explicit relation stating that the two layers use independent keys. Distinct key identifiers do not prove cryptographic independence. The native application also takes the stated GCM implementation interface. Both models hold the captured installed associations fixed and cover admitted Red payloads. Public certificate validation, faithful collection and correspondence with Linux remain explicit assumptions. Optional administration does not gate these packet proofs.

RG-029 and RG-030 cover bypass at the Inner and Outer encryption boundaries. Their proofs share packet-size bounds and records of transmitted frames with the double-encryption proof. The earlier review of MACsec authentication and protection settings under RG-024 and RG-028 remains in the [November 11 review](../data/publication/v3.3/verdict.json).

### How to inspect RG-008

The [scoped forwarding theorem](../TDN/Requirements/SecurityLevelConnectivity.lean) proves dedicated Inner assignments, matching security levels, successful intended delivery and isolation on every forwarding trace. Both deployments use that argument. The full specification adds closed references to other solutions and inherited duties for each included unclassified network. The [baseline proof](../TDN/Deployments/SecurityLevelConnectivity_Baseline.lean) discharges those conditions with its roster. The [shared deployment](../TDN/Deployments/SecurityLevelConnectivity_Shared.lean) has eight successful paths and a physical-host counterexample to the full specification.

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

Lean uses its default elaboration allowance across the theory. Two declarations in [the MACsec traffic examples](../TDN/Deployments/MacsecProtection_TrafficExamples.lean) need a larger finite allowance. Each increase applies only to the named declaration. The [source check](../scripts/construction/check_proof_limits.py) also checks the construction generators.

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
