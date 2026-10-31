import json
from pathlib import Path
from source_paths import output_path

review=json.loads(output_path("coverage-review.json").read_text())
validated=json.loads(output_path("validated-source-manifest.json").read_text())
register=json.loads(output_path("theorem_register.json").read_text())
requests=json.loads(output_path("evidence_requests.json").read_text())
scopes=review["scope_counts"]
report=f"""# Construction results

The fresh development retains all 76 original targets and every indexed source clause. Nine encompassing propositions are encoded in Lean. Three groups have checked encompassing results within explicitly listed snapshot/model scopes: RG-022 has {scopes.get('RG-022',0)} scopes, RG-034 has {scopes.get('RG-034',0)}, and RG-038 has {scopes.get('RG-038',0)}. The remaining 67 encompassing propositions have not been fully encoded. Their original statements, proposed meanings and unresolved work remain visible in the register. No result establishes complete CP compliance for any deployment.

## Established group scopes

RG-022 checks every proposal in complete loaded IKE connection inventories. The property preserves IKEv2 and the permitted CBC/GCM alternatives. Native FRR/OVS infrastructure and historical Linux profiles have separate instances. Public files, exact-file load confirmations and runtime connection identities are bound by hashes. The loader/runtime correspondence remains an explicit assumption because the runtime interface does not export every proposal suite.

RG-034 checks the declared emulated-Public-Internet branch in one historical topology and five native profiles. Every modeled Outer-to-Black path traverses an Outer Firewall, with oriented inside/outside placement and an explicit Gray path to a required Gray Firewall. The native declaration binds exact snapshot and spec hashes. OVS UUID memberships, raw interface identity and FRR control/forwarding namespace correspondence are checked before graph construction. The graph conservatively connects supported switch ports and contracts each device. The graph proof does not certify OpenFlow execution, physical independence, live Internet attachment or future state.

RG-038 checks the listed IPv4 IPsec profiles against the full encoded header/filter target, including selected Outer IPv4-options restrictions and modeled external multicast exclusion. The finite chain certificates quantify every accepted modeled packet in INPUT, FORWARD and OUTPUT. The proof depends on token semantics and Linux hook correspondence. Active IPv6 and MACsec alternatives remain separate. Known inactive GRE fallback interfaces require explicit down, unaddressed, unrouted, unattached and unconfigured-endpoint checks; no missing sysctl value is invented.

Every establishment in `theorem_register.json` names its precise theorem, platform, report, assumptions, evidence keys and completed validation reference. The global `established` field remains false because no group is established across every collected profile or arbitrary operational time.

## Partial results and observed events

The library proves generic first-match/default-deny arguments, arbitrary finite path separators, layer-preservation contracts, boundary arguments and bounded deadline arithmetic. Concrete FORWARD certificates constrain accepted packets to directional tunnel-policy metadata. The full Linux forwarding/cryptographic refinement needed to lift those certificates to universal nested encryption remains unproved. A successful sample probe cannot fill that gap.

Five native profiles provide exact declared security-level and logical-network bindings, 148 directed Red-host probe outcomes, and observed Inner peer-level facts. Same classification words do not collapse dissemination controls or different logical Red networks. The four-level profiles include Top Secret, Secret US-only and Secret Coalition, plus a separate Unclassified domain. Native independent management contributes 28 TLS application attempts across 14 managed components. Optional management remains separately scoped.

The supplemental suite includes eight address-family combinations, five encryption/encapsulation pairings, routing and management experiments, three CA arrangements, HTTP CRL/OCSP status checks, and host/KVM administration trials. Manual-SA mechanism runs retain test-key and authentication limitations. Good/revoked HTTP status checks concern endpoint behavior; complete VPN revocation enforcement remains unproved. HTTP exception proofs bound two parsed default-deny bridge chains, while negative curl timeouts remain non-causal observations.

Certificate experiments bind public P-384 credentials, explicit SHA384 policy and selected SHA384 exchanges. A deliberately SHA256-signed authentication is rejected for its signature scheme, followed by restored useful SHA384 traffic. Responder capability advertisements remain distinct from effective per-peer policy. The objective IKE exchange and header capture provide finite post-quantum sequence/fragmentation contributions under pinned experimental implementation assumptions.

PSK MKA succeeds with matching test CAKs and fails with explicit ICV rejection for mismatched CAKs. Six reversed-role EAP experiments record successful mutual TLS authentication but no successful EAP-derived protected data probe. A runtime-error ping is preserved as an error. The pinned MKA source uses 6000 ms lifetime and 2000 ms hello constants, while its delay-protect expression requires hello at most 500 ms. A conditional theorem therefore refutes full RG-028 under explicit source/build/CP-flag correspondence. The required 2000 ms interval was not weakened. KEK-width and AES-wrap source observations do not prove cryptographic primitive correctness or approved KGS provenance.

The component inventory binds 145 devices and 33 FRR sidecars. Literal DNS servers and locked root password flags are checked. Known routing-daemon names are absent from recorded encryptor processes, including host-side namespace scans. The finite name dictionary does not prove semantic absence of every routing implementation. All 145 unavailable systemctl queries remain explicit. Vendor-default change history, automatic remote-boot disablement and optional lookup-objective applicability remain unresolved.

Historical and native redundancy traces each preserve 17 outcomes covering primary use, active sharing, tagged forwarding failure, manual standby selection and restoration. Automatic HA and physical power failure remain outside those traces. NTP samples explicitly record no clock adjustment; trusted independent-clock synchronization remains unproved.

## All-target and representative-case dispositions

The independent coverage review preserves {review['source_clauses_preserved']} source-clause records, all 76 target IDs and all 57 expanded cases from nine topology, seventeen configuration and one protocol records. Evidence's representative-case dispositions are 45 covered arrangements, 11 partial arrangements and one unavailable physical serial case. Those labels describe representative realization, not requirement compliance. `coverage-review.json` records which current evidence keys and group contributions relate to each case and preserves missing aspects.

All 19 construction requests have scoped supplied, partial or unavailable responses. Request closure does not prove the associated target. Remaining gaps include product approval, physical and software independence, personnel/organizational duties, external annexes, source interpretation, temporal duties, EAP-derived protected delivery, MKA delay protection, and unresolved encompassing formalization or implementation refinement. No failed attempt is labeled mathematical impossibility. Co-resident/shared-implementation lab components provide explicit counterevidence to physical/implementation-independence claims.

## Validation and trust

The completed validation is `{validated['validation']['path']}`. All {validated['validation']['commands']} commands passed, including Lean build, every registered theorem reference, semantic examples, axiom inspection and {validated['python_tests']} Python tests. `validated-source-manifest.json` hashes the checked source files. Mutation tests reject raw/normalized interface mismatches, unmodeled connectivity, wrong namespace/OVS associations, bypasses, broadened policy guards, mixed SAs, missing policies, inactive-interface violations, declaration hash mismatch and process misattribution. Source-port reply guards are distinct from destination-port guards.

Lean checks the mathematical statements about parsed finite data and generic models. Raw observation truth, collection completeness, parser fidelity, runtime/configuration correspondence and source-to-model interpretation remain explicit trust boundaries. Snapshot and event conclusions retain their collection intervals. Source labels and transport intent are declarations. Nested-history manifests are referenced without recursively duplicating earlier checkpoint trees.

The fresh development uses Lean 4 v4.34.1 and Mathlib commit d13f23b723b8a846827a245b89c10fc7d3f11612. Mathlib supplies relation closure/induction, finite sets and finite decision foundations. Network-specific definitions are newly constructed. No suitable additional CSLib component was needed for the implemented arguments, so no unused CSLib dependency was added. No legacy proof, repository history or old theorem report was accessed. No commits were made.

`EVOLUTION.md`, per-command logs and timestamped checkpoints preserve model changes and failures. Early revisions available only at coarser checkpoint granularity are labeled honestly. The historical shared-Outer bypass remains preserved beside repaired inline Gray-firewall snapshots. The rejected direct-Black-edge interpretation and corrected native Black/Gray declaration remain visible.
"""
output_path("CONSTRUCTION_REPORT.md").write_text(report)
reading="""# Construction reading order

1. Read `CONSTRUCTION_REPORT.md` for scoped group results, partial clauses, conditional arguments and finite observations.
2. Read `theorem_register.json` for all 76 original statements, source passages, alternatives, conditions, per-clause progress, establishment scopes and remaining work. Nine encompassing propositions are encoded; 67 remain unencoded as whole targets.
3. Read `coverage-review.json` for all 57 representative-case dispositions and their current evidence associations. Read `evidence_requests.json` for the 19 scoped outcomes and rejected evidence.
4. Read `architecture.md` and `EVOLUTION.md`, then inspect `TDN/Targets`, `TDN/Semantics` and generated `TDN/Evidence` modules.
5. Inspect each claim's import report and manifest/observation dependencies, followed by the completed validation JSON and `validated-source-manifest.json`.

## Reproduction

Run from the chosen project root with Python 3 and the pinned Lean toolchain:

```sh
python3 scripts/construction/run_validation.py \
  --input-manifest artifacts/construction/RUN/source_paths.json \
  --output-dir artifacts/construction/RUN/integration \
  --history-dir artifacts/construction/RUN/integration/history \
  --recorder scripts/construction/record.py \
  --label integration-validation
```

Replace RUN with the run directory. Seed the output directory with the delivered `theorem_register.json` and `evidence_requests.json`. The runner regenerates imported modules, checks Lean, checks every claimed theorem reference, runs mutation tests and audits all 76 targets and 57 cases. Successful completion finalizes validation references and writes the source-hash manifest. Every command has an exact pre-validation checkpoint. Nested histories remain preserved in place and are referenced by their manifest hashes.

The input manifest uses project-relative paths. Declaration hashes include original transport intent, historical domain v2 and native identity/transport v2. Optional collection mappings support individually timestamped utility, historical utility, routing_v2 and routing_v4 bundles. No symlinks or absolute user paths are required. `TDN_INPUT_MANIFEST` and `TDN_OUTPUT_DIR` carry the chosen paths to children and tests. Workspace defaults remain inputs/source_paths.json, outputs and history.

The current native keys are native_baseline, native_same_level, native_shared, native_redundant, native_management, native_process_inventory, native_redundancy_events and native_declaration. Additional new keys are mka_audit and case_coverage. The old native_inventory key remains a retained input but supplies no current theorem claim. The full delivered manifest is authoritative.

## Assumptions and foundations

Read assumptions at the exact theorem scope. Native OVS/FRR correspondence supports conservative topology statements. It does not prove forwarding-program execution. Source labels and Public-Internet intent are declared, and physical/organizational authority is external. The full concrete layer/refinement obligation remains open. Optional management never gates management-free data-path results.

Lean is pinned to leanprover/lean4:v4.34.1. Mathlib is pinned to d13f23b723b8a846827a245b89c10fc7d3f11612 with transitive dependencies in lake-manifest.json. The library reuses Mathlib reflexive-transitive closure and induction, finite sets, list reasoning, finite types and decision procedures. CSLib supplied no needed compatible component for the implemented network-specific arguments; the development avoids an unused dependency and makes no exhaustive claim about CSLib's available results.
"""
output_path("READING_ORDER.md").write_text(reading)
print(json.dumps({"report":str(output_path("CONSTRUCTION_REPORT.md")),"reading_order":str(output_path("READING_ORDER.md"))}))
