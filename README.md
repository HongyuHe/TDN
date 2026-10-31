# Theory-defined Networking (TDN)

Theory-defined Networking (TDN) explores **networks that carry and maintain their own correctness arguments**. Network requirements are spread across specifications, configurations, and changing runtime state. TDN connects those sources through formal models and reusable proofs, making network behavior easier to explain, debug, and trust.

**AI agents construct the models and proofs; Lean checks the proofs.** The research goal is to put difficult reasoning into proof construction and reuse. When a network changes, the existing proofs should identify which facts and assumptions need to be checked again. The [research proposal](https://www.notion.so/hongyuhe/Theory-defined-Networking-TDN-3d98ffe4d93e80eba19acafd29acb301) describes the broader motivation.

## Approach

TDN combines **top-down proof obligation discovery and construction with bottom-up evidence provisioning**. A proof obligation is a condition that must be established to prove a requirement. The process begins by extracting source sentences and table rows, grouping requirements, and identifying example networks, configuration choices, and device roles. Each extraction retains references to the original document.

The [construction workflow](workflows/construction.md) connects proof construction to an evidence MCP server:

- **The Construction Agent works top down.** It selects clauses that need general behavioral arguments, translates them into Lean specifications, and develops general theorems supported by smaller lemmas. Routine record comparisons use direct checks. Those conditions guide requests for evidence.
- **The evidence MCP server supplies observations.** The Construction Agent queries configurations and runtime state, requests supported collections, and exports JSON for Lean import commands. The coordinator handles Twinet deployment changes and experiments.

The two directions meet at **checked conditions that connect network evidence to general proofs**. For example, Lean can check every imported edge and establish that each edge avoiding a firewall preserves a label. A reusable induction proof extends that condition to paths of any finite length. Different snapshots supply different edges and checks while using the same general proof.

Proof construction and evidence provision refine one another. A failed proof can reveal an incorrect model, missing observations, or a deployment flaw. The Construction Agent first checks its own reasoning, then requests additional evidence or a justified network repair. The workflow records interpretation decisions, evidence requests, deployment changes, proof revisions, and remaining limitations.

## Current prototype

The current case study formalizes the CSfC Multi-Site Connectivity specification against Twinet emulations. The models cover topology, packet filtering and routing, IPsec and MACsec layers, authentication, generated replies, and fragmentation. The theory separates reusable networking arguments from CSfC requirements and concrete evidence checks.

The requirements catalog contains **76 groups**. The [scope assessment](specs/proof_scope.json) recommends general proofs for **24 groups** and direct checks for **29 current contributions**. The active Lean theory now follows that scope. The remaining **22 groups** need external assurance or unsupported capabilities; **one group** states an optional permission. These decisions concern the assessed clauses, and full CSfC compliance remains unproved.

The [scope guide](docs/theory_scope.md) explains the retained arguments, removed models, and validation commands. The earlier [construction record](data/construction/current.json) preserves its original 53-group partial-contribution count.

Each proof establishes a claim about its stated model and assumptions. Applying the claim to a deployment requires faithful collection, correct translation, and a justified connection between actual processing and the modeled operations. Continuous proof maintenance remains a research goal.

## Repository guide

| Location | Purpose |
| --- | --- |
| [TDN/Semantics](TDN/Semantics/) | Reusable network models and proofs. The [library guide](docs/semantics.md) explains every module, its assumptions, and its declarations. |
| [TDN/Targets](TDN/Targets/) | CSfC specifications and general proofs of requirements or individual clauses. |
| [TDN/Evidence](TDN/Evidence/) | Imported data, local checks, and applications of general theorems to concrete networks. |
| [specs/proof_scope.json](specs/proof_scope.json) | Current decisions for all 76 groups, with retained general results and snapshot applications. |
| [specs/requirement_groups.md](specs/requirement_groups.md) | Copy of the 76 extracted requirement groups, with source quotations and interpretation notes. |
| [mcp](mcp/) | Network evidence server, vendor adapters, and shared parsers. See the [server guide](docs/evidence_service.md). |
| [data/evidence](data/evidence/) | JSON records imported by the Lean evidence modules. |
| [scripts/preprocess](scripts/preprocess/README.md) | Specification extraction, validation, and device-role ontology generation. |
| [scripts/construction](scripts/construction/README.md) | Importers, proof validation, evidence collection, and iteration recording. |
| [data/extraction](data/extraction/README.md) | Source-linked requirements, examples, and device roles. |
| [data/snapshots](data/snapshots/) | Timestamped network observations and manifests. |
| [data/construction](data/construction/) | Versioned agent exchanges, proof attempts, interpretations, and assessments. |

The [Lean entry point](TDN.lean) imports the active theory. The earlier development remains under `archive/v1/`, outside the active build and the construction agents' permitted inputs.

## Build and validate

The project pins Lean 4.34.1 and compatible Mathlib and CSLib revisions. Install [elan](https://lean-lang.org/install/manual/), then run from the repository root:

```sh
source "$HOME/.elan/env"
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/check_configuration_records.py
```

`lake build` checks the active library and evidence modules. The test runner also checks the standalone Lean examples and regression tests, including deliberately unsafe cases and an axiom audit. The first build downloads the pinned dependencies and may take longer than subsequent builds.

The historical Python importer suite requires the original run inputs, including archived records kept outside the core checkout. When those inputs are available locally, select their recorded manifest:

```sh
export TDN_INPUT_MANIFEST=data/construction/2026-10-24T014455Z/source_paths_current.json
export TDN_OUTPUT_DIR=data/construction/2026-10-24T014455Z
python3 -m unittest discover -s tests -p 'test_*.py'
```

The [construction tools guide](scripts/construction/README.md) separates current validation commands from historical generation recipes. The [emulation guide](scripts/construction/evidence/README.md) covers deployment and collection. New observations require new timestamped snapshots; changes to a live network do not alter previously saved evidence.


Network evidence is available through a [local MCP server](docs/evidence_service.md). The server collects observations from configured workers and exports structured JSON. Lean imports those records with `tdn_data` and `tdn_snapshot`, then checks the network-specific conditions used by the reusable proofs.
