# Developer guide

The [project overview](../README.md) describes TDN's motivation and approach. This guide covers the code organization and validation commands.

## Repository structure

| Location | Purpose |
| --- | --- |
| [TDN/Models](../TDN/Models/) | Reusable network models and proofs. The [library guide](library.md) explains their assumptions and declarations. |
| [TDN/Requirements](../TDN/Requirements/) | Formal requirements and general proofs of requirements or individual clauses. |
| [TDN/Deployments](../TDN/Deployments/) | Imported data, local checks, and applications of general theorems to concrete networks. |
| [Requirement groups](../specs/requirement_groups.md) | Extracted requirements with source quotations and interpretation notes. |
| [Formalization map](../specs/requirement_formalizations.md) | Links from requirement groups to their current Lean specifications. |
| [Scope assessment](../specs/proof_scope.json) | Decisions about formal proofs, direct checks, and external evidence. |
| [mcp](../mcp/) | Evidence server, vendor adapters, and parsers. See the [server guide](evidence_service.md). |
| [data/evidence](../data/evidence/) | JSON records imported by the Lean deployment modules. |
| [Preprocessing tools](../scripts/preprocess/README.md) | Specification extraction, validation, and device-role ontology generation. |
| [Construction tools](../scripts/construction/README.md) | Importers, proof validation, evidence collection, and iteration recording. |
| [data/extraction](../data/extraction/README.md) | Requirements, examples, and device roles linked to their source passages. |
| [Emulation profiles](../data/extraction/networks/profiles/README.md) | Network configurations, device mappings, and topology diagrams. |
| [data/snapshots](../data/snapshots/) | Timestamped observations and manifests. |
| [Publication records](../data/publication/v3.2/) | Retained review results, proof mappings, and interpretation decisions. |

The [Lean entry point](../TDN.lean) imports the active theory. The [construction workflow](../workflows/construction.md) describes how agents formalize requirements, obtain evidence, and review proofs.

## Build and validate

The project pins its Lean version in [lean-toolchain](../lean-toolchain) and its Mathlib and CSLib dependencies in [lake-manifest.json](../lake-manifest.json). Install [elan](https://lean-lang.org/install/manual/), then run from the repository root:

```sh
source "$HOME/.elan/env"
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/check_configuration_records.py
```

`lake build` checks the active library and deployment modules. The test runner also checks standalone Lean examples and regression tests, including deliberately unsafe cases and an axiom audit. The first build downloads the pinned dependencies and may take longer than subsequent builds.

The [construction tools guide](../scripts/construction/README.md) distinguishes current validation commands from historical generation recipes. Historical importers may require separately retained run inputs. The commands above validate the retained theory and configuration records in the current checkout.

## Collect and import evidence

The [evidence MCP server](evidence_service.md) collects configurations and runtime observations from configured workers and exports structured JSON. Lean imports those records with `load_network_records` and `load_network_snapshot`, then checks the network-specific conditions required by reusable proofs.

The [emulation guide](../scripts/construction/evidence/README.md) covers deployment and collection. New observations require new timestamped snapshots. Changes to a live network do not alter previously saved evidence.

## Update the public explorers

The [publication guide](../scripts/publication/README.md) describes how to regenerate, validate, and publish the theory hierarchy and role ontology. Keep their source templates, generated pages, public exports, and deployed versions synchronized.
