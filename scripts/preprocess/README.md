# Specification preprocessing

This directory contains the CSfC preprocessing pipeline, its validators, and the role-ontology template. Generated artifacts live under `data/extraction/`.

Run commands from the repository root:

```bash
python3 scripts/preprocess/run_csfc_preprocessing.py --stage all
python3 scripts/preprocess/run_csfc_preprocessing.py --stage ontology
python3 scripts/preprocess/run_csfc_preprocessing.py --stage check
```

The `all` stage rebuilds the saved extraction and validates it. The `ontology` stage rebuilds only the role hierarchy and its exports. The `check` stage validates the saved artifacts and review bindings.

The role ontology includes a curated mapping to the v3.1 Lean model in `data/extraction/roles/ontology_theory.json`. Every extracted role records an explicit representation, a combination of fields, a related model, or the absence of a distinct representation. The file also retains selected interpretation records and current code references. These mappings are exported as OWL annotations and leave the source-document subtype hierarchy intact. The visualization provides a representation filter and VS Code links.

The ontology generator checks the pinned Lean source hashes and resolves each reference to its current line. A changed Lean source requires reviewing the affected mappings and updating their hashes before regeneration. Selected interpretation text is retained in the mapping file so generation does not depend on historical construction-run directories. The historical decision paths remain available as provenance links.

Network extraction includes illustrated topologies, a protocol exchange, and text-only partial configurations. The curated `textual_specs` entries select prose blocks or table rows; `textual_structure` records their stated devices, relationships, and alternatives. Explicit text supplies details omitted from figures. Genuine conflicts between textual statements remain unresolved. The mapping decisions record the user-directed assessment corrections and distinguish them from the original independent review.

The readable outputs separate [network topologies](../../data/extraction/networks/networks.md), [partial configurations and alternatives](../../data/extraction/networks/configurations.md), and [protocol exchanges](../../data/extraction/networks/protocol_exchanges.md). The structured `examples.json` retains all records with an explicit `kind` for downstream consumers. The validator checks that each record appears only in its matching overview.

The [extraction guide](../../data/extraction/README.md) lists dependencies and explains the review scope. The [relocation record](../../data/extraction/validation/preprocess_relocation.json) records the move from `scripts/` and preserves the original review evidence.
