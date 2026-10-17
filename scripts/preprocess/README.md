# Specification preprocessing

This directory contains the CSfC preprocessing pipeline, its validators, and the role-ontology template. Generated artifacts live under `artifacts/extraction/`.

Run commands from the repository root:

```bash
python3 scripts/preprocess/run_csfc_preprocessing.py --stage all
python3 scripts/preprocess/run_csfc_preprocessing.py --stage ontology
python3 scripts/preprocess/run_csfc_preprocessing.py --stage check
```

The `all` stage rebuilds the saved extraction and validates it. The `ontology` stage rebuilds only the role hierarchy and its exports. The `check` stage validates the saved artifacts and review bindings.

Network extraction includes illustrated topologies, a protocol exchange, and text-only partial configurations. The curated `textual_specs` entries select prose blocks or table rows; `textual_structure` records their stated devices, relationships, and alternatives. Explicit text supplies details omitted from figures. Genuine conflicts between textual statements remain unresolved. The mapping decisions record the user-directed assessment corrections and distinguish them from the original independent review.

The readable outputs separate [network topologies](../../artifacts/extraction/networks/networks.md), [partial configurations and alternatives](../../artifacts/extraction/networks/configurations.md), and [protocol exchanges](../../artifacts/extraction/networks/protocol_exchanges.md). The structured `examples.json` retains all records with an explicit `kind` for downstream consumers. The validator checks that each record appears only in its matching overview.

The [extraction guide](../../artifacts/extraction/README.md) lists dependencies and explains the review scope. The [relocation record](../../artifacts/extraction/validation/preprocess_relocation.json) records the move from `scripts/` and preserves the original review evidence.
