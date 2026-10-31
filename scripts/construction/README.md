# Construction workflow scripts

This directory contains the active tools for theory construction, evidence provision and workflow coordination. Run the commands from the TDN repository root. The [workflow](../../workflows/construction.md) defines the agents' responsibilities and stopping conditions.

| Location | Purpose |
| --- | --- |
| `import_*.py`, `analyze_topology.py`, `audit_gray_paths.py`, `bind_domains.py` | Validate observations and generate Lean evidence modules |
| `validate_evidence.py`, `native_runtime.py`, `loaded_policy.py`, `source_paths.py` | Shared evidence parsing and path resolution |
| `initialize_register.py`, `update_register.py`, `refresh_contributions.py`, `reconcile_dependencies.py` | Maintain requirement targets, contributions and dependencies |
| `run_validation.py`, `check_register_claims.py`, `review_coverage.py`, `finalize_validation.py`, `write_reports.py` | Run the proof checks and produce scoped reports |
| `record.py`, `sync_agents.py`, `promote_snapshots.py`, `check_run.py`, `summarize_run.py` | Preserve checkpoints, exchange evidence and track the run |
| [evidence/](evidence/README.md) | Build images, generate profiles, deploy emulations, collect snapshots and run protocol experiments |

The shared `record.py` preserves nested history through manifest references. Both the validation runner and coordinator use that implementation.

## Validate the theory

Use the input manifest for the desired run. A new output directory needs the run's `theorem_register.json` and `evidence_requests.json`; those files carry the source interpretations and request decisions that the validation runner updates.

```sh
python3 scripts/construction/run_validation.py \
  --input-manifest artifacts/construction/2026-10-17T205010Z/source_paths.json \
  --output-dir artifacts/construction/2026-10-17T205010Z/integration \
  --history-dir artifacts/construction/2026-10-17T205010Z/integration/history \
  --recorder scripts/construction/record.py \
  --label local-validation
```

The runner invokes the tools in their new locations, regenerates Lean evidence and runs the existing checks. `TDN_INPUT_MANIFEST` and `TDN_OUTPUT_DIR` select the same inputs and outputs for direct tool calls and tests.

## Preserve historical evidence

The snapshots and source checkpoints under `artifacts/` retain their original paths, content and hashes. References inside those historical records describe the commands that actually ran. Current commands use this directory. The [relocation record](../../artifacts/construction/script-organization/relocation.json) maps the previous locations to the active tools.

Specification preprocessing remains in `scripts/preprocess`. Prior-work property extraction remains in `scripts/extract_prior_work_properties.py`.
