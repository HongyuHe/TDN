# Construction workflow scripts

The active construction workflow uses the [evidence MCP server](../../mcp/README.md) to collect and query network observations. Lean imports its exported JSON from `data/evidence/`. The [workflow](../../workflows/construction.md) defines proof construction, interpretation review, and validation.

| Location | Purpose |
| --- | --- |
| `start_v31.py`, `prepare_interpretation.py`, `export_spec_definitions.lean` | Prepare isolated Constructor and Interpreter workspaces and export compiled specifications. |
| `check_proof_submission.py`, `export_proof_audit.lean` | Check accepted specifications, general proofs, applications, and assumptions. |
| `record.py`, `record_attempt.py`, `record_agent_messages.py`, `checkpoint_proof_attempts.py` | Preserve proof attempts, source versions, feedback, and validation results. |
| `mcp_session.py` | Request evidence through the MCP server and retain responses. |
| [evidence/](evidence/README.md) | Build images, deploy profiles, collect observations, and run protocol experiments. |
| [Network profiles](../../data/extraction/networks/profiles/README.md) | Five supported MSC topologies, generator inputs, mappings, and diagrams. |
| `import_*.py` and related parsing helpers | Retained compatibility entry points and parsers used by regression tests and historical evidence reconstruction. |

## Run supervised construction

`start_v31.py` creates a new UTC-stamped run, preserves the current source checkpoint, and prepares a Constructor workspace under `/tmp`. The workspace contains the active theory, permitted source requirements, current campaign evidence, and pinned Lean dependencies. Repository history and the archived theory are excluded. The generated execution wrapper denies access to the original project and Codex directories. Agents must use that wrapper for filesystem commands; the tool service itself is not confined by the wrapper.

```sh
python3 scripts/construction/start_v31.py
```

The supervisor launches the independent Constructor with GPT-6.1 Sol at `xhigh`. After the Constructor compiles a complete 24-specification candidate, `prepare_interpretation.py` freezes its sources and uses `export_spec_definitions.lean` to export the actual compiled definitions. Each fresh GPT-6.1 Sol interpreter at `high` receives only those definitions and their dependencies. The supervisor retains the source-to-RG mapping outside the interpreter workspace.

```sh
python3 scripts/construction/prepare_interpretation.py \
  --run v3.3-TIMESTAMP \
  --workspace /tmp/tdn-v3.3-TIMESTAMP/constructor \
  --round 1
```

`mcp_session.py` calls the real evidence server through its stdio MCP interface. Run it with the MCP package environment and a trusted configuration. Its request file contains an array of tool calls or resource reads. Each response, including failures, is saved to a new JSONL file. A failed tool call produces a nonzero client exit code. A collection request can set `wait_complete` to keep the session open while recording status polls. Subsequent requests can refer to a named result through `$result.ID.field`.

```sh
uv run --frozen --project mcp python scripts/construction/mcp_session.py \
  --config inputs/evidence-mcp.json \
  --requests inputs/requests.json \
  --output outputs/mcp/session-001.jsonl
```

The November 4 continuation submits one complete RG at a time. The Constructor uses focused compiler feedback during development and postpones broad validation until the RG's general proof and applications are ready. Full clause coverage, kernel checks, meaningful assumptions, and reusable general proofs are required for PASS. Interpretation review resumes only when a specification's meaning changes. All new records stay under the new run directory.

`export_proof_audit.lean` reads a newline-separated list of fully qualified theorem names from `TDN_PROOF_NAMES`. After a successful build, it writes their compiled assumptions, conclusions, transitive TDN dependencies, and axioms to the path in `TDN_PROOF_AUDIT`. The command rejects missing names, definitions supplied as proofs, and axioms beyond Lean's three permitted foundational axioms. The supervisor still reviews whether the assumptions justify the source requirements and whether concrete observations establish them.

```sh
TDN_PROOF_NAMES=outputs/proof-names.txt \
TDN_PROOF_AUDIT=outputs/proof-audit.json \
lake env lean scripts/construction/export_proof_audit.lean
```

`export_spec_definitions.lean` records each specification's readable form and complete internal Lean expressions, including implicit arguments. Rebuild the accepted frozen source and the proof candidate with the same pinned dependencies before comparing those exports. `check_proof_submission.py` checks the 24-target mapping, the compiled general proofs, their evidence dependencies, and changes to the accepted definitions. The checker reports whether the accepted export contains the complete expressions. Older exports remain usable but compare only their recorded fields. The supervisor reviews clause coverage and assumptions separately.

For a completed individual RG, pass `--groups RG-039` to `check_proof_submission.py` and provide a proof map containing that RG. The accepted map still contains all 24 specifications. The default checks all 24 groups. Selecting one group changes the submission scope; it preserves the checks for specification changes, unexpected axioms and dependencies on concrete evidence.

When a completed RG changes a specification's meaning, `prepare_interpretation.py --groups RG-039` limits the blind Interpreter's targets to that group. The supervisor's export still records all 24 definitions for change tracking. Use `--import-module TDN.Requirements.MasterMscRequirementSpecs` to build the specification modules without rebuilding unrelated snapshot proofs. Additional `--import-module` arguments are supported when the specification map spans several modules. The default imports `TDN` and gives the Interpreter all 24 targets.

A frozen candidate can supply its existing compiled definitions through `--compiled-export FILE --compiled-export-sha256 HASH` while the independent validation build runs. The preparation script verifies the hash, preserves the supplied definitions and source hashes, and tests the Interpreter's access restrictions. It does not repeat the build. Acceptance still requires the independent build to export exactly the same definitions; the preparation manifest records that outstanding check.

The RG-033 packet-size application uses `packet_sizing_records.py` to combine saved native processing, public IPsec association records, packet-size observations, bridge processing and declared Red services. The output retains the raw inputs and their hashes. `packet_sizing_cases.py` selects concrete source, rejection and wire examples. `packet_sizing_continuation.py` extends a source example through the recorded route, filter, encryption and switching steps to an Outer Black interface. Both scripts produce JSON; Lean imports the records and checks the proposed steps.

```sh
python3 scripts/construction/packet_sizing_records.py \
  native.json keys-before.json keys-after.json sizing.json output.json \
  --bridge bridge.json --intent red-services.json
python3 scripts/construction/packet_sizing_cases.py output.json cases.json
python3 scripts/construction/packet_sizing_continuation.py output.json cases.json continuation.json
```

`migrate_local_projection.py` reproduces the recorded migration that adds device-local interfaces and namespace-owned addresses to older active JSON records. Preserve its before/after records when reproducing that migration. Source captures remain unchanged. New packet-size records obtain those fields directly from the current projection.

`checkpoint_proof_attempts.py` archives completed attempts with their logs and hash-checked source checkpoints. It excludes unfinished attempts and creates a new archive without replacing an earlier one. `record_agent_messages.py` preserves the actual agent prompts and replies for the selected run interval.

## Validate the active theory

```sh
lake build
python3 scripts/construction/run_lean_tests.py
python3 scripts/construction/check_configuration_records.py
lake env lean scripts/construction/audit_axioms.lean
```

The [scope guide](../../docs/theory_scope.md) and [76-group scope register](../../specs/proof_scope.json) describe the current theory. The direct-check command validates the migrated configuration and recorded-operation clauses without generating Lean code. Its JSON output includes the checked claims and input hashes.

## Historical tools and records

Superseded scripts that rewrote the v2/v3 status registers, fixed-date collection command sequences, intermediate topology generators, and replaced inventory collectors were removed from the active tree. The earlier generation recipes and source files remain available in Git at revision `1a49bb76`. Use that revision to reproduce an old workflow exactly.

The retained importers and shared parsing helpers still have proof, MCP, or regression-test consumers. Several historical importer tests require their original campaign inputs. Select the corresponding `TDN_INPUT_MANIFEST` and `TDN_OUTPUT_DIR` when running those tests. New evidence collection uses the MCP server.

Unique proof-review records and timestamped network snapshots retain their original paths and hashes. The completed script-relocation rehearsal and superseded untracked evidence values were archived outside the repository during the November 3 cleanup. Current proof inputs remain under `data/evidence/`.

The [publication tools](../publication/README.md) rebuild the hierarchy and ontology and validate their source links. Their current source mappings are under `data/publication/v3.3/`. The earlier review decisions remain available under `data/publication/v3.1/` and `data/publication/v3.2/`.
