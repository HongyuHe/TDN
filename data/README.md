# Retained TDN data

Git keeps source-linked requirements and selected network observations needed to inspect or reproduce TDN results. Routine agent activity and temporary outputs stay local.

- `extraction/` contains the source document, extracted requirements, example figures, role ontology, and source-validation records. Browser screenshots and editing history are excluded.
- `evidence/` contains the JSON values used by Lean imports and direct record checks. The manifest preserves the hashes of the migration inputs.
- `snapshots/2026-10-24T014455Z/` contains observations from the selected construction campaign. Raw output, collector source, and manifests stay together so their hashes can be checked. A captured service log can be evidence; ordinary build logs and image archives are excluded.
- `construction/2026-10-24T014455Z/` retains selected interpretations, source mappings, derived evidence records, and completion assessments. Agent workspaces, checkpoints, event streams, work queues, and intermediate status outputs stay local.

The active requirement decisions live in `specs/proof_scope.json`. Historical construction assessments describe their recorded revisions. The complete historical importer suite also uses local archived inputs that are outside the core checkout.

The BIRD capture used by the MCP import test is documented in `mcp/artifacts/README.md`. Other MCP captures remain ignored until a proof, test, or reproducibility task needs them.

Add new evidence deliberately with its consumer and provenance. The ignore rules keep new construction outputs local by default; explicitly stage a required input after checking its contents. Do not commit credentials, private keys, runtime environments, or downloaded image archives.
