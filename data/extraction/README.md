# CSfC MSC 1.3.0 specification extraction

The package contains the preserved source, requirement groups, example networks, and device roles. Mechanical checks and independent semantic review have separate results in [current status](validation/final_status.json).

11 source interpretation or external-scope issues affect 14 groups. Legal formalization has a separate group-specific review scope. No Lean model or proof has been constructed by preprocessing.

## Results

| Artifact | Count | Readable entry point |
| --- | ---: | --- |
| Shared source units | 1,596 | [Source policy](source/extraction_policy.md) |
| Literal-period prose sentences | 688 | [Sentences](exhaustive/sentences.md) |
| Logical table rows | 407 | [Contextualized rows](exhaustive/table_rows.md) |
| Other source units | 501 | [Other units](exhaustive/other_units.md) |
| Requirement groups and top-level theorem targets | 76 | [Requirement groups](requirements/requirement_groups.md) |
| Background source units | 647 | [Background group](requirements/background.md) |
| Extracted figure captions | 10 | [Captions and source references](networks/figure_captions.json) |
| Example network topologies | 9 | [Networks](networks/networks.md) |
| Partial configurations and alternatives | 17 | [Configurations](networks/configurations.md) |
| Protocol exchanges | 1 | [Protocol exchanges](networks/protocol_exchanges.md) |
| Scoped example-to-group assessments | 92 | [Requirement mappings](networks/network_requirement_links.md) |
| Device and protocol endpoint roles | 76 | [Roles](roles/roles.md) |
| Indexed role mentions | 1,328 | [Structured mentions](roles/mentions.jsonl) |
| Source-backed role subtype relationships | 40 | [Interactive hierarchy](roles/ontology.html) |
| Other documented role relationships | 31 | [Ontology guide and OWL exports](roles/ontology.md) |

Each requirement group has one proposed top-level Lean theorem. The background group has none. The theorem statements are interpretations for later formalization; preprocessing constructs no proofs.

The role ontology preserves all extracted roles, multiple parents, supporting passages, and qualifications. Its OWL subclass links express broader and specialized roles. Other documented relationships remain annotations. Topic filters organize the view without adding class claims. The [interactive explorer](roles/ontology.html) works offline and starts in the project’s light theme.

Network topologies, partial configurations, and protocol exchanges have separate overview documents. Their stable IDs and shared requirement-assessment report preserve cross-references. All ten figure crops retain their captions and legends. Each assessment names a selected requirement clause, its applicability, source presentation, and supporting quotations. Whole-solution implementation compliance remains outside the extraction.

| Assessment status | Count |
| --- | ---: |
| ambiguous | 6 |
| not applicable | 3 |
| presented as satisfying | 42 |
| required but not demonstrated | 41 |

The [text-precedence update record](validation/network_source_precedence_update.json) records the user-directed correction to two firewall assessments. Explicit text supplies details omitted from schematic figures. The coordinator checked the corrected source references and regenerated the reports. Original independent reviews are preserved; the amended judgments have not received another independent review.


## Validation and review

- [Source validation](validation/source_validation.md) checks searchable PDF characters, source spans, literal-period boundaries, contextual table rows, and exact exported JSONL records. It also checks readable source views against the index.
- [Cross-artifact validation](validation/artifact_validation.md) checks assignments, exact quotations, role instances, relative figure links, and scoped requirement assessments.
- [Extraction plan audit](validation/plan_audit/independent_review.md) records the preceding independent review. [Findings](validation/plan_audit/independent_findings.json) distinguish actual extraction defects from missing validation guards and source-scope limits.
- [Ontology validation](validation/ontology_validation.json) checks role coverage, evidence references, acyclic subtype links, serialization, and reproducible outputs. [Ontology review](validation/ontology_review/independent_review.md) records the independent source and implementation review.
- [Historical review](validation/review/review.md) preserves the previous review and its scope. Its earlier no-defect conclusion does not override the new findings.
- [Active review hashes](validation/ontology_review/reviewed_artifact_hashes.json) bind the reviewed content. Changed bytes or missing bindings fail final validation.
- [Structural correction ledger](source/structural_corrections.json) records the repaired RFC 4303 publication date and the retired source ID. Surviving source IDs remain stable.
- [Replay log](coordination/replay_run.json) records executed commands and regression-test results.

Searchable text and image labels retain separate evidence. The figure labels were transcribed from inspected crops, with raw OCR preserved for comparison. Their boxes identify figure regions rather than exact word locations.

## Remaining source questions

| Issue | Affected groups | Question |
| --- | --- | --- |
| REQ-I01 | RG-015 | Standalone encapsulator boundary and requirement strength conflict |
| REQ-I02 | RG-014, RG-039, RG-040 | Same-level filtering sentence conflicts with the permitted peers |
| REQ-I03 | RG-046, RG-011 | Management encryption and local exceptions |
| REQ-I04 | RG-032 | TRANSEC requirement strength and applicability differ |
| REQ-I05 | RG-061 | New-version compliance deadline conflict |
| REQ-I08 | RG-024 | AS connection scope wording |
| REQ-I09 | RG-039, RG-040 | Gray address-only restrictions and explicit non-tunnel exceptions |
| REQ-I10 | RG-038 | Objective table row has no Alternative marker |
| REQ-I11 | RG-048 | MACsec provisioning paragraph uses VPN terminology |
| REQ-I12 | RG-007, RG-011, RG-075 | External annex dependencies are not supplied |
| REQ-I15 | RG-024, RG-027 | EAP-TLS CAK derivation and blanket KGS generation wording |

## Domain-specific review

- REQ-I13 (RG-076): The legal undertaking is retained as a non-network obligation. Its formal applicability and any legal meaning need dedicated review; the extraction makes no enforceability claim.

## Acknowledged evidence limits

- REQ-I14 (RG-007, RG-074, RG-019): Figures and protocol examples support source-grounded, clause-specific requirement assessments. Implementation tests and theorem proofs require later evidence and models. That ordinary evidence boundary does not prevent extracting the requirements illustrated by an example.

## Resolved interpretations

- REQ-I06 (RG-045): Separate service VMs must also respect the AW host restriction. Distinct VMs do not authorize provisioning, enrollment, registration, or SIEM VMs on an AW-dedicated host.
- REQ-I07 (RG-044): The minimum logical separation required by DM-25 does not waive the physical and cryptographic separation in §4.1.4. The conditions can be imposed together.

## Reproduce the saved extraction

Run commands from the repository root. The replay uses the retained, hash-checked PDF under `artifacts/extraction/source/`. The separate copy under `docs/` is optional.

For regeneration, use Python with `pdfplumber==0.11.9` and `Pillow==12.3.0`. Final checks use Python standard-library modules and Perl. The optional `--render` path also requires Poppler and Tesseract; the saved renders and crops are already included.

```bash
python3 scripts/preprocess/run_csfc_preprocessing.py --stage ontology
python3 scripts/preprocess/run_csfc_preprocessing.py --stage check
python3 scripts/preprocess/run_csfc_preprocessing.py --stage all
```

The ontology stage regenerates the hierarchy, OWL RDF/XML, Turtle, Markdown, and standalone HTML from the current roles and reviewed [relationship decisions](roles/ontology_decisions.json). The check stage verifies those outputs and the full review binding. For optional independent RDF parsing, install `scripts/preprocess/requirements-csfc-ontology.txt` in a virtual environment and run `python3 scripts/preprocess/preprocess_csfc_ontology.py --check --rdf-check`.

The CLI replays saved AI-authored decisions for the pinned document. Fresh documents require a new source analysis and review. The producer scripts, decision records, validators, and tests preserve the original extraction workflow.

The source and derived stages support intermediate corrections. Final checks require current independent-review hashes. Regenerating images with different bytes invalidates the old crop review binding.

Portable file references are relative to their documented base. Markdown links are relative to the containing Markdown file; crop-manifest paths are relative to the repository root; retained-PDF and review-hash paths are relative to the extraction directory. Historical command logs preserve the absolute paths used during those runs.

[Agent task records](coordination/agent_tasks.json) preserve the original workflow. [Current audit interactions](validation/plan_audit/interactions.json) record the correction and review exchange.
