#!/usr/bin/env python3
"""Summarize current extraction results and distinguish review scope from proof."""
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction'


def read(name):
    return json.loads((OUT / name).read_text())


def main():
    req = read('requirements/groups.json')
    mechanical = read('validation/artifact_validation.json')
    source = read('validation/source_validation.json')
    networks = read('networks/examples.json')
    ontology = read('roles/ontology.json')
    binding = mechanical.get('review_binding', {})
    review_dir = binding.get('review_directory', 'validation/review')
    review_path = OUT / review_dir / 'review.json'
    review = json.loads(review_path.read_text()) if review_path.is_file() else {}
    affected = sorted({g for issue in req['open_issues'] for g in issue['group_ids']})
    mappings = [m for e in networks for m in e.get('requirement_group_mappings', [])]
    mapping_counts = dict(sorted(Counter(m['status'] for m in mappings).items()))
    kind_counts = Counter(e['kind'] for e in networks)
    counts = mechanical['counts']
    source_counts = source['source_counts']
    current = bool(review) and binding.get('status') == 'current'
    amendments = binding.get('post_review_semantic_amendments', [])
    status = {
        'status': ('reviewed_baseline_with_coordinator_amendments' if amendments else 'reviewed_with_unresolved_source_interpretations') if current else 'awaiting_current_independent_review',
        'mechanical_source_validation': source['status'],
        'mechanical_cross_artifact_validation': mechanical['status'],
        'independent_review': review,
        'post_review_semantic_amendments': amendments,
        'independent_review_covers_current_semantics': current and not amendments,
        'ready_for_downstream_formalization': False,
        'reason': f"{len(req['open_issues'])} source interpretation or external-scope issues affect {len(affected)} groups. Legal formalization has a separate group-specific review scope. No Lean model or proof has been constructed by preprocessing.",
        'open_source_issues': req['open_issues'],
        'affected_group_ids': affected,
        'domain_review_scope': req.get('domain_review_scope', []),
        'evidence_scope_notes': req.get('evidence_scope_notes', []),
        'resolved_interpretations': req.get('resolved_interpretations', []),
        'counts': counts,
        'sentence_count': source_counts['sentence'],
        'logical_table_row_count': source_counts['table_row'],
        'figure_label_count': source_counts['figure_label'],
        'scoped_requirement_mappings': len(mappings),
        'mapping_status_counts': mapping_counts,
        'example_kind_counts': dict(kind_counts),
        'role_ontology_counts': ontology['counts'],
        'review_binding': binding,
    }
    (OUT / 'validation/final_status.json').write_text(json.dumps(status, ensure_ascii=False, indent=2) + '\n')
    rows = [
        ('Shared source units', counts['source_units'], '[Source policy](source/extraction_policy.md)'),
        ('Literal-period prose sentences', source_counts['sentence'], '[Sentences](exhaustive/sentences.md)'),
        ('Logical table rows', source_counts['table_row'], '[Contextualized rows](exhaustive/table_rows.md)'),
        ('Other source units', counts['source_units'] - source_counts['sentence'] - source_counts['table_row'], '[Other units](exhaustive/other_units.md)'),
        ('Requirement groups and top-level theorem targets', counts['requirement_groups'], '[Requirement groups](requirements/requirement_groups.md)'),
        ('Background source units', counts['background_units'], '[Background group](requirements/background.md)'),
        ('Extracted figure captions', len(read('networks/figure_captions.json')), '[Captions and source references](networks/figure_captions.json)'),
        ('Example network topologies', kind_counts['topology'], '[Networks](networks/networks.md)'),
        ('Partial configurations and alternatives', kind_counts['textual_configuration'], '[Configurations](networks/configurations.md)'),
        ('Protocol exchanges', kind_counts['protocol_exchange'], '[Protocol exchanges](networks/protocol_exchanges.md)'),
        ('Scoped example-to-group assessments', len(mappings), '[Requirement mappings](networks/network_requirement_links.md)'),
        ('Device and protocol endpoint roles', counts['roles'], '[Roles](roles/roles.md)'),
        ('Indexed role mentions', counts['role_mentions'], '[Structured mentions](roles/mentions.jsonl)'),
        ('Source-backed role subtype relationships', ontology['counts']['source_backed_subclass_edges'], '[Interactive hierarchy](roles/ontology.html)'),
        ('Other documented role relationships', ontology['counts']['annotation_associations'], '[Ontology guide and OWL exports](roles/ontology.md)'),
    ]
    lines = [
        '# CSfC MSC 1.3.0 specification extraction', '',
        'The package contains the preserved source, requirement groups, example networks, and device roles. Mechanical checks and independent semantic review have separate results in [current status](validation/final_status.json).', '',
        status['reason'], '',
        '## Results', '',
        '| Artifact | Count | Readable entry point |', '| --- | ---: | --- |',
    ]
    lines += [f'| {label} | {number:,} | {link} |' for label, number, link in rows]
    lines += [
        '', 'Each requirement group has one proposed top-level Lean theorem. The background group has none. The theorem statements are interpretations for later formalization; preprocessing constructs no proofs.', '',
        'The role ontology preserves all extracted roles, multiple parents, supporting passages, and qualifications. Its OWL subclass links express broader and specialized roles. Other documented relationships remain annotations. Topic filters organize the view without adding class claims. The [interactive explorer](roles/ontology.html) works offline and starts in the project’s light theme.', '',
        'Network topologies, partial configurations, and protocol exchanges have separate overview documents. Their stable IDs and shared requirement-assessment report preserve cross-references. All ten figure crops retain their captions and legends. Each assessment names a selected requirement clause, its applicability, source presentation, and supporting quotations. Whole-solution implementation compliance remains outside the extraction.', '',
        '| Assessment status | Count |', '| --- | ---: |',
    ]
    lines += [f'| {label.replace("_", " ")} | {number} |' for label, number in mapping_counts.items()]
    if amendments:
        lines += ['', 'The [text-precedence update record](' + binding['relocation_receipt'] + ') records the user-directed correction to two firewall assessments. Explicit text supplies details omitted from schematic figures. The coordinator checked the corrected source references and regenerated the reports. Original independent reviews are preserved; the amended judgments have not received another independent review.', '']
    elif binding.get('relocation_receipt') in {'validation/network_presentation_update.json', 'validation/ontology_layout_update.json'}:
        lines += ['', 'The [presentation update record](' + binding['relocation_receipt'] + ') records the report presentation, ontology layout, caption export, and earlier script relocation changes. Source interpretations and assessment decisions remain unchanged. Original independent review records are preserved; the presentation changes received coordinator validation.', '']
    elif binding.get('relocation_receipt'):
        lines += ['', 'The preprocessing scripts now live under `scripts/preprocess/`. The [relocation record](' + binding['relocation_receipt'] + ') preserves the original review manifest and records reversible path updates. The move changes file locations and invocation paths; it adds no new independent semantic review.', '']
    lines += [
        '', '## Validation and review', '',
        '- [Source validation](validation/source_validation.md) checks searchable PDF characters, source spans, literal-period boundaries, contextual table rows, and exact exported JSONL records. It also checks readable source views against the index.',
        '- [Cross-artifact validation](validation/artifact_validation.md) checks assignments, exact quotations, role instances, relative figure links, and scoped requirement assessments.',
        '- [Extraction plan audit](validation/plan_audit/independent_review.md) records the preceding independent review. [Findings](validation/plan_audit/independent_findings.json) distinguish actual extraction defects from missing validation guards and source-scope limits.',
        '- [Ontology validation](validation/ontology_validation.json) checks role coverage, evidence references, acyclic subtype links, serialization, and reproducible outputs. [Ontology review](validation/ontology_review/independent_review.md) records the independent source and implementation review.',
        '- [Historical review](validation/review/review.md) preserves the previous review and its scope. Its earlier no-defect conclusion does not override the new findings.',
        f'- [Active review hashes]({review_dir}/reviewed_artifact_hashes.json) bind the reviewed content. Changed bytes or missing bindings fail final validation.',
        '- [Structural correction ledger](source/structural_corrections.json) records the repaired RFC 4303 publication date and the retired source ID. Surviving source IDs remain stable.',
        '- [Replay log](coordination/replay_run.json) records executed commands and regression-test results.', '',
        'Searchable text and image labels retain separate evidence. The figure labels were transcribed from inspected crops, with raw OCR preserved for comparison. Their boxes identify figure regions rather than exact word locations.', '',
        '## Remaining source questions', '',
        '| Issue | Affected groups | Question |', '| --- | --- | --- |',
    ]
    for issue in req['open_issues']:
        lines.append('| ' + issue['issue_id'] + ' | ' + ', '.join(issue['group_ids']) + ' | ' + issue['title'].replace('|', '\\|') + ' |')
    for key, title in [('domain_review_scope', 'Domain-specific review'), ('evidence_scope_notes', 'Acknowledged evidence limits'), ('resolved_interpretations', 'Resolved interpretations')]:
        lines += ['', '## ' + title, '']
        for note in req.get(key, []):
            lines.append('- ' + note['issue_id'] + ' (' + ', '.join(note['group_ids']) + '): ' + note.get('resolution', note['detail']))
    lines += [
        '', '## Reproduce the saved extraction', '',
        'Run commands from the repository root. The replay uses the retained, hash-checked PDF under `artifacts/extraction/source/`. The separate copy under `docs/` is optional.', '',
        'For regeneration, use Python with `pdfplumber==0.11.9` and `Pillow==12.3.0`. Final checks use Python standard-library modules and Perl. The optional `--render` path also requires Poppler and Tesseract; the saved renders and crops are already included.', '',
        '```bash', 'python3 scripts/preprocess/run_csfc_preprocessing.py --stage ontology', 'python3 scripts/preprocess/run_csfc_preprocessing.py --stage check', 'python3 scripts/preprocess/run_csfc_preprocessing.py --stage all', '```', '',
        'The ontology stage regenerates the hierarchy, OWL RDF/XML, Turtle, Markdown, and standalone HTML from the current roles and reviewed [relationship decisions](roles/ontology_decisions.json). The check stage verifies those outputs and the full review binding. For optional independent RDF parsing, install `scripts/preprocess/requirements-csfc-ontology.txt` in a virtual environment and run `python3 scripts/preprocess/preprocess_csfc_ontology.py --check --rdf-check`.', '',
        'The CLI replays saved AI-authored decisions for the pinned document. Fresh documents require a new source analysis and review. The producer scripts, decision records, validators, and tests preserve the original extraction workflow.', '',
        'The source and derived stages support intermediate corrections. Final checks require current independent-review hashes. Regenerating images with different bytes invalidates the old crop review binding.', '',
        'Portable file references are relative to their documented base. Markdown links are relative to the containing Markdown file; crop-manifest paths are relative to the repository root; retained-PDF and review-hash paths are relative to the extraction directory. Historical command logs preserve the absolute paths used during those runs.', '',
        '[Agent task records](coordination/agent_tasks.json) preserve the original workflow. [Current audit interactions](validation/plan_audit/interactions.json) record the correction and review exchange.', '',
    ]
    (OUT / 'README.md').write_text('\n'.join(lines))
    print(json.dumps({'status': status['status'], 'open_source_issues': len(req['open_issues']), 'affected_groups': len(affected), 'scoped_mappings': len(mappings)}))


if __name__ == '__main__':
    main()
