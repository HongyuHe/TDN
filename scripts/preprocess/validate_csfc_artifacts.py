#!/usr/bin/env python3
"""Check all produced extraction artifacts without treating coverage as semantic review."""
import argparse
import hashlib
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads((OUT / path).read_text())


def relocated_review_bindings(bound, manifest_path):
    """Verify recorded changes against the original reviewed file bytes."""
    receipt_name = next((name for name in ['validation/network_source_precedence_update.json', 'validation/ontology_layout_update.json', 'validation/network_presentation_update.json', 'validation/preprocess_relocation.json'] if (OUT / name).is_file()), 'validation/preprocess_relocation.json')
    if not (OUT / receipt_name).is_file():
        return bound, {}, None
    receipt = load(receipt_name)
    if receipt['review_manifest_sha256'] != sha(manifest_path):
        raise ValueError('Preprocessing relocation refers to a different review manifest.')
    relocated, paths = dict(bound), {}
    for change in receipt['changes']:
        old, new = change['old_path'], change['new_path']
        if old not in bound or bound[old] != change['before_sha256']:
            raise ValueError('Relocation lacks the original reviewed hash: ' + old)
        current = (OUT / new).read_bytes()
        if hashlib.sha256(current).hexdigest() != change['after_sha256']:
            raise ValueError('Relocated artifact changed: ' + new)
        lines = current.decode().splitlines(keepends=True)
        #* Reverse the recorded edits to recover the exact independently reviewed bytes.
        for edit in reversed(change['edits']):
            start = edit['after_start']
            end = start + len(edit['after_lines'])
            if lines[start:end] != edit['after_lines']:
                raise ValueError('Relocation edit differs from current content: ' + new)
            lines[start:end] = edit['before_lines']
        if hashlib.sha256(''.join(lines).encode()).hexdigest() != bound[old]:
            raise ValueError('Relocation cannot recover the reviewed content: ' + old)
        relocated.pop(old)
        relocated[new] = change['after_sha256']
        paths[old] = new
    additions = receipt.get('added_artifacts', {})
    for path, digest in additions.items():
        if path in relocated or not (OUT / path).is_file() or sha(OUT / path) != digest:
            raise ValueError('Added artifact differs from its recorded hash: ' + path)
        relocated[path] = digest
    if len(relocated) != len(bound) + len(additions):
        raise ValueError('Relocation must preserve all review bindings.')
    return relocated, paths, receipt_name


def example_partition_errors(examples, overviews):
    errors = []
    for kind, overview in overviews.items():
        expected = [e['example_id'] for e in examples if e['kind'] == kind]
        actual = re.findall(r'^## (NET-\d{3}):', overview, re.MULTILINE)
        if actual != expected:
            errors.append('Missing, duplicated, or misplaced entries in ' + kind)
    if set(overviews) != {e['kind'] for e in examples}:
        errors.append('Presentation categories do not cover the extracted example kinds.')
    return errors


def network_view_errors(examples, overview, details, captions):
    errors = []
    if '### Requirement-group assessment' in overview or re.search(r'^#### NET-|^> |\*\*Reasoning:\*\*', overview, re.MULTILINE):
        errors.append('The network overview contains detailed assessments or quotations.')
    expected_ids = [m['mapping_id'] for e in examples for m in e['requirement_group_mappings']]
    if re.findall(r'^#### (NET-\d{3}-MAP-\d+):', details, re.MULTILINE) != expected_ids:
        errors.append('Detailed assessment blocks are missing or reordered.')
    by_figure = {c['figure_number']: c for c in captions}
    for example in examples:
        marker = '## ' + example['example_id'] + ': '
        if marker not in overview:
            errors.append('Missing network summary: ' + example['example_id'])
            continue
        block = overview.split(marker, 1)[1].split('\n## ', 1)[0]
        counts = ', '.join(f'{status}: {count}' for status, count in example['compliance']['status_counts'].items())
        if 'Requirement assessment: {' + counts + '}.' not in block:
            errors.append('Assessment counts differ: ' + example['example_id'])
        expected_captions = [by_figure[c['figure_number']] for c in example['figure_crops']]
        if example.get('figure_captions') != expected_captions:
            errors.append('Example caption records differ: ' + example['example_id'])
        for caption in expected_captions:
            if '**' + caption['text'] + '**' not in block:
                errors.append('Missing full caption: ' + str(caption['figure_number']))
        for mapping in example['requirement_group_mappings']:
            if mapping['clause_scope'].replace('|', '\\|') not in block:
                errors.append('Missing assessment table row: ' + mapping['mapping_id'])
            if 'network_requirement_links.md#' + mapping['mapping_id'].lower() not in block:
                errors.append('Missing assessment detail link: ' + mapping['mapping_id'])
            for field in ['clause_scope', 'rationale', 'applicability', 'qualifications_and_exceptions']:
                if mapping[field] not in details:
                    errors.append('Missing detail: ' + mapping['mapping_id'] + '/' + field)
        if any(p['text'] not in details for p in example['setup_passages']):
            errors.append('Missing setup quotation: ' + example['example_id'])
    return errors


def scoped_mapping_errors(examples, groups, index, decisions):
    errors, identifiers = [], []
    decision_map = {e['example_id']: e['mappings'] for e in decisions['examples']}
    if set(decision_map) != {e['example_id'] for e in examples}:
        errors.append('Mapping decisions do not cover exactly the extracted examples.')
    statuses = {'presented_as_satisfying', 'presented_as_violating', 'required_but_not_demonstrated', 'ambiguous', 'not_applicable'}
    bases = {'explicit_source_statement', 'interpreted_source_presentation', 'visual_interpretation'}
    for example in examples:
        mappings = example.get('requirement_group_mappings', [])
        selected = decision_map.get(example['example_id'], [])
        if not mappings or len(mappings) != len(selected):
            errors.append(example['example_id'] + ': missing or incomplete group mappings')
        for mapping, decision in zip(mappings, selected):
            mid = mapping.get('mapping_id', '')
            identifiers.append(mid)
            group = groups.get(mapping.get('group_id'))
            if not group:
                errors.append(mid + ': unknown requirement group')
                continue
            if any(mapping.get(key) != value for key, value in decision.items()):
                errors.append(mid + ': assessment differs from the recorded decision')
            if mapping.get('status') not in statuses or mapping.get('basis') not in bases or mapping.get('scope') != 'specific_clause':
                errors.append(mid + ': invalid status, evidence basis, or scope')
            for field in ['clause_scope', 'applicability', 'rationale', 'qualifications_and_exceptions']:
                if not isinstance(mapping.get(field), str) or not mapping[field].strip():
                    errors.append(mid + ': missing ' + field)
            clause_ids = mapping.get('clause_source_ids', [])
            evidence_ids = mapping.get('example_source_ids', [])
            if not clause_ids or not set(clause_ids) <= set(group['source_ids']):
                errors.append(mid + ': clauses are outside the selected group')
            if not evidence_ids or not set(evidence_ids) <= set(example['source_ids']):
                errors.append(mid + ': evidence is outside the selected example')
            expected_original = list(dict.fromkeys(index[sid]['requirement_id'] for sid in clause_ids if sid in index and index[sid].get('requirement_id')))
            if mapping.get('original_requirement_ids') != expected_original:
                errors.append(mid + ': numbered requirement projection differs')
            for id_field, passage_field in [('clause_source_ids', 'clause_passages'), ('example_source_ids', 'example_passages')]:
                expected = [{'source_id': sid, 'text': index[sid]['text']} for sid in mapping.get(id_field, []) if sid in index]
                if mapping.get(passage_field) != expected:
                    errors.append(mid + ': incomplete or altered ' + passage_field)
            expected_strength = {'interpretation': group['document_force']['interpretation'], 'table_rows': [r for r in group['document_force']['table_rows'] if r['source_id'] in clause_ids], 'semantics_source_ids': group['document_force']['semantics_source_ids']}
            if mapping.get('requirement_strength') != expected_strength:
                errors.append(mid + ': requirement strength differs from the selected group')
            if mapping.get('group_open_issue_ids') != group['open_issue_ids'] or mapping.get('group_qualifications_and_exceptions') != group['qualifications_and_exceptions']:
                errors.append(mid + ': group exceptions or unresolved issues differ')
            if mapping.get('group_scope_note_ids') != group.get('scope_note_ids', []):
                errors.append(mid + ': group scope notes differ')
        expected_rids = {rid for m in mappings for rid in m['original_requirement_ids']}
        links = example.get('requirement_links', [])
        if {link['requirement_id'] for link in links} != expected_rids:
            errors.append(example['example_id'] + ': numbered links do not cover the assessed clauses')
        for link in links:
            selected_mappings = [m for m in mappings if link['requirement_id'] in m['original_requirement_ids']]
            if link.get('mapping_ids') != [m['mapping_id'] for m in selected_mappings] or link.get('statuses') != list(dict.fromkeys(m['status'] for m in selected_mappings)):
                errors.append(example['example_id'] + ': numbered link loses assessment status or mapping identity')
        expected_counts = dict(Counter(m['status'] for m in mappings))
        if example.get('compliance', {}).get('status') != 'scoped_group_assessment' or example.get('compliance', {}).get('status_counts') != expected_counts:
            errors.append(example['example_id'] + ': stale compliance summary')
    if len(set(identifiers)) != len(identifiers) or '' in identifiers:
        errors.append('Mapping identifiers are missing or duplicated.')
    return errors


def validate(require_semantic_review=False):
    required = ['source/document.json','source/source_index.jsonl','source/corrections.json','exhaustive/sentences.jsonl','exhaustive/table_rows.jsonl','exhaustive/other_units.jsonl','requirements/groups.json','requirements/background.json','requirements/requirement_groups.md','networks/examples.json','networks/figure_register.json','networks/textual_example_register.json','networks/crop_manifest.json','roles/roles.json','roles/mentions.jsonl','roles/exclusions.json']
    required += ['networks/figure_captions.json', 'networks/networks.md', 'networks/configurations.md', 'networks/protocol_exchanges.md', 'networks/network_requirement_links.md']
    missing = [p for p in required if not (OUT / p).is_file()]
    if missing:
        raise FileNotFoundError('Required final artifacts are missing: ' + ', '.join(missing))
    units = [json.loads(l) for l in (OUT / 'source/source_index.jsonl').read_text().splitlines()]
    index = {u['source_id']: u for u in units}
    req = load('requirements/groups.json')
    bg = load('requirements/background.json')
    examples = load('networks/examples.json')
    roles = load('roles/roles.json')
    mentions = [json.loads(l) for l in (OUT / 'roles/mentions.jsonl').read_text().splitlines()]
    checks, errors = {}, []
    def check(name, okay, detail):
        checks[name] = {'passed': bool(okay), 'detail': detail}
        if not okay:
            errors.append(name)
    refs_bad, quotes_bad = [], []
    def walk(obj, path):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ['source_id','parent_figure_source_id'] and value is not None and value not in index:
                    refs_bad.append([path, key, value])
                if key.endswith('source_ids') and isinstance(value, list):
                    for sid in value:
                        if sid not in index:
                            refs_bad.append([path,key,sid])
                walk(value, path + '/' + key)
            if 'source_id' in obj and 'text' in obj and obj['source_id'] in index:
                if obj['text'] != index[obj['source_id']]['text']:
                    quotes_bad.append([path, obj['source_id']])
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                walk(value, path + '/' + str(i))
    for filename in ['requirements/groups.json','requirements/background.json','networks/examples.json','networks/figure_register.json','networks/textual_example_register.json','roles/roles.json','roles/exclusions.json','roles/unresolved.json','roles/instances.json']:
        walk(load(filename), filename)
    check('all_source_references_resolve', not refs_bad, refs_bad)
    check('all_indexed_quotations_match', not quotes_bad, quotes_bad)
    check('requirements_use_current_source_index', req['source_index_sha256'] == sha(OUT / 'source/source_index.jsonl') == bg['source_index_sha256'], req['source_index_sha256'])
    assigned = set(u['source_id'] for u in bg['source_units'])
    for g in req['groups']:
        assigned.update(g['source_ids'])
        assigned.update(g['context_source_ids'])
    check('every_source_assigned', assigned == set(index), {'source_units': len(index), 'assigned_units': len(assigned), 'unassigned': sorted(set(index) - assigned)})
    bad_targets = [g['group_id'] for g in req['groups'] if g.get('theorem_target_count') != 1 or not isinstance(g.get('theorem_name'), str) or not g.get('theorem_statement')]
    names = [g['theorem_name'] for g in req['groups']]
    check('one_unique_theorem_per_requirement_group', not bad_targets and len(names) == len(set(names)), {'groups': len(names), 'invalid_groups': bad_targets})
    check('background_has_no_theorem', bg.get('theorem_target_count') == 0 and bg.get('theorem_name') is None and bg.get('theorem_statement') is None, bg['group_id'])
    duplicate_groups = [g for g, count in Counter(g['group_id'] for g in req['groups']).items() if count != 1]
    check('requirement_group_ids_unique', not duplicate_groups, duplicate_groups)
    check('original_requirement_map_export_matches_groups', load('requirements/original_requirement_map.json') == req['original_requirement_id_to_group_id'], 'The separate map must equal the map in groups.json.')
    gid = {g['group_id']: g for g in req['groups']}
    mapping_errors = scoped_mapping_errors(examples, gid, index, load('networks/mapping_decisions.json'))
    check('example_assessments_are_complete_scoped_and_source_grounded', not mapping_errors, mapping_errors)
    original_ids = {u['requirement_id'] for u in units if u.get('requirement_id')}
    check('all_original_requirement_ids_mapped', set(req['original_requirement_id_to_group_id']) == original_ids, {'original_requirement_ids': len(original_ids)})
    role_ids = {r['role_id'] for r in roles}
    bad_links = []
    for e in examples:
        node_ids = {d['device_id'] for d in e['devices']} | {n['network_id'] for n in e['networks']} | {a['aggregate_id'] for a in e.get('aggregates', [])}
        for d in e['devices']:
            if not set(d['role_ids']) <= role_ids:
                bad_links.append([e['example_id'],d['device_id'],'role'])
        for link in e['links']:
            if not set(link['endpoints']) <= node_ids:
                bad_links.append([e['example_id'],link['endpoints'],'endpoint'])
        for link in e['requirement_links']:
            expected = req['original_requirement_id_to_group_id'].get(link['requirement_id'])
            if link['group_ids'] != [expected] or expected not in gid and expected != bg['group_id']:
                bad_links.append([e['example_id'],link['requirement_id'],'group'])
    check('network_roles_endpoints_and_requirement_groups', not bad_links, bad_links)
    expected_instances = [dict(example_id=e['example_id'], **d) for e in examples for d in e['devices']]
    check('role_instance_export_matches_examples', load('roles/instances.json') == expected_instances, {'expected_instances': len(expected_instances)})
    mention_errors = []
    for m in mentions:
        if m['role_id'] not in role_ids or m['source_id'] not in index or index[m['source_id']]['text'][m['text_start']:m['text_end']] != m['source_wording']:
            mention_errors.append(m['mention_id'])
    check('role_mentions_have_exact_source_spans', not mention_errors, {'mentions': len(mentions), 'invalid': mention_errors})
    check('all_roles_have_evidence', all(r['source_ids'] for r in roles), {'roles': len(roles)})
    ontology_spec = importlib.util.spec_from_file_location('csfc_ontology_validation', ROOT / 'scripts/preprocess/preprocess_csfc_ontology.py')
    ontology_module = importlib.util.module_from_spec(ontology_spec)
    ontology_spec.loader.exec_module(ontology_module)
    ontology_graph, _, ontology_outputs = ontology_module.expected_outputs(OUT)
    stale_ontology = [name for name, expected in ontology_outputs.items() if not (OUT / 'roles' / name).is_file() or (OUT / 'roles' / name).read_text() != expected]
    check('role_ontology_matches_roles_evidence_and_curated_hierarchy', not stale_ontology, {'stale_outputs': stale_ontology, 'counts': ontology_graph['counts']})
    figures = load('networks/figure_register.json')
    crops = load('networks/crop_manifest.json')
    check('all_ten_figures_registered_once', sorted(f['figure_number'] for f in figures) == list(range(1,11)), {'figures': len(figures), 'topology_figures': 9, 'protocol_figures': 1})
    crop_errors = [c['figure_number'] for c in crops if not (ROOT / c['crop_path']).is_file() or c.get('review_status') != 'visually_inspected']
    check('all_crops_present_and_reviewed', not crop_errors, crop_errors)
    overviews = {kind: (OUT / 'networks' / name).read_text() for kind, name in [('topology', 'networks.md'), ('protocol_exchange', 'protocol_exchanges.md'), ('textual_configuration', 'configurations.md')]}
    partition_errors = example_partition_errors(examples, overviews)
    check('example_categories_are_separate_and_complete', not partition_errors, partition_errors)
    network_markdown = '\n'.join(overviews.values())
    image_refs = re.findall(r'!\[[^\]]*\]\(([^)]+)\)', network_markdown)
    expected_images = ['crops/figure-' + str(n).zfill(2) + '.png' for n in range(1, 11)]
    check('example_reports_have_all_relative_figure_links', image_refs == expected_images and all((OUT / 'networks' / p).is_file() for p in image_refs), image_refs)
    caption_spec = importlib.util.spec_from_file_location('csfc_network_views', ROOT / 'scripts/preprocess/reconcile_csfc_extraction.py')
    caption_module = importlib.util.module_from_spec(caption_spec)
    caption_spec.loader.exec_module(caption_module)
    spans = [json.loads(line) for line in (OUT / 'baseline/spans.jsonl').read_text().splitlines()]
    expected_captions = caption_module.extract_figure_captions(units, spans, crops)
    captions = load('networks/figure_captions.json')
    check('all_full_captions_match_indexed_pdf_spans', captions == expected_captions, {'captions': len(captions)})
    markdown_errors = network_view_errors(examples, network_markdown, (OUT / 'networks/network_requirement_links.md').read_text(), expected_captions)
    check('readable_network_assessments_match_structured_records', not markdown_errors, markdown_errors)
    source = load('validation/source_validation.json')
    check('source_validation_passed', source['status'] == 'pass', source['status'])
    review_binding = {'status': 'not_available', 'semantic_verdict_is_separate': True}
    review_dir = next((p for p in ['validation/ontology_review', 'validation/plan_audit', 'validation/review'] if (OUT / p / 'reviewed_artifact_hashes.json').is_file()), 'validation/review')
    manifest_path = OUT / review_dir / 'reviewed_artifact_hashes.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        bound = manifest.get('artifacts', {})
        bound, relocated_paths, relocation_receipt = relocated_review_bindings(bound, manifest_path)
        mandatory = {'source/source_index.jsonl','source/corrections.json','source/structural_corrections.json','requirements/groups.json','requirements/background.json','networks/examples.json','networks/mapping_decisions.json','networks/networks.md','networks/requirement_links.md','roles/roles.json','roles/mentions.jsonl','exhaustive/sentences.md','exhaustive/table_rows.md','exhaustive/other_units.md'}
        mandatory.update({'networks/configurations.md', 'networks/protocol_exchanges.md'})
        mandatory.update({'roles/ontology_decisions.json', *{'roles/' + name for name in ontology_module.OUTPUT_NAMES}, '../../scripts/preprocess/preprocess_csfc_ontology.py', '../../scripts/preprocess/templates/csfc_role_ontology.html', '../../tests/test_csfc_ontology.py'})
        if review_dir == 'validation/ontology_review':
            #* The ontology review extends the earlier audit without reducing its coverage.
            previous = load('validation/plan_audit/reviewed_artifact_hashes.json')
            mandatory.update(previous['artifacts'])
        mandatory = {relocated_paths.get(path, path) for path in mandatory}
        changed = [p for p, digest in bound.items() if not (OUT / p).is_file() or sha(OUT / p) != digest]
        absent_bindings = sorted(mandatory - set(bound))
        reports = ['review.json', 'findings.json', 'review.md'] if review_dir == 'validation/review' else ['review.json', 'independent_findings.json', 'independent_review.md']
        report_missing = [review_dir + '/' + p for p in reports if not (OUT / review_dir / p).is_file()]
        review_binding = {'status': 'current' if not changed and not absent_bindings and not report_missing else 'stale_or_incomplete', 'review_directory': review_dir, 'changed_artifacts': changed, 'missing_bindings': absent_bindings, 'missing_review_reports': report_missing, 'review_status': manifest.get('review_status'), 'semantic_verdict_is_separate': True}
        if relocation_receipt:
            review_binding['relocation_receipt'] = relocation_receipt
            review_binding['relocation_scope'] = load(relocation_receipt)['scope'] + ' No new independent semantic review is claimed.'
            amendments = load(relocation_receipt).get('semantic_amendments', [])
            review_binding['post_review_semantic_amendments'] = amendments
            review_binding['independent_review_covers_current_semantics'] = not amendments
    if require_semantic_review:
        check('independent_review_and_recorded_updates_have_valid_provenance', review_binding['status'] == 'current', review_binding)
    result = {'status': 'pass' if not errors else 'fail', 'scope': 'Mechanical cross-artifact validation only.', 'checks': checks, 'errors': errors, 'counts': {'source_units': len(units), 'requirement_groups': len(req['groups']), 'background_units': len(bg['source_units']), 'examples': len(examples), 'roles': len(roles), 'role_mentions': len(mentions)}, 'artifact_hashes': {p: sha(OUT / p) for p in required}, 'review_binding': review_binding}
    (OUT / 'validation/artifact_validation.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    lines = ['# Cross-artifact mechanical validation', '', 'Status: **' + result['status'] + '**. Semantic review remains a separate assessment.', '']
    lines += ['- ' + ('PASS' if c['passed'] else 'FAIL') + ': ' + k + '. ' + json.dumps(c['detail'],ensure_ascii=False) for k,c in checks.items()]
    (OUT / 'validation/artifact_validation.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'status':result['status'],'counts':result['counts'],'errors':errors},indent=2))
    return not errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-semantic-review', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if validate(args.require_semantic_review) else 1)
