#!/usr/bin/env python3
"""Resolve reviewed example decisions against grouped clauses and source evidence."""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction'
STATUSES = {
    'presented_as_satisfying', 'presented_as_violating',
    'required_but_not_demonstrated', 'ambiguous', 'not_applicable',
}
BASES = {'explicit_source_statement', 'interpreted_source_presentation', 'visual_interpretation'}
EXAMPLE_VIEWS = [
    ('topology', 'networks.md', 'Example networks', 'Concrete network topologies with identified components, network zones, and connections.'),
    ('protocol_exchange', 'protocol_exchanges.md', 'Protocol exchanges', 'Message exchanges between protocol endpoints.'),
    ('textual_configuration', 'configurations.md', 'Partial configurations and alternatives', 'Partial arrangements and design alternatives described in prose or tables, without a concrete network topology.'),
]


def extract_figure_captions(source, spans, figures):
    """Recover complete captions from PDF spans, preserving literal-period fragments."""
    captions = {}
    for span in spans:
        if span['kind'] != 'figure_caption':
            continue
        text = re.sub(r'\s+', ' ', span['raw_text']).strip()
        match = re.match(r'^Figure\s+(\d+)\.\s+(.+)$', text)
        if not match:
            raise ValueError('Incomplete figure caption: ' + span['span_id'])
        number = int(match[1])
        if number in captions:
            raise ValueError('Duplicate figure caption: ' + str(number))
        units = [u for u in source if u.get('prose_kind') == 'figure_caption' and any(s['span_id'] == span['span_id'] for s in u.get('baseline_spans', []))]
        if not units:
            raise ValueError('Caption has no indexed evidence: ' + span['span_id'])
        #* The full PDF span keeps decimal points intact, including CNSA 2.0.
        fragments = sorted((s['start'], s['end']) for u in units for s in u['baseline_spans'] if s['span_id'] == span['span_id'])
        recovered = ''.join(span['raw_text'][start:end] for start, end in fragments)
        if re.sub(r'\s+', '', recovered) != re.sub(r'\s+', '', span['raw_text']):
            raise ValueError('Caption fragments do not cover the PDF span: ' + span['span_id'])
        captions[number] = {'figure_number': number, 'page': span['page'], 'text': text, 'raw_text': span['raw_text'], 'source_ids': [u['source_id'] for u in units], 'baseline_span_ids': [span['span_id']], 'bbox': span['bbox']}
    expected = {f['figure_number']: f['page'] for f in figures}
    if set(captions) != set(expected) or any(captions[n]['page'] != page for n, page in expected.items()):
        raise ValueError('Figure captions must match every registered figure and page.')
    return [captions[n] for n in sorted(captions)]


def apply_mappings(networks):
    requirements = json.loads((OUT / 'requirements/groups.json').read_text())
    groups = {g['group_id']: g for g in requirements['groups']}
    source = [json.loads(line) for line in (OUT / 'source/source_index.jsonl').read_text().splitlines()]
    by_id = {u['source_id']: u for u in source}
    spans = [json.loads(line) for line in (OUT / 'baseline/spans.jsonl').read_text().splitlines()]
    captions = {c['figure_number']: c for c in extract_figure_captions(source, spans, json.loads((OUT / 'networks/crop_manifest.json').read_text()))}
    decisions = json.loads((OUT / 'networks/mapping_decisions.json').read_text())
    by_example = {e['example_id']: e for e in decisions['examples']}
    if set(by_example) != {e['example_id'] for e in networks}:
        raise ValueError('Mapping decisions must cover exactly the extracted examples.')
    for network in networks:
        network['figure_captions'] = [captions[c['figure_number']] for c in network['figure_crops']]
        decision = by_example[network['example_id']]
        mappings = []
        for index, item in enumerate(decision['mappings'], 1):
            group = groups[item['group_id']]
            if item['status'] not in STATUSES or item['basis'] not in BASES:
                raise ValueError('Invalid mapping status or evidence basis.')
            clause_ids = item['clause_source_ids']
            example_ids = item['example_source_ids']
            if not clause_ids or not set(clause_ids) <= set(group['source_ids']):
                raise ValueError('Clause references must belong to ' + group['group_id'])
            if not example_ids or not set(example_ids) <= set(network['source_ids']):
                raise ValueError('Example evidence is outside ' + network['example_id'])
            original_ids = list(dict.fromkeys(by_id[sid]['requirement_id'] for sid in clause_ids if by_id[sid].get('requirement_id')))
            if not set(original_ids) <= set(group['original_requirement_ids']):
                raise ValueError('Numbered requirement is outside its group.')
            mapping = dict(item)
            mapping.update({
                'mapping_id': network['example_id'] + '-MAP-' + f'{index:02}',
                'group_title': group['title'],
                'scope': 'specific_clause',
                'original_requirement_ids': original_ids,
                'clause_passages': [{'source_id': sid, 'text': by_id[sid]['text']} for sid in clause_ids],
                'example_passages': [{'source_id': sid, 'text': by_id[sid]['text']} for sid in example_ids],
                'requirement_strength': {
                    'interpretation': group['document_force']['interpretation'],
                    'table_rows': [row for row in group['document_force']['table_rows'] if row['source_id'] in clause_ids],
                    'semantics_source_ids': group['document_force']['semantics_source_ids'],
                },
                'group_qualifications_and_exceptions': group['qualifications_and_exceptions'],
                'group_open_issue_ids': group['open_issue_ids'],
                'group_scope_note_ids': group.get('scope_note_ids', []),
            })
            mappings.append(mapping)
        if not mappings:
            raise ValueError('Every example needs a substantive mapping.')
        network['requirement_group_mappings'] = mappings
        projection = {}
        for mapping in mappings:
            for rid in mapping['original_requirement_ids']:
                link = projection.setdefault(rid, {
                    'requirement_id': rid, 'group_ids': [mapping['group_id']],
                    'source_ids': [sid for sid in mapping['clause_source_ids'] if by_id[sid].get('requirement_id') == rid],
                    'mapping_ids': [], 'statuses': [],
                    'relation_basis': 'derived_from_scoped_group_mappings',
                    'relation': 'Read the linked clause-scoped mapping for applicability, source presentation, and evidence limits.',
                })
                link['mapping_ids'].append(mapping['mapping_id'])
                if mapping['status'] not in link['statuses']:
                    link['statuses'].append(mapping['status'])
        network['requirement_links'] = list(projection.values())
        network['compliance'] = {
            'status': 'scoped_group_assessment',
            'whole_solution_status': 'not_assessed',
            'status_counts': dict(sorted(Counter(m['status'] for m in mappings).items())),
            'scope_limit': decision['scope_limit'],
            'interpretation_policy': decisions['source_precedence_policy'] + ' Statuses describe the intended design; deployment implementation is a separate question.',
        }
        network['status'] = 'evidence_linked_semantic_review_separate'
    return networks


def mapping_summary(network):
    lines = [network['compliance']['scope_limit'], '']
    labels = {
        'presented_as_satisfying': 'Presented as satisfying',
        'presented_as_violating': 'Presented as violating',
        'required_but_not_demonstrated': 'Required; implementation not demonstrated',
        'ambiguous': 'Ambiguous',
        'not_applicable': 'Not applicable to selected alternative',
    }
    lines += ['| Requirement group | Selected clause | Assessment |', '| --- | --- | --- |']
    for mapping in network['requirement_group_mappings']:
        target = '../requirements/requirement_groups.md#' + mapping['group_id'].lower()
        group_link = f'[{mapping["group_id"]}: {mapping["group_title"]}]({target})'
        assessment = '[' + labels[mapping['status']] + '](network_requirement_links.md#' + mapping['mapping_id'].lower() + ')'
        lines.append('| ' + group_link + ' | ' + mapping['clause_scope'].replace('|', '\\|') + ' | ' + assessment + ' |')
    lines.append('')
    return lines


def mapping_markdown(network):
    lines = ['### Requirement-group assessment', ''] + mapping_summary(network)
    for mapping in network['requirement_group_mappings']:
        target = '../requirements/requirement_groups.md#' + mapping['group_id'].lower()
        lines += [
            '<a id="' + mapping['mapping_id'].lower() + '"></a>', '',
            f'#### {mapping["mapping_id"]}: [{mapping["group_id"]} - {mapping["group_title"]}]({target})', '',
            f'**{mapping["status"]}** | Basis: `{mapping["basis"]}` | Scope: selected clause only.', '',
            '**Clause assessed:** ' + mapping['clause_scope'], '',
            '**Applicability:** ' + mapping['applicability'], '',
            '**Reasoning:** ' + mapping['rationale'], '',
            '**Requirement strength:** ' + mapping['requirement_strength']['interpretation'], '',
        ]
        for row in mapping['requirement_strength']['table_rows']:
            lines += [f'- `{row["original_requirement_id"]}`: `{row["threshold_objective_verbatim"]}`; alternatives: `{row["alternatives_verbatim"] or "none stated"}`.']
        if mapping['requirement_strength']['table_rows']:
            lines.append('')
        lines += ['**Qualifications and exceptions:** ' + mapping['qualifications_and_exceptions'], '']
        if mapping['group_open_issue_ids']:
            lines += ['Group interpretation issues: ' + ', '.join(mapping['group_open_issue_ids']) + '.', '']
        if mapping['group_scope_note_ids']:
            lines += ['Group scope notes: ' + ', '.join(mapping['group_scope_note_ids']) + '.', '']
        lines += ['Selected requirement clauses, quoted verbatim:', '']
        for passage in mapping['clause_passages']:
            lines += [f'`{passage["source_id"]}`', '', '> ' + passage['text'], '']
        lines += ['Example evidence, quoted verbatim:', '']
        for passage in mapping['example_passages']:
            text = passage['text'] or '[Indexed figure region; inspect the figure crop above.]'
            lines += [f'`{passage["source_id"]}`', '', '> ' + text, '']
    return lines


def summary_table(title, headers, rows):
    if not rows:
        return []
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    return [f'### {title}', '', '| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |'] + ['| ' + ' | '.join(cell(value) for value in row) + ' |' for row in rows] + ['']


def example_summary(e):
    lines = []
    counts = ', '.join(f'{status}: {count}' for status, count in e['compliance']['status_counts'].items())
    lines += [f'## {e["example_id"]}: {e["title"]}','','Kind: '+e['kind']+'. Requirement assessment: {'+counts+'}.','']
    for c in e['figure_crops']:
        caption = next(x for x in e['figure_captions'] if x['figure_number'] == c['figure_number'])
        lines += [f'![Figure {c["figure_number"]}](crops/figure-{c["figure_number"]:02}.png)', '', '**' + caption['text'] + '**', '', f'PDF page {c["page"]}. [Caption text and source references](figure_captions.json).', '']
    if not e['figure_crops']:
        lines += ['Figure: none assigned. Extracted from prose or tables as a partial configuration.', '']
    lines += mapping_summary(e)
    lines += ['[Detailed assessments and source passages](network_requirement_links.md#' + e['example_id'].lower() + ').', '']
    lines += summary_table('Devices and aggregate services', ['ID', 'Name', 'Location', 'Roles', 'Evidence basis'], [(d['device_id'], d['name'], d['location'], ', '.join(d['role_ids']), d['basis']) for d in e['devices']])
    lines += summary_table('Solution aggregates', ['ID', 'Name', 'Evidence basis'], [(a['aggregate_id'], a['name'], a['basis']) for a in e.get('aggregates', [])])
    lines += summary_table('Networks and zones', ['ID', 'Name', 'Zone', 'Location', 'Evidence basis'], [(z['network_id'], z['name'], z['zone'], z['location'], z['basis']) for z in e['networks']])
    for key, label in [('interfaces','Interfaces'), ('sites_and_boundaries','Sites and boundaries'), ('shared_components','Shared components')]:
        lines += summary_table(label, ['Summary', 'Evidence basis'], [(f['text'], f['basis']) for f in e[key]])
    lines += summary_table('Configuration alternatives', ['Name', 'Meaning'], [(c['name'], json.dumps(c['meaning'], ensure_ascii=False) if isinstance(c['meaning'], dict) else c['meaning']) for c in e.get('configurations', [])])
    lines += summary_table('Recorded facts', ['Summary', 'Evidence basis'], [(f['text'], f['basis']) for f in e['facts']])
    lines += summary_table('Connections', ['Endpoints', 'Description', 'Evidence basis'], [(' ↔ '.join(link['endpoints']), link['description'], link['basis']) for link in e['links']])
    lines += summary_table('Unknown details', ['Unspecified information'], [(x,) for x in e['unknowns']])
    lines += summary_table('Open issues', ['ID', 'Summary'], [(x['issue_id'], x['description']) for x in e['open_issues']])
    return lines


def write_networks(examples):
    known_kinds = {kind for kind, _, _, _ in EXAMPLE_VIEWS}
    if any(e['kind'] not in known_kinds for e in examples):
        raise ValueError('Every example must have a recognized presentation category.')
    for kind, filename, title, description in EXAMPLE_VIEWS:
        selected = [e for e in examples if e['kind'] == kind]
        links = ' | '.join(f'[{label}]({name})' for _, name, label, _ in EXAMPLE_VIEWS if name != filename)
        lines = [
            '# ' + title, '', description + f' Entries: {len(selected)}.', '', links, '',
            'Detailed assessments and verbatim source passages are in [network_requirement_links.md](network_requirement_links.md). Stable NET identifiers preserve references across categories.', '',
            'The original assessments were authored by the extraction subagent and independently reviewed. Later user-directed corrections are recorded in [mapping decisions](mapping_decisions.json). The scripts replay those decisions, verify source references, and render the reports.', '',
            'Statuses apply to the selected clauses and alternatives. Unmapped groups remain unassessed. General procurement, personnel, lifecycle, audit, and testing duties are not repeated for every schematic.', '',
            'Explicit textual descriptions and applicable requirements supply details omitted from figures. Schematic connections do not establish a physical bypass of a textually required component. Genuine conflicts between textual statements remain open.', '',
        ]
        for example in selected:
            lines += example_summary(example)
        (OUT / 'networks' / filename).write_text('\n'.join(lines).rstrip() + '\n')
    captions = {c['figure_number']: c for e in examples for c in e['figure_captions']}
    (OUT / 'networks/figure_captions.json').write_text(json.dumps([captions[n] for n in sorted(captions)], ensure_ascii=False, indent=2) + '\n')


def write_requirement_links(networks):
    lines = [
        '# Example to requirement-group assessments', '',
        'Every assessment names the selected clause and its applicability. Statuses describe source presentation or outstanding evidence for that clause. They do not certify every clause in a group or a deployed solution.', '',
        'Browse [network topologies](networks.md), [partial configurations and alternatives](configurations.md), or [protocol exchanges](protocol_exchanges.md). Numbered requirement links in examples.json are a compatibility projection of these assessments.', '',
        'The extraction subagent authored the original judgments in [mapping_decisions.json](mapping_decisions.json). An [independent audit](../validation/plan_audit/independent_review.md) reviewed that version. The decision file separately records later user-directed corrections by the coordinator. The scripts validate and render the saved judgments.', '',
        'Explicit textual descriptions and applicable requirements supply details omitted from figures. Ambiguous means the source wording, applicability, or example-to-requirement relationship remains unresolved after applying that rule. Missing symbols alone do not create ambiguity. A clear requirement with missing implementation evidence is labeled required_but_not_demonstrated.', '',
    ]
    for network in networks:
        lines += ['<a id="' + network['example_id'].lower() + '"></a>', '', '## ' + network['example_id'] + ': ' + network['title'], '']
        lines += mapping_markdown(network)
        lines += ['### Verbatim indexed setup passages', '']
        for passage in network['setup_passages']:
            lines += ['`' + passage['source_id'] + '`', '', '> ' + passage['text'], '']
    (OUT / 'networks/network_requirement_links.md').write_text('\n'.join(lines).rstrip() + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--networks-only', action='store_true', help='Compatibility flag; reconciliation only writes network artifacts.')
    parser.parse_args()
    networks = apply_mappings(json.loads((OUT / 'networks/examples.json').read_text()))
    (OUT / 'networks/examples.json').write_text(json.dumps(networks, indent=2, ensure_ascii=False) + '\n')
    write_networks(networks)
    write_requirement_links(networks)
    validation_path = OUT / 'networks/validation.json'
    validation = json.loads(validation_path.read_text())
    validation['requirement_group_reconciliation'] = 'complete'
    validation['scoped_requirement_mapping_count'] = sum(len(e['requirement_group_mappings']) for e in networks)
    validation['examples_with_scoped_requirement_mappings'] = len(networks)
    validation['mapping_status_counts'] = dict(sorted(Counter(m['status'] for e in networks for m in e['requirement_group_mappings']).items()))
    validation['independent_semantic_review'] = 'See validation/plan_audit and validation/final_status.json; producer checks do not grant semantic approval.'
    validation['limitations'] = [s for s in validation['limitations'] if not s.startswith('Requirement-group links require')]
    validation['example_kind_counts'] = dict(sorted(Counter(e['kind'] for e in networks).items()))
    validation_path.write_text(json.dumps(validation, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'examples': len(networks), 'categories': validation['example_kind_counts'], 'scoped_requirement_mappings': validation['scoped_requirement_mapping_count']}))


if __name__ == '__main__':
    main()
