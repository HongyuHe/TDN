#!/usr/bin/env python3
"""Summarize the current construction run without upgrading proof claims."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text())


def main():
    pointer = read(ROOT / 'artifacts/construction/current.json')
    run = ROOT / 'artifacts/construction' / pointer['directory']
    state = read(run / 'session.json')
    groups_path = run / 'agents/construction/outputs/theorem_register.json'
    cases_path = run / 'agents/evidence/outputs/case_coverage.json'
    groups = read(groups_path)['groups'] if groups_path.exists() else []
    cases = read(cases_path)['cases'] if cases_path.exists() else []
    original = read(ROOT / 'artifacts/extraction/requirements/groups.json')['groups']
    expected = {g['group_id']: g for g in original}
    errors = []
    if groups:
        if len(groups) != 76 or {g['group_id'] for g in groups} != set(expected):
            errors.append('The target register does not contain exactly the 76 source groups.')
        for group in groups:
            source = expected.get(group['group_id'])
            if source and group['original_intended_statement'] != source['theorem_statement']:
                errors.append('Original statement changed: ' + group['group_id'])
    source_examples = read(ROOT / 'artifacts/extraction/networks/examples.json')
    if cases and {c['example_id'] for c in cases} != {e['example_id'] for e in source_examples}:
        errors.append('The case register does not cover exactly the extracted examples.')
    events = []
    if (run / 'evolution/coordinator.jsonl').exists():
        events += [json.loads(line) for line in (run / 'evolution/coordinator.jsonl').read_text().splitlines()]
    for actor in ['evidence', 'construction']:
        history = run / 'agents' / actor / 'history'
        for path in history.glob('*.json'):
            entry = read(path)
            entry['record_path'] = str(path.relative_to(run))
            events.append(entry)
    events.sort(key=lambda event: event.get('at', ''))
    report = {'at': datetime.now(timezone.utc).isoformat(), 'run_id': state['run_id'],
              'status': state['status'], 'target_count': len(groups),
              'target_status_counts': dict(Counter(g['status'] for g in groups)),
              'case_count': len(cases), 'case_status_counts': dict(Counter(c['status'] for c in cases)),
              'representative_case_status_counts': dict(Counter(c.get('representative_status', 'unclassified') for c in cases)),
              'register_checks': {'passed': not errors, 'errors': errors},
              'interpretation': 'Agent-reported outcomes require separate coordinator validation. A register entry is not a checked proof.'}
    (run / 'progress.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Construction evolution', '', 'Run: `' + state['run_id'] + '`. Status: **' + state['status'] + '**.', '',
             'The timeline records reported changes and their reasons. Proof and deployment claims remain subject to their linked validation records.', '',
             '- [Proof register](agents/construction/outputs/theorem_register.json)',
             '- [Representative cases](agents/evidence/outputs/case_coverage.json)',
             '- [Evidence evolution](agents/evidence/outputs/EVOLUTION.md)',
             '- [Proof evolution](agents/construction/outputs/EVOLUTION.md)',
             '- [Agent interactions](INTERACTIONS.md)',
             '- [Progress and coverage checks](progress.json)', '',
             '| UTC timestamp | Actor | Event | Reason | Record |', '| --- | --- | --- | --- | --- |']
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    for event in events:
        name = event.get('label', event.get('kind', 'event'))
        reason = event.get('reason', 'Preserved ' + str(len(event.get('updates', []))) + ' changed artifacts.')
        path = event.get('record_path', 'evolution/coordinator.jsonl')
        lines.append('| ' + ' | '.join([cell(event.get('at', '')), cell(event.get('actor', '')), cell(name), cell(reason), '[record](' + path + ')']) + ' |')
    (run / 'EVOLUTION.md').write_text('\n'.join(lines) + '\n')
    interactions = []
    for path in (run / 'communications').glob('*.json'):
        entry = read(path)
        if 'author' in entry:
            body = '\n'.join(item['text'] for item in entry.get('content', []) if 'text' in item)
            actor, recipient = entry['author'], entry.get('recipient', '')
        elif 'tool' in entry:
            arguments = entry.get('arguments', {})
            body = arguments.get('message', arguments.get('prompt', ''))
            actor = 'Coordinator tool call'
            recipient = arguments.get('target', arguments.get('task_name', ''))
        else:
            continue
        interactions.append((entry.get('at', ''), actor, recipient, body, str(path.relative_to(run))))
    interactions.sort()
    transcript = ['# Agent interactions', '',
                  'Each row links to the exact recorded coordination message or launch instruction. The preview is shortened for scanning. Internal encrypted metadata is excluded.', '',
                  '| UTC timestamp | From | To | Message preview | Full record |',
                  '| --- | --- | --- | --- | --- |']
    for instant, actor, recipient, body, path in interactions:
        preview = ' '.join(body.split())
        if len(preview) > 220:
            preview = preview[:217] + '...'
        transcript.append('| ' + ' | '.join([cell(instant), cell(actor), cell(recipient), cell(preview), '[record](' + path + ')']) + ' |')
    (run / 'INTERACTIONS.md').write_text('\n'.join(transcript) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
