#!/usr/bin/env python3
"""Check workflow bookkeeping and report open work without judging proof meaning."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-converged', action='store_true')
    args = parser.parse_args()
    run = ROOT / 'artifacts/construction' / read(ROOT / 'artifacts/construction/current.json')['directory']
    construction = run / 'agents/construction/outputs'
    evidence = run / 'agents/evidence/outputs'
    groups = read(construction / 'theorem_register.json')['groups']
    cases = read(evidence / 'case_coverage.json')['cases']
    requests = read(construction / 'evidence_requests.json')['requests']
    responses = read(evidence / 'evidence_requests_responses.json')['requests']
    original = read(ROOT / 'artifacts/extraction/requirements/groups.json')['groups']
    examples = read(ROOT / 'artifacts/extraction/networks/examples.json')
    errors = []
    open_work = []
    expected = {g['group_id']: g for g in original}
    if len(groups) != 76 or {g['group_id'] for g in groups} != set(expected):
        errors.append('Target IDs must match all 76 extracted groups exactly.')
    for group in groups:
        identifier = group['group_id']
        source = expected.get(identifier)
        if source and group['original_intended_statement'] != source['theorem_statement']:
            errors.append(identifier + ': original statement differs from extraction.')
        if not group.get('disposition_reason'):
            errors.append(identifier + ': missing explanation of the result.')
        if group['status'] == 'established_within_listed_scopes':
            if not group.get('formal_definition') or not group.get('established_scopes'):
                errors.append(identifier + ': checked claim lacks a definition or scope.')
            for scope in group.get('established_scopes', []):
                for field in ['scope', 'theorem', 'assumptions', 'report', 'validation']:
                    if not scope.get(field):
                        errors.append(identifier + ': scope lacks ' + field + '.')
    if len({c['case_id'] for c in cases}) != len(cases):
        errors.append('Representative case IDs are duplicated.')
    if {c['example_id'] for c in cases} != {e['example_id'] for e in examples}:
        errors.append('Representative cases do not cover exactly the extracted example IDs.')
    for case in cases:
        status = case.get('representative_status', case['status'])
        if any(word in status for word in ['planned', 'progress', 'pending']):
            open_work.append(case['case_id'] + ': ' + status)
        elif status == 'covered' and not case.get('snapshot_ids'):
            errors.append(case['case_id'] + ': covered case lacks a snapshot reference.')
        elif status not in {'covered', 'represented'} and not case.get('unrepresented_reason'):
            errors.append(case['case_id'] + ': incomplete case lacks a reason.')
    response_map = {r['request_id']: r for r in responses if r.get('request_id')}
    request_ids = [r['request_id'] for r in requests]
    if len(set(request_ids)) != len(request_ids):
        errors.append('Evidence request IDs are duplicated.')
    for request in requests:
        identifier = request['request_id']
        response = response_map.get(identifier)
        if response is None:
            open_work.append(identifier + ': missing Evidence Agent ledger response')
        for actor, record in [('Construction', request), ('Evidence', response)]:
            if record is None:
                continue
            status = record.get('status', 'unknown')
            if any(word in status for word in ['submitted', 'pending', 'progress', 'unknown']):
                open_work.append(identifier + ': ' + actor + ' status ' + status)
    for response in responses:
        identifier = response.get('request_id', response.get('id', 'unnamed response'))
        if response.get('pending'):
            open_work.append(identifier + ': response retains pending obligations')
        if identifier not in request_ids:
            status = response.get('status', 'unknown')
            if any(word in status for word in ['submitted', 'pending', 'progress', 'unknown']):
                open_work.append(identifier + ': separate Evidence request status ' + status)
    report = {
        'at': datetime.now(timezone.utc).isoformat(),
        'structural_checks_passed': not errors,
        'errors': errors,
        'open_work': open_work,
        'counts': {'targets': len(groups), 'cases': len(cases), 'requests': len(requests)},
        'target_status_counts': dict(Counter(g['status'] for g in groups)),
        'representative_case_status_counts': dict(Counter(c.get('representative_status') for c in cases)),
        'interpretation': 'Mechanical bookkeeping only. Source fidelity, proof meaning, valid rejection reasons, and live behavior require separate review. Unresolved proof outcomes are allowed when their remaining obligations are explicit.'
    }
    (run / 'validation/workflow-bookkeeping.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if errors or (args.require_converged and open_work) else 0)


if __name__ == '__main__':
    main()
