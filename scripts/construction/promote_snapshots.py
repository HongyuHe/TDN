#!/usr/bin/env python3
"""Verify immutable evidence and copy it into the repository and proof workspace."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil


ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True)
    parser.add_argument('bundles', nargs='+')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.label):
        raise ValueError('Use a simple event label.')
    current = json.loads((ROOT / 'artifacts/construction/current.json').read_text())
    run = ROOT / 'artifacts/construction' / current['directory']
    state = json.loads((run / 'session.json').read_text())
    evidence = Path(state['workspaces']['evidence']) / 'outputs/snapshots'
    construction = Path(state['workspaces']['construction']) / 'inputs/snapshots'
    records = []
    for name in args.bundles:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Bundle names must be relative to the evidence snapshot directory.')
        source = evidence / relative
        manifest_path = source / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        files = [Path('manifest.json')]
        for entry in manifest['files']:
            entry_path = Path(entry['path'])
            if entry_path.is_absolute() or '..' in entry_path.parts:
                raise ValueError('Manifest file paths must be bundle-relative.')
            path = source / entry_path
            if not path.resolve().is_relative_to(source.resolve()) or path.is_symlink():
                raise ValueError('Manifest path escapes the bundle or is a symlink.')
            if digest(path) != entry['sha256']:
                raise ValueError('Manifest hash mismatch: ' + str(path))
            files.append(entry_path)
        basis = 'started_at' if manifest.get('started_at') else 'assembled_at'
        instant = manifest.get(basis)
        if not instant:
            instant = json.loads((source / 'events.json').read_text())['started_at']
            basis = 'events.started_at'
        timestamp = datetime.fromisoformat(instant).strftime('%Y-%m-%dT%H%M%SZ')
        label = re.sub(r'-20\d{6}T\d{4,6}Z$', '', relative.name)
        if basis == 'assembled_at':
            label += '-assembled'
        destination = ROOT / 'artifacts/snapshots' / ('msc-' + timestamp + '-' + label)
        for target in [destination, construction / relative]:
            for item in files:
                saved = target / item
                if saved.exists() and digest(saved) != digest(source / item):
                    raise ValueError('Refusing to overwrite immutable evidence: ' + str(saved))
                if not saved.exists():
                    saved.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source / item, saved)
        project_path = str(destination.relative_to(ROOT))
        ignore = ROOT / '.gitignore'
        content = ignore.read_text()
        rule = '!/' + project_path + '/'
        if rule not in content.splitlines():
            ignore.write_text(content + '\n' + rule + '\n!/' + project_path + '/**\n')
        records.append({'source_id': name, 'repository_path': project_path,
                        'manifest_sha256': digest(manifest_path), 'file_count': len(files),
                        'timestamp_basis': basis})
    event = {'at': datetime.now(timezone.utc).isoformat(), 'actor': 'coordinator',
             'kind': 'evidence_handoff', 'label': args.label,
             'reason': 'Verify manifest hashes and retain immutable repository and proof inputs.',
             'command': ['python3', 'scripts/construction/promote_snapshots.py', '--label', args.label, *args.bundles],
             'details': records}
    (run / 'validation' / (args.label + '-handoff.json')).write_text(json.dumps(records, indent=2) + '\n')
    with (run / 'evolution/coordinator.jsonl').open('a') as handle:
        handle.write(json.dumps(event) + '\n')
    print(json.dumps(records, indent=2))


if __name__ == '__main__':
    main()
