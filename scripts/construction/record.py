#!/usr/bin/env python3
"""Record construction events and preserve source checkpoints with UTC times."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import os
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=['event', 'checkpoint'])
    parser.add_argument('--actor', required=True)
    parser.add_argument('--reason', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--details', default='{}')
    parser.add_argument('--paths', nargs='*', default=[])
    parser.add_argument('--history-dir', default='history')
    args = parser.parse_args()
    root = Path.cwd().resolve()
    history = (root / args.history_dir).resolve()
    history.relative_to(root)
    history.mkdir(parents=True, exist_ok=True)
    instant = datetime.now(timezone.utc)
    #* Parallel commands can receive the same clock reading. Keep records distinct.
    stamp = instant.strftime('%Y%m%dT%H%M%S.%fZ') + '-' + uuid.uuid4().hex
    entry = {'at': instant.isoformat(), 'actor': args.actor, 'kind': args.kind,
             'label': args.label, 'reason': args.reason,
             'details': json.loads(args.details)}
    if args.kind == 'checkpoint':
        target = history / (stamp + '-' + args.actor)
        target.mkdir()
        files = []
        captured = set()
        history_references = []
        for name in args.paths:
            source = (root / name).resolve()
            source.relative_to(root)
            if not source.exists():
                continue
            candidates=[]
            if source.is_dir():
                for current, directories, names in os.walk(source):
                    current_path=Path(current)
                    retained=[]
                    for directory in sorted(directories):
                        child=current_path/directory
                        if child.is_symlink() or directory in {'.git','.lake','__pycache__','private','secrets','pki'}:
                            continue
                        if child.resolve()==history:
                            continue
                        if directory=='history':
                            entries=[]
                            for record in sorted(child.glob('*.json')):
                                if record.is_file() and not record.is_symlink():
                                    entries.append({'path':str(record.relative_to(root)),'sha256':hashlib.sha256(record.read_bytes()).hexdigest(),'bytes':record.stat().st_size})
                            history_references.append({'path':str(child.relative_to(root)),'reason':'Existing nested history remains preserved in place; do not recursively duplicate checkpoint trees','record_manifests':entries})
                            continue
                        retained.append(directory)
                    directories[:]=retained
                    candidates.extend(current_path/name for name in sorted(names))
            else:
                candidates=[source]
            for path in candidates:
                relative = path.relative_to(root)
                if str(relative) in captured:
                    continue
                if not path.is_file() or path.is_symlink():
                    continue
                if history == path or history in path.parents:
                    continue
                if any(part in {'.git', '.lake', '__pycache__', 'private', 'secrets', 'pki'} for part in relative.parts):
                    continue
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, destination)
                copied = destination.read_bytes()
                files.append({'path': str(relative), 'sha256': hashlib.sha256(copied).hexdigest(), 'bytes': len(copied)})
                captured.add(str(relative))
        entry['checkpoint'] = str(target.relative_to(root))
        entry['files'] = files
        entry['history_references'] = history_references
        (target / 'manifest.json').write_text(json.dumps(entry, indent=2) + '\n')
    path = history / (stamp + '-' + args.actor + '.json')
    path.write_text(json.dumps(entry, indent=2) + '\n')
    print(str(path.relative_to(root)))


if __name__ == '__main__':
    main()
