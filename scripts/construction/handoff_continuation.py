"""Publish explicitly referenced public evidence to the coordinator and constructor."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def referenced_paths(value, prefix):
    if isinstance(value, str) and value.startswith(prefix):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from referenced_paths(item, prefix)
    elif isinstance(value, list):
        for item in value:
            yield from referenced_paths(item, prefix)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('responses', nargs='+')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    relative_run = Path('data/construction') / args.run
    run = root / relative_run
    session = json.loads((run / 'session.json').read_text())
    evidence = Path(session['workspaces']['evidence']['path'])
    construction = Path(session['workspaces']['construction']['path'])
    prefix = 'data/snapshots/' + args.run + '/'
    records = []
    for name in args.responses:
        if Path(name).name != name:
            raise ValueError('Response must be a filename')
        response = evidence / relative_run / 'responses' / name
        data = json.loads(response.read_text())
        paths = sorted(set(referenced_paths(data, prefix)))
        verified = 0
        public_files = []
        for relative in paths:
            source = evidence / relative
            if '..' in Path(relative).parts or source.is_symlink():
                raise ValueError('Unsafe evidence reference: ' + relative)
            if not source.exists():
                raise ValueError('Missing evidence reference: ' + relative)
            if not source.resolve().is_relative_to((evidence / prefix).resolve()):
                raise ValueError('Evidence reference leaves the permitted snapshot directory')
            manifests = list(source.rglob('manifest.json')) if source.is_dir() else []
            for manifest in manifests:
                for item in json.loads(manifest.read_text()).get('files', []):
                    path = manifest.parent / item['path']
                    if '..' in Path(item['path']).parts or Path(item['path']).is_absolute():
                        raise ValueError('Unsafe manifest path')
                    if digest(path) != item['sha256']:
                        raise ValueError('Evidence hash mismatch: ' + str(path))
                    verified += 1
            for target_root in [root, construction]:
                target = target_root / relative
                files = list(source.rglob('*')) if source.is_dir() else [source]
                for path in files:
                    if path.is_symlink():
                        raise ValueError('Symlink in published evidence')
                    if not path.is_file():
                        continue
                    destination = target / path.relative_to(source) if source.is_dir() else target
                    if destination.exists() and digest(destination) != digest(path):
                        raise ValueError('Published evidence changed: ' + str(destination))
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
        #* Public runtimes and source references require explicit file hashes.
        public_bases = [relative_run / 'evidence/runtime', relative_run / 'references']
        for item in data.get('external_public_files', []):
            relative = Path(item['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('Unsafe public runtime path')
            source = evidence / relative
            if (not source.is_file() or source.is_symlink()
                    or not any(source.resolve().is_relative_to((evidence / base).resolve())
                               for base in public_bases)):
                raise ValueError('Public file leaves the permitted runtime or reference directory')
            if digest(source) != item['sha256'] or source.stat().st_size != item['bytes']:
                raise ValueError('Public runtime hash or size mismatch')
            for target_root in [root, construction]:
                destination = target_root / relative
                if destination.exists():
                    if destination.is_symlink() or digest(destination) != item['sha256']:
                        raise ValueError('Published public runtime changed')
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                if digest(destination) != item['sha256']:
                    raise ValueError('Public runtime copy failed verification')
            public_files.append(str(relative))
            verified += 1
        for target in [run / 'communications' / name,
                       construction / relative_run / 'responses' / name]:
            #* Retain earlier response versions before publishing a corrected assessment.
            if target.exists() and digest(target) != digest(response):
                prior = target.parent / 'previous' / digest(target) / target.name
                prior.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, prior)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(response, target)
        records.append({'response': name, 'paths': paths, 'public_runtime_files': public_files,
                        'verified_files': verified})
    event = {'at': datetime.now(timezone.utc).isoformat(),
             'event': 'public_evidence_handoff', 'records': records}
    with (run / 'communications/coordinator-events.jsonl').open('a') as stream:
        stream.write(json.dumps(event) + '\n')
    print(json.dumps(event))


if __name__ == '__main__':
    main()
