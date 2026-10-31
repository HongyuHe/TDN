"""Copy new-run agent records and source checkpoints without changing old runs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_tree(source, target, versions=None):
    count = 0
    for path in source.rglob('*'):
        relative = path.relative_to(source)
        if any(p in {'.git', '.lake', '__pycache__', '.venv', 'tools-venv', 'upstream', 'private', 'secrets'} for p in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        dest = target / relative
        content = path.read_bytes()
        content_hash = hashlib.sha256(content).hexdigest()
        if dest.exists() and digest(dest) == content_hash:
            continue
        #* Preserve earlier collected records before updating the current agent view.
        if dest.exists() and versions is not None:
            prior = versions / relative.parent / digest(dest) / relative.name
            prior.parent.mkdir(parents=True, exist_ok=True)
            if not prior.exists():
                shutil.copy2(dest, prior)
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary = dest.with_name(dest.name + '.collecting')
        temporary.write_bytes(content)
        temporary.replace(dest)
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    run = root / 'artifacts/construction' / args.run
    state = json.loads((run / 'session.json').read_text())
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    counts = {}
    for actor, entry in state['workspaces'].items():
        work = Path(entry['path'])
        source = work / 'artifacts/construction' / args.run
        counts[actor] = copy_tree(source, run / 'agents' / actor,
                                  run / 'record-versions' / actor)
        files = []
        contents = {}
        candidates = []
        for name in ['TDN', 'scripts/construction', 'tests']:
            candidates += list((work / name).rglob('*'))
        candidates += [work / n for n in ['TDN.lean', 'lakefile.toml', 'lake-manifest.json', 'lean-toolchain']]
        for path in sorted(candidates):
            if path.is_symlink() or not path.is_file() or '__pycache__' in path.parts:
                continue
            #* Hash and preserve the same bytes even while an agent edits its source.
            relative = str(path.relative_to(work))
            content = path.read_bytes()
            contents[relative] = content
            files.append({'path': relative, 'sha256': hashlib.sha256(content).hexdigest()})
        signature = hashlib.sha256(json.dumps(files).encode()).hexdigest()
        checkpoint = run / 'checkpoints' / actor / signature
        if not checkpoint.exists():
            temporary = checkpoint.with_name('.collecting-' + stamp)
            temporary.mkdir(parents=True)
            for item in files:
                dest = temporary / item['path']
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(contents[item['path']])
            (temporary / 'manifest.json').write_text(json.dumps({'at': stamp, 'files': files}, indent=2) + '\n')
            temporary.rename(checkpoint)
        counts[actor + '_source_manifest'] = signature
    with (run / 'collection-events.jsonl').open('a') as output:
        output.write(json.dumps({'at': stamp, 'collected': counts}) + '\n')
    print(json.dumps(counts))


if __name__ == '__main__':
    main()
