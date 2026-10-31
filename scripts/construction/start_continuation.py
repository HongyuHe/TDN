"""Prepare isolated continuation workspaces without exposing archived proofs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    run = root / 'data/construction' / args.run
    base = Path('/tmp') / ('tdn-continuation-' + args.run)
    base.mkdir(exist_ok=False)
    old = root / 'data/construction/2026-10-17T205010Z'
    source = json.loads((old / 'source_paths.json').read_text())
    models = {'construction': ('gpt-6-astra', 'high'), 'evidence': ('gpt-6.1-sol', 'high')}
    manifest = {'run': args.run, 'started_at': datetime.now(timezone.utc).isoformat(), 'workspaces': {}, 'isolation_checks': []}
    for actor, model in models.items():
        work = base / actor
        work.mkdir()
        for name in ['TDN', 'TDN.lean', 'scripts/construction', 'tests', 'data/extraction', 'workflows/construction.md', 'lakefile.toml', 'lake-manifest.json', 'lean-toolchain']:
            src, dst = root / name, work / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '.git'))
            else:
                shutil.copy2(src, dst)
        #* Copy only observations and metadata explicitly named by the current input manifest.
        paths = list(source['paths'].values())
        paths += [p for collection in source['collections'].values() for p in collection.values()]
        for name in paths:
            src, dst = root / name, work / name
            if dst.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns('.git', '__pycache__', 'private', 'secrets'))
            else:
                shutil.copy2(src, dst)
        out = work / 'data/construction' / args.run
        out.mkdir(parents=True)
        for name in ['theorem_register.json', 'evidence_requests.json']:
            shutil.copy2(old / 'integration' / name, out / name)
        (out / 'source_paths.json').write_text(json.dumps(source, indent=2) + '\n')
        for name in ['references', 'history', 'communications', 'requests', 'responses']:
            (out / name).mkdir()
        (work / 'outputs').mkdir()
        #* APFS copy-on-write clones isolate package and build changes from the working repository.
        subprocess.run(['cp', '-cR', str(root / '.lake'), str(work / '.lake')], check=True)
        other = base / ('evidence' if actor == 'construction' else 'construction')
        profile = base / (actor + '.sb')
        profile.write_text('(version 1)\n(allow default)\n' + ''.join(
            '(deny file-read* file-write* (subpath ' + json.dumps(str(p.resolve())) + '))\n'
            for p in [Path.home() / 'Projects', Path.home() / '.codex', other]
        ))
        wrapper = base / (actor + '-exec')
        wrapper.write_text('#!/bin/bash\nset -eu\ncd ' + str(work) + '\n' +
            'export TDN_INPUT_MANIFEST=' + str((out / 'source_paths.json').relative_to(work)) + '\n' +
            'export TDN_OUTPUT_DIR=' + str(out.relative_to(work)) + '\n' +
            'exec /usr/bin/sandbox-exec -f ' + str(profile) + ' "$@"\n')
        wrapper.chmod(0o755)
        denied = subprocess.run([str(wrapper), 'cat', str(root / 'archive/v1/TDN.lean')], capture_output=True, text=True)
        permitted = subprocess.run([str(wrapper), 'test', '-r', 'TDN.lean'])
        assert denied.returncode != 0 and 'Operation not permitted' in denied.stderr
        assert permitted.returncode == 0
        manifest['isolation_checks'].append({'actor': actor, 'archive_read_denied': True, 'current_development_readable': True})
        manifest['workspaces'][actor] = {'path': str(work), 'wrapper': str(wrapper), 'profile': str(profile), 'model': model[0], 'reasoning_effort': model[1]}
    manifest['workflow_sha256'] = hashlib.sha256((root / 'workflows/construction.md').read_bytes()).hexdigest()
    (run / 'session.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (run / 'validation/isolation_checks.json').write_text(json.dumps(manifest['isolation_checks'], indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
