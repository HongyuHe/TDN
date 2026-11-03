"""Create an isolated v3.1 constructor workspace and an immutable baseline."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clone(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cp', '-cR', str(source), str(destination)], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run_id = args.run or 'v3.1-' + stamp
    run = root / 'data/construction' / run_id
    run.mkdir(parents=True, exist_ok=False)
    for name in ['baseline', 'communications', 'interpretation', 'proof', 'validation', 'history', 'mcp']:
        (run / name).mkdir()
    work = Path('/tmp') / ('tdn-' + run_id) / 'constructor'
    work.mkdir(parents=True, exist_ok=False)
    names = ['TDN', 'TDN.lean', 'lakefile.toml', 'lake-manifest.json', 'lean-toolchain', 'mcp', 'data/evidence', 'data/extraction', 'specs', 'workflows/construction.md', 'scripts/construction', 'tests']
    #* Copy tracked active files only, without repository history or archived theory.
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    selected = [name for name in tracked if name and any(name == prefix or name.startswith(prefix + '/') for prefix in names)]
    for name in selected:
        src, dst = root / name, work / name
        if not src.is_file() or src.is_symlink():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    #* The workflow and preparation script include the supervisor's uncommitted update.
    for name in ['workflows/construction.md', 'scripts/construction/start_v31.py',
                 'scripts/construction/mcp_session.py', 'scripts/construction/export_spec_definitions.lean',
                 'scripts/construction/prepare_interpretation.py']:
        shutil.copy2(root / name, work / name)
    inputs = work / 'inputs'
    inputs.mkdir()
    shutil.copy2(root / 'data/construction/2026-10-24T014455Z/interpretations.md', inputs / 'prior_interpretations.md')
    (work / 'outputs').mkdir()
    clone(root / '.lake', work / '.lake')
    stale_cache = []
    for cache_subdir in ['.lake/build/lib/lean/TDN', '.lake/build/ir/TDN']:
        cache = work / cache_subdir
        for path in cache.rglob('*'):
            if path.is_file():
                relative = path.relative_to(cache)
                source = work / 'TDN' / relative.parent / (relative.name.split('.')[0] + '.lean')
                if not source.exists():
                    stale_cache.append(str(path.relative_to(work)))
                    path.unlink()
    #* Only the current campaign's captured network evidence is initially permitted.
    captures = root / 'data/snapshots/2026-10-24T014455Z'
    clone(captures, work / 'data/snapshots/2026-10-24T014455Z')
    captured_root = work / 'data/snapshots/2026-10-24T014455Z'
    saved = {path.name: '../data/snapshots/2026-10-24T014455Z/' + path.name
             for path in captured_root.iterdir()
             if (path / 'snapshot.json').is_file() and (path / 'manifest.json').is_file()}
    configuration = {'store': '../outputs/mcp/collections',
                     'lean_output': '../outputs/mcp/exported',
                     'networks': [], 'saved_snapshots': saved, 'adapter_modules': []}
    supplements = {
        'native-baseline-20261024T015000Z': 'native-baseline-processing-20261024T015100Z',
        'native-shared-four-levels-20261024T015300Z-coverage-v1': 'native-shared-processing-20261024T015500Z',
    }
    configuration['saved_execution_supplements'] = {
        name: '../data/snapshots/2026-10-24T014455Z/' + supplement
        for name, supplement in supplements.items()
        if name in saved and (captured_root / supplement / 'manifest.json').is_file()
    }
    configuration['execution_epoch_union'] = [name for name in ['native-baseline-20261024T015000Z']
        if name in configuration['saved_execution_supplements']]
    configuration['saved_experiments'] = {
        path.name: {'path': '../data/snapshots/2026-10-24T014455Z/pairings-v7/' + path.name,
                    'parser': 'mixed-protocol-v1'}
        for path in sorted((captured_root / 'pairings-v7').glob('*'))
        if path.is_dir() and (path / 'manifest.json').is_file()
    }
    (inputs / 'evidence-mcp.json').write_text(json.dumps(configuration, indent=2) + '\n')
    profile = work.parent / 'constructor.sb'
    denied = [Path.home() / 'Projects', Path.home() / '.codex']
    profile.write_text('(version 1)\n(allow default)\n' + ''.join('(deny file-read* file-write* (subpath ' + json.dumps(str(p.resolve())) + '))\n' for p in denied))
    wrapper = work.parent / 'constructor-exec'
    wrapper.write_text('#!/bin/bash\nset -eu\ncd ' + str(work) + '\nexec /usr/bin/sandbox-exec -f ' + str(profile) + ' "$@"\n')
    wrapper.chmod(0o755)
    checks = {}
    for name in ['archive/v1/TDN.lean', 'specs/requirement_groups.md', '.git/config']:
        r = subprocess.run([str(wrapper), 'cat', str(root / name)], capture_output=True, text=True)
        checks[name] = {'denied': r.returncode != 0 and 'Operation not permitted' in r.stderr}
    checks['active_source_readable'] = subprocess.run([str(wrapper), 'test', '-r', 'TDN.lean']).returncode == 0
    assert all(v['denied'] for k, v in checks.items() if isinstance(v, dict))
    assert checks['active_source_readable']
    for name in ['TDN', 'TDN.lean', 'lakefile.toml', 'lake-manifest.json', 'lean-toolchain', 'workflows/construction.md', 'specs/proof_scope.json']:
        clone(root / name, run / 'baseline' / name)
    scope = json.loads((root / 'specs/proof_scope.json').read_text())
    ids = [g['id'] for g in scope['groups'] if g['decision'] == 'formal']
    assert len(ids) == 24
    manifest = {
        'run': run_id, 'started_at': datetime.now(timezone.utc).isoformat(),
        'baseline_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'constructor': {'model': 'gpt-6.1-sol', 'effort': 'xhigh', 'workspace': str(work), 'wrapper': str(wrapper)},
        'interpreter': {'model': 'gpt-6.1-sol', 'effort': 'high', 'fresh_each_round': True},
        'selected_groups': ids, 'isolation_checks': checks,
        'isolation_limits': 'Sandbox rules enforce file access for commands through the wrapper. Agent instructions require all filesystem commands to use the wrapper; the agent tool service itself is not confined.',
        'workflow_sha256': digest(root / 'workflows/construction.md'),
        'mcp_configuration_sha256': digest(inputs / 'evidence-mcp.json'),
        'baseline_evidence_hashes': {str(p.relative_to(work)): digest(p) for p in sorted((work / 'data/evidence').rglob('*.json'))},
        'baseline_hashes': {str(p.relative_to(run / 'baseline')): digest(p) for p in sorted((run / 'baseline').rglob('*')) if p.is_file()},
        'permitted_tracked_files': selected,
        'removed_stale_build_artifacts': stale_cache,
    }
    (run / 'session.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (run / 'events.jsonl').write_text(json.dumps({'at': manifest['started_at'], 'actor': 'supervisor', 'event': 'run_initialized', 'baseline': manifest['baseline_commit'], 'selected_groups': ids, 'workflow_sha256': manifest['workflow_sha256']}) + '\n')
    (run / 'validation/isolation.json').write_text(json.dumps(checks, indent=2) + '\n')
    print(json.dumps({'run': str(run), 'workspace': str(work), 'wrapper': str(wrapper), 'groups': ids}, indent=2))


if __name__ == '__main__':
    main()
