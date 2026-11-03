"""Package compiled definitions for a fresh interpreter without source requirements."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--round', type=int, required=True)
    parser.add_argument('--map', default='outputs/spec_map.json')
    parser.add_argument('--exec-wrapper', help='Command wrapper for the frozen candidate workspace')
    parser.add_argument('--definition-source', action='append', default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    run = root / 'data/construction' / args.run
    work = Path(args.workspace).resolve()
    directory = run / 'interpretation' / f'round-{args.round:03d}'
    directory.mkdir(parents=True, exist_ok=False)
    tooling = directory / 'tooling'
    tooling.mkdir()
    shutil.copy2(Path(__file__), tooling / Path(__file__).name)
    shutil.copy2(root / 'scripts/construction/export_spec_definitions.lean', tooling / 'export_spec_definitions.lean')
    mapping = json.loads((work / args.map).read_text())
    groups = mapping if isinstance(mapping, list) else mapping['groups']
    assert len(groups) == 24 and len({g['rg_id'] for g in groups}) == 24
    names = [g['specification'] for g in groups]
    assert len(set(names)) == 24
    (directory / 'spec_map.json').write_text(json.dumps(mapping, indent=2) + '\n')
    snapshot = directory / 'candidate'
    snapshot.mkdir()
    for name in ['TDN', 'TDN.lean', 'lakefile.toml', 'lake-manifest.json', 'lean-toolchain']:
        dst = snapshot / name
        subprocess.run(['cp', '-cR', str(work / name), str(dst)], check=True)
    names_path = work / 'outputs' / f'interpreter-{args.round:03d}-names.txt'
    names_path.write_text('\n'.join(names) + '\n')
    exported = work / 'outputs' / f'interpreter-{args.round:03d}-definitions.json'
    exporter = work / 'scripts/construction/export_spec_definitions.lean'
    shutil.copy2(root / 'scripts/construction/export_spec_definitions.lean', exporter)
    wrapper = Path(args.exec_wrapper).resolve() if args.exec_wrapper else work.parent / 'constructor-exec'
    build = subprocess.run([str(wrapper), 'lake', 'build'], capture_output=True, text=True)
    (directory / 'build.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        raise RuntimeError('Candidate build failed before definition export; retained build.log')
    command = [str(wrapper), 'env', 'TDN_SPEC_NAMES=' + str(names_path), 'TDN_SPEC_EXPORT=' + str(exported), 'lake', 'env', 'lean', 'scripts/construction/export_spec_definitions.lean']
    result = subprocess.run(command, capture_output=True, text=True)
    (directory / 'export.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError('Definition export failed; retained export.log')
    for p in snapshot.rglob('*'):
        if p.is_file():
            assert digest(p) == digest(work / p.relative_to(snapshot)), 'Source changed during freeze'
    shutil.copy2(exported, directory / 'definitions.json')
    package = json.loads(exported.read_text())
    records = {d['name']: d for d in package['declarations']}
    blind = work.parent / f'interpreter-{args.round:03d}'
    blind.mkdir(exist_ok=False)
    (blind / 'input').mkdir()
    (blind / 'output').mkdir()
    shutil.copy2(exported, blind / 'input/definitions.json')
    sources = {g['source_file'] for g in groups}
    sources.update(args.definition_source)
    if (work / 'TDN/Targets/ComplianceModel.lean').exists():
        sources.add('TDN/Targets/ComplianceModel.lean')
    for source_name in sorted(sources):
        source = work / source_name
        if not source.resolve().is_relative_to((work / 'TDN').resolve()) or source.suffix != '.lean':
            raise ValueError('Interpreter sources must be Lean files under TDN/')
        text = source.read_text()
        if re.search(r'^\s*(?:(?:private|protected|noncomputable)\s+)*(?:theorem|lemma|example|axiom)\b', text, re.MULTILINE):
            continue
        if '/-' in text or any(line.lstrip().startswith('--') for line in text.splitlines()):
            continue
        destination = blind / 'input/sources' / source_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    target_names = []
    for index, name in enumerate(names, 1):
        pending, selected = [name], {}
        while pending:
            current = pending.pop()
            if current in selected or current not in records:
                continue
            selected[current] = records[current]
            pending.extend(records[current]['dependencies'])
        target = f'S{index:02d}'
        path = blind / 'input' / (target + '.json')
        path.write_text(json.dumps({'target': target, 'root': name, 'declarations': list(selected.values())}, indent=2, ensure_ascii=False) + '\n')
        target_names.append({'target': target, 'root': name, 'file': 'input/' + target + '.json'})
    (blind / 'input/targets.json').write_text(json.dumps(target_names, indent=2) + '\n')
    profile = work.parent / f'interpreter-{args.round:03d}.sb'
    denied = [Path.home() / 'Projects', Path.home() / '.codex']
    denied += [p for p in work.parent.iterdir() if p.is_dir() and p != blind]
    denied += [p for p in Path('/tmp').glob('tdn*') if p.is_dir() and p.resolve() != work.parent.resolve()]
    profile.write_text('(version 1)\n(allow default)\n(deny network*)\n' + ''.join(
        '(deny file-read* file-write* (subpath ' + json.dumps(str(p.resolve())) + '))\n'
        for p in denied
    ))
    wrapper = work.parent / f'interpreter-{args.round:03d}-exec'
    wrapper.write_text('#!/bin/bash\nset -eu\ncd ' + str(blind) + '\nexec /usr/bin/sandbox-exec -f ' + str(profile) + ' "$@"\n')
    wrapper.chmod(0o755)
    checks = {}
    constructor_requirements = work.parent / 'constructor/specs/requirement_groups.md'
    for label, path in [('original_rg', root / 'specs/requirement_groups.md'), ('constructor_rg', constructor_requirements), ('audit', root / '.lavish/rg-register-audit.html'), ('original_archive', root / 'archive/v1/TDN.lean')]:
        checked = subprocess.run([str(wrapper), 'cat', str(path)], capture_output=True, text=True)
        checks[label] = checked.returncode != 0 and 'Operation not permitted' in checked.stderr
    assert all(checks.values()), checks
    manifest = {'at': datetime.now(timezone.utc).isoformat(), 'round': args.round, 'workspace': str(blind), 'wrapper': str(wrapper), 'model': 'gpt-6.1-sol', 'effort': 'high', 'denial_checks': checks, 'source_hashes': {str(p.relative_to(snapshot)): digest(p) for p in snapshot.rglob('*') if p.is_file()}, 'tooling_hashes': {p.name: digest(p) for p in tooling.iterdir()}, 'blind_input_hashes': {str(p.relative_to(blind)): digest(p) for p in (blind / 'input').rglob('*') if p.is_file()}}
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'round_directory': str(directory), 'workspace': str(blind), 'wrapper': str(wrapper), 'declarations': len(records)}, indent=2))


if __name__ == '__main__':
    main()
