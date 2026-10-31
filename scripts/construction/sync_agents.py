#!/usr/bin/env python3
"""Preserve agent outputs and intermediate histories without importing proofs."""
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[2]


def file_digest(path):
    result = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def capture_messages(run, state):
    start = state['started_at'][:19]
    date = state['started_at'][:10].replace('-', '/')
    directory = Path.home() / '.codex/sessions' / date
    sessions = sorted(directory.glob('*.jsonl'), key=lambda path: path.stat().st_mtime, reverse=True)[:8]
    count = 0
    targets = {'/root', 'evidence_v2', 'construction_v2', '/root/evidence_v2', '/root/construction_v2'}
    coordination_tools = {'send_message', 'spawn_agent', 'followup_task', 'interrupt_agent'}
    for path in sessions:
        for line in path.open():
            if 'agent_message' not in line and not any(name in line for name in coordination_tools):
                continue
            try:
                record = json.loads(line)
                payload = record.get('payload', {})
                name = payload.get('name', '')
                if record.get('timestamp', '')[:19] < start:
                    continue
                if payload.get('type') == 'agent_message':
                    if payload.get('author') not in targets or payload.get('recipient') not in targets:
                        continue
                    identifier = payload.get('id')
                    if not identifier:
                        continue
                    saved = {'at': record.get('timestamp'), 'source_session': path.stem,
                             'author': payload['author'], 'recipient': payload['recipient'],
                             'content': [{'type': item.get('type'), 'text': item['text']}
                                         for item in payload.get('content', [])
                                         if isinstance(item, dict) and isinstance(item.get('text'), str)]}
                    (run / 'communications' / (identifier + '.json')).write_text(json.dumps(saved, indent=2) + '\n')
                    count += 1
                    continue
                if payload.get('type') not in {'function_call', 'custom_tool_call'}:
                    continue
                if name.split('.')[-1] not in coordination_tools:
                    continue
                arguments = json.loads(payload.get('arguments', payload.get('input', '')))
            except (ValueError, TypeError):
                continue
            if arguments.get('target') not in targets and arguments.get('task_name') not in {'evidence_v2', 'construction_v2'}:
                continue
            identifier = payload.get('call_id')
            if not identifier:
                continue
            saved = {'at': record.get('timestamp'), 'source_session': path.stem, 'tool': name, 'arguments': arguments}
            (run / 'communications' / ('tool-' + identifier + '.json')).write_text(json.dumps(saved, indent=2) + '\n')
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reports-only', action='store_true')
    parser.add_argument('--new-history-only', action='store_true', help='Reuse previously copied immutable checkpoints when their manifests are unchanged.')
    args = parser.parse_args()
    pointer = json.loads((ROOT / 'data/construction/current.json').read_text())
    run = ROOT / 'data/construction' / pointer['directory']
    state = json.loads((run / 'session.json').read_text())
    updates = []
    blocked = []
    large_artifacts = []
    for actor, where in state['workspaces'].items():
        workspace = Path(where)
        for folder in ['outputs'] if args.reports_only else ['outputs', 'history']:
            if args.reports_only:
                paths = (workspace / folder).glob('*')
            elif folder == 'history' and args.new_history_only:
                paths = []
                for item in sorted((workspace / folder).iterdir()):
                    manifest = item / 'manifest.json'
                    saved = run / 'agents' / actor / item.relative_to(workspace) / 'manifest.json'
                    if item.is_dir() and manifest.is_file() and saved.is_file() and file_digest(manifest) == file_digest(saved):
                        continue
                    paths.extend(item.rglob('*') if item.is_dir() else [item])
            else:
                paths = (workspace / folder).rglob('*')
            for source in sorted(paths):
                if not source.is_file() or source.is_symlink():
                    continue
                relative = source.relative_to(workspace)
                if source.name.endswith(('.tar.gz', '.tar.zst')) and source.stat().st_size > 50_000_000:
                    digest = file_digest(source)
                    target = run / 'agents' / actor / relative
                    if not target.exists() or file_digest(target) != digest:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source, target)
                    if file_digest(target) != digest:
                        raise ValueError('Large artifact changed during capture: ' + str(relative))
                    large_artifacts.append({'actor': actor, 'path': str(target.relative_to(run)),
                                            'sha256': digest, 'bytes': source.stat().st_size,
                                            'git': 'Excluded binary; retained locally for replay.'})
                    continue
                content = source.read_bytes()
                if any(marker in content for marker in [b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----', b'ghp_']):
                    blocked.append({'actor': actor, 'path': str(relative), 'reason': 'possible secret; content not copied'})
                    continue
                digest = hashlib.sha256(content).hexdigest()
                target = run / 'agents' / actor / relative
                if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
                    continue
                version = run / 'checkpoints' / actor / digest / source.name
                version.parent.mkdir(parents=True, exist_ok=True)
                if not version.exists():
                    version.write_bytes(content)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                updates.append({'actor': actor, 'path': str(relative), 'sha256': digest, 'version': str(version.relative_to(run))})
    event = {'at': datetime.now(timezone.utc).isoformat(), 'actor': 'coordinator', 'kind': 'agent_artifact_sync', 'reports_only': args.reports_only, 'reuse_immutable_checkpoints': args.new_history_only, 'updates': updates, 'blocked': blocked}
    if updates or blocked:
        with (run / 'evolution/coordinator.jsonl').open('a') as handle:
            handle.write(json.dumps(event) + '\n')
    if large_artifacts:
        (run / 'validation/large-artifacts.json').write_text(json.dumps(large_artifacts, indent=2) + '\n')
    messages = capture_messages(run, state)
    print(json.dumps({'updated': len(updates), 'blocked': blocked, 'coordination_records': messages}))


if __name__ == '__main__':
    main()
