"""Retain raw observations and repair omitted Linux platform-interface metadata."""
import hashlib
import json
from pathlib import Path
import shutil
from common import BASE, write_json

root=BASE/'runs/20261112-blind-theory-01/snapshots'
for directory in sorted(root.glob('net-*')):
    source=directory/'native'
    target=directory/'native-normalized'
    if target.exists():
        continue
    snapshot=json.loads((source/'snapshot.json').read_text())
    manifest=json.loads((source/'manifest.json').read_text())
    expected=set(snapshot['scope']['expected_interface_ids'])
    missing=[i for i in snapshot['interfaces'] if i['id'] not in expected]
    assert missing and all(i['name'] in {'gre0','gretap0','erspan0'} and not i['observed_up'] and not i['addresses'] for i in missing)
    shutil.copytree(source,target)
    snapshot['scope']['expected_interface_ids'].extend(i['id'] for i in missing)
    snapshot['scope']['platform_interface_names']=['gre0','gretap0','erspan0']
    write_json(target/'snapshot.json',snapshot)
    for entry in manifest['files']:
        if entry['path']=='snapshot.json':
            raw=(target/'snapshot.json').read_bytes();entry.update(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
    write_json(target/'manifest.json',manifest)
    write_json(directory/'inventory-repair.json',{'source_snapshot_sha256':hashlib.sha256((source/'snapshot.json').read_bytes()).hexdigest(),
        'reason':'The collector omitted its platform-interface option. Retained raw observations show disabled, unaddressed kernel GRE template interfaces on every device. Add those already observed records to expected coverage; no observations or active interfaces are removed.',
        'added_expected_ids':[i['id'] for i in missing], 'raw_observations_unchanged':True})
