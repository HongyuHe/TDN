"""Expose source-bound native component inventory with failed observations explicit."""
import ast
import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require

CAPABILITIES = ['devices', 'runtime', 'accounts', 'key_access', 'time', 'unavailable', 'observations']
LEAN_VIEW = 'native_component_inventory'
SCOPE = 'Public native component runtime and access metadata sampled sequentially'
COLLECTOR_HASH = 'fe3a9d74bb86358c286eff3a26b64078e8ea734d255127b41aaacfeee6aa339a'
HOST = {'host-time-status':['timedatectl','status'],'host-time-show':['timedatectl','show'],
    'host-time-namespace':['readlink','/proc/self/ns/time'],'host-ntp':['chronyc','tracking']}


def parse(directory):
    root=Path(directory);digest=validate_files(root)
    source=(root/'collector.py').read_bytes()
    require(hashlib.sha256(source).hexdigest()==COLLECTOR_HASH,'Unreviewed native audit collector')
    tree=ast.parse(source)
    tables={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ['COMMON','VPN']:
            tables[node.targets[0].id]=ast.literal_eval(node.value)
    require(set(tables)=={'COMMON','VPN'},'Missing collector command inventory')
    spec=json.loads((root/'spec.json').read_text());devices={d['id']:d for d in spec['devices']}
    records=json.loads((root/'observations.json').read_text())['records']
    expected={(name,kind):['docker','exec',name,*command] for name,d in devices.items()
        for kind,command in (tables['COMMON'] | (tables['VPN'] if d['role'] in ['inner','outer'] else {})).items()}
    expected.update({(None,kind):command for kind,command in HOST.items()})
    require(len(records)==len(expected) and len({(r['device'],r['kind']) for r in records})==len(expected),'Incomplete or duplicate public audit')
    output={key:[] for key in ['runtime','accounts','key_access','time','unavailable']}
    for record in records:
        require(expected.get((record['device'],record['kind']))==record['command'],'Public audit command differs')
        value={'device':record['device'],'kind':record['kind'],'observation':record['id'],
            'available':record['returncode']==0,'startedAt':record['startedAt'],'endedAt':record['endedAt']}
        if record['returncode']:
            output['unavailable'].append(dict(value,returncode=record['returncode'],stderr=record['stderr']));continue
        kind,text=record['kind'],record['stdout']
        if kind=='accounts':
            users=[]
            for line in text.splitlines():
                parts=line.split(':');require(len(parts)==7 and parts[2].isdigit() and parts[3].isdigit(),'Unsupported passwd record')
                users.append({'login':parts[0],'uid':int(parts[2]),'gid':int(parts[3]),'home':parts[5],'shell':parts[6]})
            output['accounts'].append(dict(value,users=users))
        elif kind=='private-key-access':
            fields=text.strip().split(maxsplit=4)
            require(len(fields)==5 and all(f.isdigit() for f in fields[:4]) and fields[4]=='/etc/swanctl/private/key.pem','Unsupported private-key metadata')
            output['key_access'].append(dict(value,mode=fields[0],uid=int(fields[1]),gid=int(fields[2]),bytes=int(fields[3]),path=fields[4]))
        elif kind in ['credential-path-access','vici-socket-access','swanctl-commands']:
            output['key_access'].append(dict(value,text=text))
        elif kind.startswith('host-time') or kind in ['clock','time-namespace','host-ntp']:
            output['time'].append(dict(value,text=text))
        else:output['runtime'].append(dict(value,text=text))
    observations=[{'id':row['id'],'record':row} for row in records]
    report={'devices':[{'id':d['id'],'role':d['role']} for d in spec['devices']],**output,'observations':observations,
        'rawObservationIds':[r['id'] for r in records],'manifestSha256':digest,'projectionVersion':'native-component-audit-v1',
        'specSha256':hashlib.sha256((root/'spec.json').read_bytes()).hexdigest(),
        'scope':[SCOPE,'File metadata identifies access settings. It does not prove that every application API prevents key export.',
            'No private-key contents are read. Failed commands provide no negative fact. Host clock status remains implementation evidence.']}
    return {'runtime_backend':'native-linux-component-audit'},report


validated_experiment=parse


def query_experiment(directory,collection,category,device,offset,limit):
    manifest,report=parse(directory)
    return query_report(manifest,report,CAPABILITIES,collection,category,device,offset,limit)


def read_experiment_raw(directory,observation,stderr=False):
    _,report=parse(directory);rows=[r for r in report['observations'] if r['id']==observation]
    require(len(rows)==1,'Unknown native component observation')
    return rows[0]['record']['stderr' if stderr else 'stdout']


def export_experiment(directory,destination):
    _,report=parse(directory)
    return export_report(report,destination,LEAN_VIEW)
