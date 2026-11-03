"""Expose retained cover-sender settings, scheduled attempts and observed wire lengths."""
import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require

CAPABILITIES = ['devices', 'configurations', 'attempts', 'wire_observations', 'probes', 'observations', 'coverage']
LEAN_VIEW = 'cover_sender'
SCOPE = 'Fixed-size cover sender before the actual MACsec controlled port'
SOURCE_HASH = '0e431d829b3dadc643d04786e5c986b8a53fa3c8a1c69b381e616c1ecd2e0a27'


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    manifest = json.loads((root/'manifest.json').read_text())
    evidence = json.loads((root/'evidence.json').read_text())
    commands = json.loads((root/'commands.json').read_text())
    by_id = {r['id']:r for r in commands}
    require(len(by_id)==len(commands), 'Duplicate cover observation')
    require(hashlib.sha256((root/'macsec_cover_endpoint_v4.py').read_bytes()).hexdigest()==SOURCE_HASH and
            manifest['code_hashes']['macsec_cover_endpoint_v4.py']==SOURCE_HASH, 'Unreviewed cover implementation')
    configurations, attempts, frames = [], [], []
    for device in ['OA','OB']:
        ready = json.loads((root/(device+'-ready.json')).read_text())
        events = json.loads((root/(device+'-cover-events.json')).read_text())
        settings = events['settings']
        launches = [r for r in commands if r.get('device_id')==device and any(str(v).endswith('/macsec_cover_endpoint_v4.py') for v in r['command'])]
        require(len(launches)==1 and launches[0]['returncode']==0, 'Cover process execution not observed')
        command = launches[0]['command']
        defaults = {'--interface':'macsec0','--interval-ms':20,'--frame-body-bytes':512,'--queue-limit':64}
        for flag, default in defaults.items():
            value = command[command.index(flag)+1] if flag in command else default
            if isinstance(default,int):value=int(value)
            require(settings[flag[2:].replace('-','_')]==value and ready[flag[2:].replace('-','_')]==value, 'Launch and ready settings differ')
        require(ready['max_payload_bytes']==settings['frame_body_bytes']-24 and ready['max_payload_bytes']>0 and
                ready['ready_at_ns']==events['started_at_ns'] and json.loads(launches[0]['stdout'])==events['stats'], 'Cover accounting or runtime statistics differ')
        seq=events['send_events']
        require(seq and [r['sequence'] for r in seq]==list(range(1,len(seq)+1)) and
                all(a['at_ns']<=b['at_ns'] for a,b in zip(seq,seq[1:])), 'Cover attempt sequence is incomplete')
        for row in seq:
            require(row['body_length']==settings['frame_body_bytes'] and row['kind'] in ['data','dummy'] and
                    0<=row['queue_after_send']<=settings['queue_limit'], 'Cover attempt violates its recorded settings')
            attempts.append(dict(row,device=device,source=device+'-cover-events.json'))
        stats=events['stats']
        require(stats['data_frames_sent']+stats['dummy_frames_sent']+stats['send_errors']==len(seq), 'Successful and failed sends do not account for all attempts')
        configurations.append({'device':device,'interface':settings['interface'],'intervalMilliseconds':settings['interval_ms'],
            'frameBodyBytes':settings['frame_body_bytes'],'headerBytes':24,'maxPayloadBytes':ready['max_payload_bytes'],
            'queueLimit':settings['queue_limit'],'activeDuringCapture':True,'launchObservation':launches[0]['id'],
            'sourceSha256':SOURCE_HASH,'statistics':stats,'startedAtNs':events['started_at_ns'],'endedAtNs':events['ended_at_ns']})
    for path in sorted(root.glob('*-headers-*.json')):
        capture=json.loads(path.read_text())
        for index,row in enumerate(capture.get('frames',[])):
            header=row['headers']
            if header.get('ethertype') not in ['0x88b5','0x88e5']:continue
            frames.append({'id':path.name+':'+str(index),'source':path.name,'device':path.stem.split('-')[-1],
                'interface':row['interface'],'packetType':row['packet_type'],'atNs':row['at_ns'],
                'ethertype':header['ethertype'],'frameLength':header['frame_length'],'headers':header})
    report={'devices':evidence['devices'],'configurations':configurations,'attempts':attempts,'wire_observations':frames,
        'probes':evidence['probes'],'observations':[{'id':r['id'],'record':r} for r in commands],
        'rawObservationIds':list(by_id),'manifestSha256':manifest_hash,'projectionVersion':'cover-sender-v1',
        'coverage':[{'scope':SCOPE,'sourceCorrespondence':'Exact retained implementation and actual launch settings.',
            'timing':'Scheduled attempt records include software lag; no hard deadline or fairness assertion.',
            'sendErrors':'Retained explicitly. Each attempt log is written even if send fails; wire success is not inferred from the attempt.',
            'packetBytes':'Header observations retain decoded lengths. Full raw frames are unavailable in this capture.',
            'authority':'No approval or complete TRANSEC assurance inferred.'}], 'scope':[SCOPE]}
    return {'runtime_backend':evidence['runtime_backend']},report


validated_experiment=parse


def query_experiment(directory,collection,category,device,offset,limit):
    manifest,report=parse(directory)
    return query_report(manifest,report,CAPABILITIES,collection,category,device,offset,limit)


def read_experiment_raw(directory,observation,stderr=False):
    _,report=parse(directory)
    rows=[r for r in report['observations'] if r['id']==observation]
    require(len(rows)==1,'Unknown cover observation')
    return rows[0]['record'].get('stderr' if stderr else 'stdout','')


def export_experiment(directory,destination):
    _,report=parse(directory)
    return export_report(report,destination,LEAN_VIEW)
