#!/usr/bin/env python3
"""Extend conventional DNS controls with exact IPv6 and PF state observations."""
import argparse,hashlib,json,subprocess
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--device-prefix',default='ND');p.add_argument('--guest-port-base',type=int,default=22222);a=p.parse_args();root=Path(a.root);out=root/'exports/native-DNS-hardening-v10';out.mkdir();records=[];error=None
def utc():return datetime.now(timezone.utc).isoformat()
def run(argv,check=True):
    begin=utc();r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=40)
    assert '-----BEGIN PRIVATE KEY-----'not in r.stdout and'-----BEGIN EC PRIVATE KEY-----'not in r.stdout
    records.append({'id':'dns8-%04d'%len(records),'started_at':begin,'ended_at':utc(),'command':list(map(str,argv)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    if check and r.returncode:raise RuntimeError(json.dumps(records[-1]))
    return r
def ex(node,*cmd,check=True):return run(['docker','exec',node,*cmd],check)
def ssh(i,cmd,check=True):return run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-p',a.guest_port_base+i,'root@127.0.0.1',cmd],check)
probe="""import socket,json,sys
p=sys.argv[1];s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM if p=='udp' else socket.SOCK_STREAM);s.settimeout(1)
try:
 if p=='udp':s.sendto(b'owned-conventional-DNS-egress-probe',('::1',53));s.recvfrom(2048)
 else:s.connect(('::1',53))
 print(json.dumps({'transport':p,'result':'unexpected-response-or-connect'}));raise SystemExit(3)
except OSError as e:print(json.dumps({'transport':p,'result':'rejected-or-no-reply','errno':e.errno,'error':str(e),'destination':'[::1]:53'}))
"""
try:
    spec=json.loads((root/'scripts/profiles/native-os-diversity-v3.json').read_text());devices=[d['id']for d in spec['devices']if not d['id'].startswith((a.device_prefix+'_I_',a.device_prefix+'_R_'))]
    assert len(devices)==7
    for node in devices:
        ex(node,'uname','-a');run(['docker','inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.HostConfig.NetworkMode}}',node])
        for cmd in [['ip','-j','address'],['ip','-j','-6','route','show','table','all'],['ip6tables-save','-c'],['iptables-save','-c'],['cat','/etc/resolv.conf'],['cat','/etc/nsswitch.conf'],['cat','/etc/os-release'],['ls','-l','/lib/ld-musl-x86_64.so.1','/lib/x86_64-linux-gnu/libc.so.6'],['getconf','GNU_LIBC_VERSION'],['ldd','--version'],['ss','-H','-lntu'],['ps','-eo','pid,comm'],['getent','hosts','www.example.com']]:ex(node,*cmd,check=False)
        for protocol in ['udp','tcp']:
            if ex(node,'ip6tables','-C','OUTPUT','-p',protocol,'--dport','53','-j','REJECT',check=False).returncode:ex(node,'ip6tables','-I','OUTPUT','1','-p',protocol,'--dport','53','-j','REJECT')
        ex(node,'sysctl','net.ipv6.conf.all.disable_ipv6','net.ipv6.conf.lo.disable_ipv6')
        ex(node,'sysctl','-w','net.ipv6.conf.lo.disable_ipv6=0')
        ex(node,'ip','-6','address','replace','::1/128','dev','lo')
        ex(node,'ip','-j','-6','address','show','dev','lo')
        ex(node,'ip6tables-save','-c')
        for protocol in ['udp','tcp']:
            r=ex(node,'python3','-c',probe,protocol,check=False);records[-1].update({'probe':'Linux-IPv6-'+protocol+'53-'+node,'expected_result':'rejected-or-no-reply','observed_result':'rejected-or-no-reply'if r.returncode==0 and'rejected-or-no-reply'in r.stdout else'collection-error-or-allowed'})
        ex(node,'ip6tables-save','-c')
    for i in [0,1]:
        for cmd in ['freebsd-version -kru','drill -h','ifconfig -a','netstat -rn -f inet6','pfctl -si','pfctl -ss -vv','pfctl -sr -vv','cat /etc/pf.conf','cat /etc/resolv.conf','cat /etc/nsswitch.conf','ldd /usr/bin/getent','ls -l /lib/libc.so.7','sha256 /lib/libc.so.7','sockstat -46l','ps -axo pid,comm','sysrc pf_enable nuageinit_enable local_unbound_enable named_enable resolvconf_enable']:
            ssh(i,cmd,check=False)
        states=ssh(i,'pfctl -ss').stdout
        records[-1].update({'scope':'Complete current PF states; state records are retained independently of rule ordering. No current DNS state is inferred absent without examining this output.','state_table_empty':not states.strip()})
        for protocol in ['udp','tcp']:
            import shlex
            r=ssh(i,'drill -6 '+('-t 'if protocol=='tcp'else'')+'@::1 www.example.com',check=False);records[-1].update({'probe':'FreeBSD-IPv6-'+protocol+'53-'+str(i),'expected_result':'rejected-or-no-reply','observed_result':'rejected-or-no-reply'if r.returncode==1 and'Error'in r.stderr+r.stdout else'collection-error-or-allowed'})
        ssh(i,'pfctl -si');ssh(i,'pfctl -ss -vv');ssh(i,'pfctl -sr -vv')
    for src,dst in [(a.device_prefix+'_R_A1','10.2.1.10'),(a.device_prefix+'_R_B1','10.1.1.10')]:
        r=ex(src,'ping','-n','-c','3','-W','1',dst,check=False);records[-1].update({'probe':'protected-data-after-dual-family-DNS-'+src,'expected_result':'delivered','observed_result':'delivered'if r.returncode==0 else'no-reply'})
except Exception as e:error=str(e)
finally:
    (out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
    (out/'observations.json').write_text(json.dumps({'at':utc(),'records':records,'error':error,'scope':['Seven selected native Linux network devices retain complete before/after IPv6 OUTPUT rules, actual interfaces/routes, libc identity, resolver/NSS files and listening sockets/processes. New leading UDP53/TCP53 REJECT rules extend the prior IPv4 prefix controls.','Two actual FreeBSD Inners retain effective enabled PF state, complete state tables, local addresses, full rules/config and libc/socket inventories. Existing source-self rules cover conventional TCP/UDP53; no arbitrary encrypted-DNS restriction is asserted. Current state presence is an independent condition and must be checked from retained records.','The original v8 FreeBSD Python probes fail because that guest does not install Python. The v9 helper uses the already installed drill tool with explicit IPv6 and UDP/TCP selection. The earlier Linux loopback probes encountered disabled IPv6 and did not increment rule counters. The v10 helper explicitly enables only IPv6 loopback and assigns ::1/128 before testing. External interface IPv6 settings are unchanged. All final IPv6 probes target the actual loopback IPv6 address ::1. Rule counters before/after distinguish the active rejection match from lack of a listening server. No externally routed IPv6 path is claimed. Positive nested Red traffic is separately tested in both directions.','Musl-based routers identify musl 1.2.5 through the loader diagnostic; GNU getconf and ldd version-query failures are retained. An nsswitch hosts line alone is not asserted to change musl resolver behavior. Actual empty resolver files, packet filters and listening-service inventory remain independent observations. Host root, Docker, guest-root configuration and key provisioning remain trusted controls. The service/resolver inventories are point observations. Default accounts, organizational policies, all future applications and remote boot defaults remain separate clauses.']},indent=2)+'\n')
    (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n')
    print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
