#!/usr/bin/env python3
"""Central RADIUS EAP-TLS and negotiated MACsec, with reversed peer roles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import time
from eap_delay_lab_v18 import Lab

SCRIPT_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",required=True);a=p.parse_args();base=Path(a.root)
    for reverse in [False,True]:
        name="eap-tls-"+("reverse" if reverse else "forward")+"-v18"
        lab=Lab(base/"exports",name);lab.prefix="tcv3e18-";lab.code_hashes["eap_tls_v18.py"]=SCRIPT_SHA256;procs=[];handles=[];error=None
        private=base/"private"/name;private.mkdir(parents=True,exist_ok=False);private.chmod(0o700)
        openssl_config=private/'openssl.cnf'
        openssl_config.write_text('openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_configuration\n[ssl_configuration]\nsystem_default = tls_system_default\n[tls_system_default]\nMinProtocol = TLSv1.3\nMaxProtocol = TLSv1.3\nCiphersuites = TLS_AES_256_GCM_SHA384\nGroups = MLKEM1024\n')
        os.environ['OPENSSL_CONF']=str(openssl_config)
        (lab.root/'openssl.cnf.public').write_bytes(openssl_config.read_bytes())
        radius_secret=secrets.token_hex(24);lab.keyvalues.append(radius_secret)
        auth="P1" if reverse else "P0";supp="P0" if reverse else "P1"
        def launch(node,exe,conf):
            log=private/(node+".log");h=log.open("w");handles.append(h)
            proc=__import__("subprocess").Popen(["ip","netns","exec",lab.prefix+node,str(exe),"-dd","-t",str(conf)],stdout=h,stderr=__import__("subprocess").STDOUT)
            procs.append(proc);time.sleep(.5)
            if proc.poll() is not None:raise RuntimeError(node+" daemon exited "+str(proc.returncode))
        try:
            lab.run(["openssl","version","-a"])
            lab.run(["uname","-a"])
            lab.run(["readlink","/proc/self/ns/net"])
            for n,r in [("P0","MACsec-peer"),("P1","MACsec-peer"),("AS","central-authentication-server")]:lab.node(n,r,"central" if n in [auth,"AS"] else "remote")
            lab.link("P0","eth0","P1","eth0",zone="gray-data")
            for node in ["P0","P1"]:lab.run(["ip","link","set","eth0","allmulticast","on","promisc","on"],node)
            lab.link(auth,"control","AS","eth0","10.88.0.1/30","10.88.0.2/30",zone="gray-management")
            for capture_node in ["P0","P1"]:
                packet_program="import socket,json,time;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('eth0',0));s.settimeout(60)\nwhile True:\n b,info=s.recvfrom(65535)\n if len(b)>=18 and b[12:14] in [bytes.fromhex('888e'),bytes.fromhex('88e5')]:print(json.dumps({'at':time.time(),'source':b[6:12].hex(),'destination':b[:6].hex(),'ethertype':b[12:14].hex(),'length':len(b),'eapol_type':b[15] if b[12:14]==bytes.fromhex('888e') else None,'macsec_pn':int.from_bytes(b[16:20],'big') if b[12:14]==bytes.fromhex('88e5') and len(b)>=20 else None,'pkttype':info[2]}),flush=True)\n"
                h=(private/(capture_node+"-headers.log")).open("w");handles.append(h)
                proc=__import__("subprocess").Popen(["ip","netns","exec",lab.prefix+capture_node,"python3","-u","-c",packet_program],stdout=h,stderr=h);procs.append(proc)
            for n in [auth,supp,"AS"]:lab.run(["sysctl","-qw","net.ipv4.ip_forward=0"],n)
            lab.run(["openssl","genpkey","-algorithm","ML-DSA-87","-out",str(private/"ca.key")])
            lab.run(["openssl","req","-new","-x509","-key",str(private/"ca.key"),"-out",str(private/"ca.pem"),"-days","1","-subj","/CN=EAP-Test-CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign"])
            for who,eku in [("as","serverAuth"),("peer","clientAuth")]:
                lab.run(["openssl","genpkey","-algorithm","ML-DSA-87","-out",str(private/(who+".key"))])
                lab.run(["openssl","req","-new","-key",str(private/(who+".key")),"-out",str(private/(who+".csr")),"-subj","/CN="+who+".msc.test"])
                (private/(who+".ext")).write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage="+eku+"\nsubjectAltName=DNS:"+who+".msc.test\n")
                lab.run(["openssl","x509","-req","-in",str(private/(who+".csr")),"-CA",str(private/"ca.pem"),"-CAkey",str(private/"ca.key"),"-CAcreateserial","-days","1","-extfile",str(private/(who+".ext")),"-out",str(private/(who+".pem"))])
                lab.run(["openssl","x509","-in",str(private/(who+".pem")),"-noout","-text"])
            (private/"clients").write_text("10.88.0.1 "+radius_secret+"\n");(private/"users").write_text('"peer.msc.test" TLS\n')
            server="driver=none\ninterface=eth0\nssid=eap-as\neap_server=1\neap_user_file="+str(private/"users")+"\nca_cert="+str(private/"ca.pem")+"\nserver_cert="+str(private/"as.pem")+"\nprivate_key="+str(private/"as.key")+"\nradius_server_clients="+str(private/"clients")+"\nradius_server_auth_port=1812\nlogger_stdout=-1\nlogger_stdout_level=1\n"
            server+="openssl_ciphers=DEFAULT\nopenssl_ecdh_curves=MLKEM1024\ntls_flags=[DISABLE-TLSv1.0][DISABLE-TLSv1.1][DISABLE-TLSv1.2][ENABLE-TLSv1.3]\n"
            host="driver=macsec_linux\ninterface=eth0\nssid=msc-auth\nieee8021x=1\nuse_pae_group_addr=1\neap_server=0\nown_ip_addr=10.88.0.1\nnas_identifier="+auth+"\nauth_server_addr=10.88.0.2\nauth_server_port=1812\nauth_server_shared_secret="+radius_secret+"\nmacsec_policy=1\nmacsec_integ_only=0\nmacsec_csindex=1\nmacsec_replay_protect=1\nmacsec_replay_window=0\nmka_priority=0\nlogger_stdout=-1\nlogger_stdout_level=1\n"
            client="ap_scan=0\neapol_version=3\nnetwork={\n key_mgmt=IEEE8021X\n eap=TLS\n identity=\"peer.msc.test\"\n ca_cert=\""+str(private/"ca.pem")+"\"\n client_cert=\""+str(private/"peer.pem")+"\"\n private_key=\""+str(private/"peer.key")+"\"\n domain_match=\"as.msc.test\"\n eapol_flags=0\n macsec_policy=1\n macsec_csindex=1\n macsec_replay_protect=1\n macsec_replay_window=0\n mka_priority=1\n}\n"
            client=client.replace(" eap=TLS\n"," eap=TLS\n phase1=\"tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_2=1 tls_disable_tlsv1_3=0\"\n openssl_ciphers=\"DEFAULT\"\n")
            for who,conf in [("AS",server),(auth,host),(supp,client)]:
                (private/(who+".conf")).write_text(conf)
                (lab.root/(who+".conf.public")).write_text(conf.replace(radius_secret,"[REDACTED_RADIUS_SECRET]"))
            hostap=base/"hostap-pq-delay-auth/hostapd-2.12/hostapd/hostapd"
            launch("AS",hostap,private/"AS.conf");launch(auth,hostap,private/(auth+".conf"))
            log=private/(supp+".log");h=log.open("w");handles.append(h)
            proc=__import__("subprocess").Popen(["ip","netns","exec",lab.prefix+supp,str(base/"hostap-pq-delay-auth/wpa_supplicant-2.12/wpa_supplicant/wpa_supplicant"),"-dd","-t","-Dmacsec_linux","-ieth0","-c",str(private/(supp+".conf"))],stdout=h,stderr=__import__("subprocess").STDOUT);procs.append(proc)
            for attempt in range(90):
                ready=[]
                for node in ["P0","P1"]:
                    interfaces=json.loads(lab.run(["ip","-j","-d","link"],node).stdout)
                    ready.append(any(i.get("linkinfo",{}).get("info_kind")=="macsec" for i in interfaces))
                if all(ready):break
                time.sleep(.5)
            for idx,node in enumerate(["P0","P1"]):
                lab.run(["ip","-s","macsec","show"],node)
                ports=json.loads(lab.run(["ip","-j","-d","link"],node).stdout)
                iface=next((i["ifname"] for i in ports if i.get("linkinfo",{}).get("info_kind")=="macsec"),None)
                if not iface:raise RuntimeError("No MACsec interface at "+node)
                lab.run(["ip","addr","add","10.92.0.%d/30"%(idx+1),"dev",iface],node);lab.run(["ip","link","set",iface,"up"],node)
            for sak_attempt in range(60):
                installed=[]
                for node in ["P0","P1"]:
                    status=lab.run(["ip","-s","macsec","show"],node).stdout
                    installed.append("state on" in status and "RXSC:" in status)
                if all(installed):break
                time.sleep(.5)
            for node in ["P0","P1"]:
                lab.run(["ip","-s","-d","link","show"],node)
                lab.run(["cat","/proc/net/packet"],node)
            lab.ping("P0","10.92.0.2","delivered","EAP-derived-MKA-traffic")
            lab.state("before-data-delay")
            for cmd in [["tc","qdisc","add","dev","eth0","root","handle","1:","prio","bands","3"],["tc","filter","add","dev","eth0","parent","1:","protocol","0x88e5","prio","1","u32","match","u32","0","0","flowid","1:3"],["tc","qdisc","add","dev","eth0","parent","1:3","handle","30:","netem","delay","3000ms"]]:lab.run(cmd,"P0")
            r=lab.run(["ping","-n","-c","3","-W","4","-i","0.2","10.92.0.2"],"P0",False)
            lab.probes.append({"id":"EAP-derived-three-second-data-delay","source_device":"P0","destination":"10.92.0.2","expected_result":"no_reply","observed_result":"delivered" if r.returncode==0 else "no_reply" if r.returncode==1 else "collection_error","observation_id":lab.commands[-1]["id"]})
            for node in ["P0","P1"]:lab.run(["ip","-s","macsec","show"],node)
            lab.run(["tc","-s","qdisc","show","dev","eth0"],"P0")
            lab.run(["tc","qdisc","replace","dev","eth0","parent","1:3","handle","30:","netem","delay","100ms"],"P0")
            lab.ping("P0","10.92.0.2","delivered","EAP-derived-100ms-data-delay")
            lab.run(["tc","qdisc","del","dev","eth0","root"],"P0")
            lab.ping("P0","10.92.0.2","delivered","EAP-derived-restored-useful-traffic")
            lab.ping("P1","10.92.0.1","delivered","EAP-reverse-direction-before-delay")
            for cmd in [["tc","qdisc","add","dev","eth0","root","handle","1:","prio","bands","3"],["tc","filter","add","dev","eth0","parent","1:","protocol","0x88e5","prio","1","u32","match","u32","0","0","flowid","1:3"],["tc","qdisc","add","dev","eth0","parent","1:3","handle","30:","netem","delay","3000ms"]]:lab.run(cmd,"P1")
            r=lab.run(["ping","-n","-c","3","-W","4","-i","0.2","10.92.0.1"],"P1",False)
            lab.probes.append({"id":"EAP-reverse-direction-three-second-delay","source_device":"P1","destination":"10.92.0.1","expected_result":"no_reply","observed_result":"delivered" if r.returncode==0 else "no_reply" if r.returncode==1 else "collection_error","observation_id":lab.commands[-1]["id"]})
            for node in ["P0","P1"]:lab.run(["ip","-s","macsec","show"],node)
            lab.run(["tc","qdisc","replace","dev","eth0","parent","1:3","handle","30:","netem","delay","100ms"],"P1")
            lab.ping("P1","10.92.0.1","delivered","EAP-reverse-direction-100ms-delay")
            lab.run(["tc","qdisc","del","dev","eth0","root"],"P1")
            lab.ping("P1","10.92.0.1","delivered","EAP-reverse-direction-restored-useful")
            lab.state("stable-after")
        except Exception as exc:error=str(exc)
        finally:
            for proc in procs:
                proc.terminate()
                try:proc.wait(timeout=3)
                except Exception:proc.kill();proc.wait()
            for h in handles:h.close()
            for log in private.glob("*.log"):lab.run(["cat",str(log)],check=False)
            (lab.root/"case.json").write_text(json.dumps({"source_case_id":"NET-023-C04","authentication":"EAP-TLS via central RADIUS AS with negotiated MKA","authenticator":auth,"supplicant":supp,"script_sha256":SCRIPT_SHA256,"limitations":["Experimental objective EAP-TLS: ML-DSA-87 certificates and TLS1.3 MLKEM1024 group pinning. Effective negotiated algorithms must be checked independently of configuration. Both supplicant and authenticator functions are tested in separate arrangements; no simultaneous-operation requirement is invented","Test CA and RADIUS secret do not establish external PKI approval","AS has one Gray management attachment and no Red attachment"]},indent=2)+"\n")
            (lab.root/"collector.source.py").write_bytes(Path(__file__).read_bytes())
            (lab.root/"eap_delay_lab_v18.py").write_bytes(Path(__file__).with_name("eap_delay_lab_v18.py").read_bytes())
            lab.finish(error)

if __name__=="__main__":main()
