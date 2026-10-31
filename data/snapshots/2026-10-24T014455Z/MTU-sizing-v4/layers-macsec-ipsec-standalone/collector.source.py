#!/usr/bin/env python3
"""Additional Linux MSC realizations for mixed families and layer pairings."""
import argparse
from datetime import datetime,timezone
import hashlib
import itertools
import json
from pathlib import Path
import secrets
import re
import subprocess
import time


CODE_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def utc():
    return datetime.now(timezone.utc).isoformat()


class Lab:
    def __init__(self,root,name):
        self.root=Path(root)/name
        self.root.mkdir(parents=True,exist_ok=False)
        self.name=name
        self.prefix="tcv3mt4-"
        self.captures=[]
        self.capture_phase=0
        self.nodes=[]
        self.links=[]
        self.tunnels=[]
        self.commands=[]
        self.probes=[]
        self.started=utc()
        self.keyvalues=[]
        self.pending=[]
        self.code_hashes={"mtu_sizing_v4.py":CODE_SHA256,"pairing_headers_v6.py":hashlib.sha256(Path(__file__).with_name("pairing_headers_v6.py").read_bytes()).hexdigest()}
    def sanitize(self,value):
        text=str(value)
        for key in self.keyvalues:text=text.replace(key,"[REDACTED_TEST_KEY]")
        text=re.sub(r'(?m)^([^\n]*hexdump[^\n]*:)[^\n]*$',r'\1 [REDACTED_HEXDUMP]',text)
        lines=[];continuation=False
        for line in text.splitlines(keepends=True):
            if continuation and re.match(r'^\s+(?:[0-9a-fA-F]{2}\s+){4,}',line):
                lines.append('     [REDACTED_HEXDUMP_CONTINUATION]\n')
                continue
            continuation='hexdump' in line and '[REDACTED_HEXDUMP]' in line
            lines.append(line)
        return ''.join(lines)
    def run(self,cmd,node=None,check=True):
        args=["ip","netns","exec",self.prefix+node,*map(str,cmd)] if node else list(map(str,cmd))
        begin=utc()
        try:r=subprocess.run(args,text=True,capture_output=True,timeout=15)
        except Exception as exc:raise RuntimeError(self.sanitize(exc)) from None
        safe=[]
        for word in args:
            safe.append("[REDACTED_TEST_KEY]" if word in self.keyvalues else word)
        text=self.sanitize(r.stdout)
        for key in self.keyvalues:
            text=text.replace(key,"[REDACTED_TEST_KEY]")
        record={"id":"cmd-%04d"%len(self.commands),"started_at":begin,"ended_at":utc(),"command":safe,"device_id":node,"returncode":r.returncode,"stdout":text,"stderr":self.sanitize(r.stderr)}
        self.commands.append(record)
        if check and r.returncode:
            raise RuntimeError(json.dumps(record))
        return r
    def node(self,name,role,site="",level="L1"):
        self.run(["ip","netns","add",self.prefix+name])
        self.nodes.append({"id":name,"role":role,"site":site,"security_level_id":level,"namespace":self.prefix+name,"physical_independence":"unavailable"})
        self.run(["ip","link","set","lo","up"],name)
        self.run(["sysctl","-qw","net.ipv4.ip_forward=1","net.ipv6.conf.all.forwarding=1","net.ipv4.conf.all.rp_filter=0","net.ipv4.conf.default.rp_filter=0"],name)
    def link(self,a,ai,b,bi,aa=None,ba=None,zone="gray"):
        ix=len(self.links)
        x=self.prefix.replace("-","")[:8]+"x%02d"%ix;y=self.prefix.replace("-","")[:8]+"y%02d"%ix
        self.run(["ip","link","add",x,"type","veth","peer","name",y])
        for old,node,new,addr in [(x,a,ai,aa),(y,b,bi,ba)]:
            self.run(["ip","link","set",old,"netns",self.prefix+node])
            self.run(["ip","link","set",old,"name",new],node)
            self.run(["ip","link","set",new,"mtu","1500","up"],node)
            if addr:
                self.run(["ip","address","add",addr,"dev",new],node)
        self.links.append({"endpoints":[a+":"+ai,b+":"+bi],"relation":"veth","zone":zone,"addresses":[aa,ba],"physical_claim_supported":False})
    def route(self,node,dst,via,dev=None):
        cmd=["ip","route","replace",dst,"via",via]
        if dev:cmd.extend(["dev",dev])
        self.run(cmd,node)
    def esp(self,a,b,local,remote,ls,rs,reqid,layer):
        k1="0x"+secrets.token_hex(36);k2="0x"+secrets.token_hex(36)
        self.keyvalues.extend([k1,k2])
        for node,src,dst,key,spi in [(a,local,remote,k1,reqid*10+1),(b,local,remote,k1,reqid*10+1),(a,remote,local,k2,reqid*10+2),(b,remote,local,k2,reqid*10+2)]:
            cmd=["ip","xfrm","state","add","src",src,"dst",dst,"proto","esp","spi",spi,"reqid",reqid,"mode","tunnel","flag","af-unspec","replay-window",32,"aead","rfc4106(gcm(aes))",key,128]
            self.run(cmd,node)
            self.pending.append((node,cmd))
        for node,src,dst,ts,peer_ts in [(a,local,remote,ls,rs),(b,remote,local,rs,ls)]:
            self.run(["ip","xfrm","policy","add","dir","out","src",ts,"dst",peer_ts,"tmpl","src",src,"dst",dst,"proto","esp","reqid",reqid,"mode","tunnel"],node)
            for direction in ["in","fwd"]:
                self.run(["ip","xfrm","policy","add","dir",direction,"src",peer_ts,"dst",ts,"tmpl","src",dst,"dst",src,"proto","esp","reqid",reqid,"mode","tunnel"],node)
        self.tunnels.append({"id":layer,"mechanism":"IPsec","layer":layer,"endpoints":[a,b],"local":local,"remote":remote,"selectors":[ls,rs],"mode":"tunnel","algorithm":"AES-GCM-256","replay_window":32,"authentication":"manual test SA provisioning; no IKE/authentication claim"})
    def restore_inner(self):
        fresh={}
        for node in ["IA","IB"]:self.run(["ip","xfrm","state","flush"],node)
        for node,cmd in self.pending:
            if node not in ["IA","IB"]:continue
            replacement=[]
            for arg in cmd:
                if arg in self.keyvalues:
                    if arg not in fresh:
                        fresh[arg]="0x"+secrets.token_hex(36)
                        self.keyvalues.append(fresh[arg])
                    replacement.append(fresh[arg])
                else:replacement.append(arg)
            self.run(replacement,node)
    def macsec(self,a,b,ai,bi,local,remote,layer):
        self.run(["modprobe","macsec"])
        k1=secrets.token_hex(32);k2=secrets.token_hex(32)
        self.keyvalues.extend([k1,k2])
        macs={}
        for node,iface,key,keyid in [(a,ai,k1,"01"),(b,bi,k2,"02")]:
            port=json.loads(self.run(["ip","-j","link","show",iface],node).stdout)[0]
            macs[node]=port["address"]
            self.run(["ip","link","add","link",iface,"name","macsec0","type","macsec","port",1,"encrypt","on","protect","on","validate","strict","replay","on","window",0,"cipher","gcm-aes-256"],node)
            self.run(["ip","macsec","add","macsec0","tx","sa",0,"pn",1,"on","key",keyid,key],node)
        for node,peer,key,keyid in [(a,b,k2,"02"),(b,a,k1,"01")]:
            self.run(["ip","macsec","add","macsec0","rx","port",1,"address",macs[peer]],node)
            self.run(["ip","macsec","add","macsec0","rx","port",1,"address",macs[peer],"sa",0,"pn",1,"on","key",keyid,key],node)
            self.run(["ip","link","set","macsec0","up"],node)
        for node,addr in [(a,local),(b,remote)]:
            self.run(["ip","address","add",addr,"dev","macsec0"],node)
        self.tunnels.append({"id":layer,"mechanism":"MACsec","layer":layer,"endpoints":[a,b],"local":local,"remote":remote,"algorithm":"GCM-AES-256","replay_window":0,"validate":"strict","encrypt":True,"protect":True,"authentication":"manual test SAK provisioning; MKA and CAK authentication not established"})
    def l2tp(self,a,b,local,remote,ai,bi):
        for node,l,r,tid,ptid,sid,psid,iface in [(a,local,remote,10,20,100,200,ai),(b,remote,local,20,10,200,100,bi)]:
            self.run(["ip","l2tp","add","tunnel","tunnel_id",tid,"peer_tunnel_id",ptid,"encap","udp","local",l,"remote",r,"udp_sport",1701,"udp_dport",1701],node)
            self.run(["ip","l2tp","add","session","tunnel_id",tid,"session_id",sid,"peer_session_id",psid,"name","l2tpeth0"],node)
            self.run(["ip","link","add","br0","type","bridge"],node)
            for port in [iface,"l2tpeth0"]:
                self.run(["ip","link","set",port,"master","br0"],node)
                self.run(["ip","link","set",port,"up"],node)
            self.run(["ip","link","set","br0","up"],node)
        self.tunnels.append({"id":"encapsulation","mechanism":"L2TPv3-over-UDP","layer":"between-inner-and-outer","endpoints":[a,b],"local":local,"remote":remote,"udp_port":1701})
    def ping(self,source,destination,expect,label):
        if not self.captures:self.start_headers()
        r=self.run(["ping","-n","-c",3,"-W",1,"-s",64,destination],source,False)
        self.probes.append({"id":label,"source_device":source,"destination":destination,"expected_result":expect,"observed_result":"delivered" if r.returncode==0 else "no_reply" if r.returncode==1 else "collection_error","observation_id":self.commands[-1]["id"]})
    def start_headers(self):
        self.capture_phase+=1
        for node in self.nodes:
            name=node["id"]
            cmd=["ip","netns","exec",self.prefix+name,"python3",str(Path(__file__).with_name("pairing_headers_v6.py")),"--output",str(self.root/("phase-"+str(self.capture_phase)+"-headers-"+name+".json"))]
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.captures.append((name,cmd,proc,utc(),self.capture_phase))
        time.sleep(0.4)
    def stop_headers(self,label):
        for name,cmd,proc,started,phase in self.captures:
            proc.terminate()
            stdout,stderr=proc.communicate(timeout=10)
            record={"id":"cmd-%04d"%len(self.commands),"started_at":started,"ended_at":utc(),"command":cmd,"device_id":name,"returncode":proc.returncode,"stdout":self.sanitize(stdout),"stderr":self.sanitize(stderr),"scope":"Field-only AF_PACKET parser. No packet payload or ciphertext bytes are serialized.","capture_phase":phase}
            self.commands.append(record)
            (self.root/(label+"-headers-"+name+".json")).write_text(json.dumps(record,indent=2)+"\n")
        self.captures=[]
    def state(self,label):
        self.stop_headers(label)
        values={}
        host={}
        for key,cmd in {"hostname":["hostname","-f"],"kernel":["uname","-a"],"kernel_build":["cat","/proc/version"],"boot_id":["cat","/proc/sys/kernel/random/boot_id"],"worker_uuid":["cat","/sys/class/dmi/id/product_uuid"],"ip_version":["ip","-Version"],"iptables_version":["iptables","--version"],"nft_version":["nft","--version"],"tcpdump_version":["tcpdump","--version"]}.items():
            r=self.run(cmd,None,False);host[key]={"observation_id":self.commands[-1]["id"],"returncode":r.returncode,"value":r.stdout}
        (self.root/(label+"-host.json")).write_text(json.dumps(host,indent=2)+"\n")
        for node in self.nodes:
            name=node["id"];values[name]={}
            for peer in self.nodes:
                if peer["id"]!=name:self.run(["ip","netns","set",self.prefix+peer["id"],"auto"],name,False)
            cmds={"interfaces":["ip","-j","-d","address"],"links":["ip","-s","-j","-d","link","show"],"namespace":["readlink","/proc/self/ns/net"],"namespace_inode":["stat","-Lc","%i","/var/run/netns/"+self.prefix+name],"named_namespaces":["ip","-j","netns","list"],"peer_nsids":["ip","-j","netns","list-id"],"rules4":["ip","-j","-4","rule","show"],"rules6":["ip","-j","-6","rule","show"],"routes4":["ip","-j","-4","route","show","table","all"],"routes6":["ip","-j","-6","route","show","table","all"],"filters4":["iptables-save","-c"],"filters6":["ip6tables-save","-c"],"policies":["ip","-s","xfrm","policy"],"xfrm":["ip","-s","xfrm","state","list","nokeys"],"macsec":["ip","-s","macsec","show"],"bridge_links":["bridge","-j","-d","link","show"],"bridge_vlans":["bridge","-j","-d","vlan","show"],"bridge_fdb":["bridge","-j","-d","fdb","show"],"nft_ruleset":["nft","-j","list","ruleset"],"ebtables":["ebtables-save"],"bridge_netfilter":["sh","-c","for f in /proc/sys/net/bridge/* /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding; do test -f \"$f\" && printf '%s=' \"$f\" && cat \"$f\"; done"],"l2tp_tunnels":["ip","l2tp","show","tunnel"],"l2tp_sessions":["ip","l2tp","show","session"],"tunnels4":["ip","-d","tunnel","show"],"tunnels6":["ip","-6","-d","tunnel","show"],"tc":["sh","-c","for p in /sys/class/net/*; do d=${p##*/}; echo interface=$d; tc -j -s qdisc show dev \"$d\"; tc -j -s filter show dev \"$d\" ingress; tc -j -s filter show dev \"$d\" egress; done"]}
            for key,cmd in cmds.items():
                r=self.run(cmd,name,False);values[name][key]={"observation_id":self.commands[-1]["id"],"returncode":r.returncode,"value":self.sanitize(r.stdout)}
        (self.root/(label+".json")).write_text(json.dumps(values,indent=2)+"\n")
        return values
    def finish(self,error=None):
        if self.captures:self.stop_headers("interrupted")
        if error is not None:error=self.sanitize(error)
        evidence={"schema_version":"csfc-mechanism-evidence/v1","configuration_id":self.name,"runtime_backend":"supplemental-linux-netns-static-routes","started_at":self.started,"ended_at":utc(),"devices":self.nodes,"links":self.links,"tunnels":self.tunnels,"probes":self.probes,"error":error,"limitations":["Virtual namespace graph; no physical independence or product approval","Manually provisioned SAs do not establish IKE/MKA/certificate authentication","Test keys generated by Python secrets; no NSA KGS approval claim"]}
        (self.root/"collector.source.py").write_bytes(Path(__file__).read_bytes())
        (self.root/"pairing_headers_v6.py").write_bytes(Path(__file__).with_name("pairing_headers_v6.py").read_bytes())
        (self.root/"evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
        (self.root/"commands.json").write_text(json.dumps(self.commands,indent=2)+"\n")
        files=[{"path":str(p.relative_to(self.root)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size} for p in sorted(self.root.iterdir()) if p.is_file()]
        (self.root/"manifest.json").write_text(json.dumps({"schema_version":"csfc-mechanism-evidence/v1","started_at":self.started,"ended_at":utc(),"configuration_id":self.name,"runtime_backend":"supplemental-linux-netns-static-routes","code_sha256":CODE_SHA256,"code_hashes":self.code_hashes,"files":files,"error":error},indent=2)+"\n")
        for node in reversed(self.nodes):
            subprocess.run(["ip","netns","delete",self.prefix+node["id"]],capture_output=True)
        print(json.dumps({"configuration":self.name,"error":error,"probes":self.probes}),flush=True)


def pairing(root,inner,outer,standalone=False):
    lab=Lab(root,"layers-"+inner+"-"+outer+("-standalone" if standalone else "-integrated"))
    try:
        for n,r in [("HA","host"),("IA","inner"),("OA","outer"),("OB","outer"),("IB","inner"),("HB","host")]:
            lab.node(n,r,n[-1])
        lab.link("HA","red","IA","red","10.1.0.2/24","10.1.0.1/24","red")
        lab.link("HB","red","IB","red","10.2.0.2/24","10.2.0.1/24","red")
        lab.route("HA","10.2.0.0/24","10.1.0.1")
        lab.route("HB","10.1.0.0/24","10.2.0.1")
        if outer=="macsec":
            lab.node("BF","outer-ethernet-firewall")
            lab.link("OA","black","BF","p1",zone="black")
            lab.link("OB","black","BF","p2",zone="black")
            lab.run(["ip","link","add","br0","type","bridge"],"BF")
            for iface in ["p1","p2"]:lab.run(["ip","link","set",iface,"master","br0"],"BF")
            lab.run(["ip","link","set","br0","up"],"BF")
            lab.run(["ebtables","-P","FORWARD","DROP"],"BF")
            lab.run(["ebtables","-A","FORWARD","-p","0x88e5","-j","ACCEPT"],"BF")
            lab.macsec("OA","OB","black","black","10.90.0.1/30","10.90.0.2/30","outer")
        else:
            lab.node("FA","outer-firewall","A");lab.node("FB","outer-firewall","B")
            lab.link("OA","black","FA","inside","192.0.2.1/30","192.0.2.2/30","black")
            lab.link("OB","black","FB","inside","192.0.3.1/30","192.0.3.2/30","black")
            lab.link("FA","outside","FB","outside","198.51.100.1/30","198.51.100.2/30","black")
            lab.route("OA","default","192.0.2.2");lab.route("OB","default","192.0.3.2")
            lab.route("FA","192.0.3.0/30","198.51.100.2");lab.route("FB","192.0.2.0/30","198.51.100.1")
            for node in ["FA","FB"]:
                lab.run(["iptables","-P","FORWARD","DROP"],node)
                for src,dst in [("192.0.2.1","192.0.3.1"),("192.0.3.1","192.0.2.1")]:
                    lab.run(["iptables","-A","FORWARD","-s",src,"-d",dst,"-p","esp","-j","ACCEPT"],node)
        if inner=="ipsec":
            lab.link("IA","gray","OA","gray","10.11.0.1/30","10.11.0.2/30")
            lab.link("IB","gray","OB","gray","10.21.0.1/30","10.21.0.2/30")
            lab.route("IA","10.2.0.0/24","10.11.0.2");lab.route("IB","10.1.0.0/24","10.21.0.2")
            lab.route("IA","10.21.0.1/32","10.11.0.2");lab.route("IB","10.11.0.1/32","10.21.0.2")
            if outer=="macsec":
                lab.route("OA","10.21.0.1/32","10.90.0.2");lab.route("OB","10.11.0.1/32","10.90.0.1")
            lab.esp("IA","IB","10.11.0.1","10.21.0.1","10.1.0.0/24","10.2.0.0/24",100,"inner")
            if outer=="ipsec":lab.esp("OA","OB","192.0.2.1","192.0.3.1","10.11.0.1/32","10.21.0.1/32",200,"outer")
        else:
            ends=["EA","EB"] if standalone else ["OA","OB"]
            if standalone:
                lab.node("EA","encapsulator","A");lab.node("EB","encapsulator","B")
                lab.link("EA","uplink","OA","gray","10.11.0.1/30","10.11.0.2/30")
                lab.link("EB","uplink","OB","gray","10.21.0.1/30","10.21.0.2/30")
                lab.route("EA","10.21.0.1/32","10.11.0.2");lab.route("EB","10.11.0.1/32","10.21.0.2")
                encips=["10.11.0.1","10.21.0.1"]
                if outer=="macsec":
                    lab.route("OA","10.21.0.1/32","10.90.0.2");lab.route("OB","10.11.0.1/32","10.90.0.1")
            elif outer=="macsec":encips=["10.90.0.1","10.90.0.2"]
            else:
                encips=["10.11.0.2","10.21.0.2"]
                lab.run(["ip","addr","add",encips[0]+"/32","dev","lo"],"OA")
                lab.run(["ip","addr","add",encips[1]+"/32","dev","lo"],"OB")
            lab.link("IA","gray",ends[0],"innerframes")
            lab.link("IB","gray",ends[1],"innerframes")
            if outer=="ipsec":lab.esp("OA","OB","192.0.2.1","192.0.3.1",encips[0]+"/32",encips[1]+"/32",200,"outer")
            lab.l2tp(ends[0],ends[1],encips[0],encips[1],"innerframes","innerframes")
            lab.macsec("IA","IB","gray","gray","10.60.0.1/30","10.60.0.2/30","inner")
            lab.route("IA","10.2.0.0/24","10.60.0.2");lab.route("IB","10.1.0.0/24","10.60.0.1")
        time.sleep(1)
        from pairing_defensive_policy_v3 import install
        install(lab,inner,outer,standalone)

        lab.state("before-sizing")
        for node in ["OA","OB"]:lab.run(["ip","link","set","black","mtu","1400"],node)
        lab.start_headers()
        diagnostics=[]
        for source,dest in [("HA","10.2.0.2"),("HB","10.1.0.2")]:
            result=lab.run(["ping","-n","-c","2","-W","1","-M","do","-s","1300",dest],source,False)
            diagnostics.append({"source":source,"destination":dest,"payload_bytes":1300,"returncode":result.returncode,"observation_id":lab.commands[-1]["id"],"scope":"Ordinary assigned-address before-sizing diagnostic; delivery or failure is retained without a required result."})
        lab.state("reduced-underlay-before-sizing")
        for node in ["HA","HB","IA","IB"]:lab.run(["ip","link","set","red","mtu","1100"],node)
        for node in ["IA","IB"]:lab.run(["ip","link","set","gray","mtu","1200"],node)
        if inner=="macsec":
            for node in ["IA","IB"]:lab.run(["ip","link","set","macsec0","mtu","1100"],node)
            for node in ["EA","EB"]:lab.run(["ip","link","set","uplink","mtu","1200"],node)
        lab.start_headers()
        for source,dest in [("HA","10.2.0.2"),("HB","10.1.0.2")]:
            for size,expect in [(1072,"delivered"),(1073,"size-rejected")]:
                result=lab.run(["ping","-n","-c","3","-W","1","-M","do","-s",str(size),dest],source,False)
                lab.probes.append({"id":"sized-ordinary-"+source+"-"+str(size),"source_device":source,"destination":dest,"expected_result":expect,"observed_result":"delivered"if result.returncode==0 else"size-rejected","observation_id":lab.commands[-1]["id"]})
        lab.state("configured-sizing")
        if inner=="ipsec":lab.run(["ip","xfrm","state","flush"],"IA")
        else:lab.run(["ip","link","set","macsec0","down"],"IA")
        lab.ping("HA","10.2.0.2","no_reply","sized-Inner-loss")
        if inner=="ipsec":lab.restore_inner()
        else:
            lab.run(["ip","link","set","macsec0","up"],"IA")
            lab.route("IA","10.2.0.0/24","10.60.0.2")
        lab.ping("HA","10.2.0.2","delivered","sized-restoration")
        lab.state("stable-sized-after")
        (lab.root/"sizing-scope.json").write_text(json.dumps({
            "source_clauses":["MSC-SR-23","MSC-IR-2"],
            "interpretation":"Configure IPv4 external Gray packet MTU or MACsec external frame sizing with actual nested overhead considered. IPv6 PMTU is separately represented by IPv6-PMTU-v4.",
            "settings":{"Outer_Black_MTU":1400,"Inner_Gray_carrier_MTU":1200,"Red_IP_MTU":1100,"Inner_MACsec_plaintext_MTU":1100 if inner=="macsec"else None,"standalone_encapsulator_Gray_MTU":1200 if standalone else None},
            "ordinary_controls":"Only assigned-address kernel ping is generated.1072-byte ICMP payload plus28-byte IPv4/ICMP headers fits1100.1073 is locally rejected. Header capture retains actual Outer ESP lengths and fragmentation metadata.",
            "before_diagnostics":diagnostics,
            "limitations":["Finite maximum-size controls and fixed geometry do not prove every possible padding/algorithm/frame format or arbitrary future MTU change.","Manual static SAs and supplemental namespaces do not establish MKA/IKE authentication, native FRR/OVS or product approval.","No IPv6, alternate L2TP cookie, arbitrary Ethernet payload or jumbo-frame guarantee is supplied."]
        },indent=2)+"\n")
        lab.finish()
    except Exception as exc:lab.finish(str(exc))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    pairing(args.output,"macsec","ipsec",True)

if __name__=="__main__":main()
