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
        self.prefix="tcv3f13-"
        self.nodes=[]
        self.links=[]
        self.tunnels=[]
        self.commands=[]
        self.probes=[]
        self.started=utc()
        self.keyvalues=[]
        self.pending=[]
        self.code_hashes={"family_execution_v13.py":CODE_SHA256}
        binding={}
        for key,cmd in {"hostname":["hostname","-f"],"kernel":["uname","-a"],"boot_id":["cat","/proc/sys/kernel/random/boot_id"],"hardware_uuid":["cat","/sys/class/dmi/id/product_uuid"]}.items():
            result=self.run(cmd)
            binding[key]={"value":result.stdout.strip(),"observation_id":self.commands[-1]["id"]}
        (self.root/"worker-binding.json").write_text(json.dumps({"at":utc(),"binding":binding,"scope":"Contemporaneous worker observation from the actual collector process; namespace inode identities appear in each state capture."},indent=2)+"\n")
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
        r=self.run(["ping","-n","-c",3,"-W",1,"-s",64,destination],source,False)
        self.probes.append({"id":label,"source_device":source,"destination":destination,"expected_result":expect,"observed_result":"delivered" if r.returncode==0 else "no_reply" if r.returncode==1 else "collection_error","observation_id":self.commands[-1]["id"]})
    def state(self,label):
        values={}
        for node in self.nodes:
            name=node["id"]
            values[name]={}
            for peer in self.nodes:
                if peer["id"]!=name:self.run(["ip","netns","set",self.prefix+peer["id"],"auto"],name,False)
            self.run(["stat","-Lc","%i", "/var/run/netns/"+self.prefix+name])
            for key,cmd in {"interfaces":["ip","-j","-d","address"],"rules4":["ip","-j","-4","rule","show"],"rules6":["ip","-j","-6","rule","show"],"namespace":["readlink","/proc/self/ns/net"],"named_namespaces":["ip","-j","netns","list"],"peer_nsids":["ip","-j","netns","list-id"],"routes4":["ip","-j","-4","route","show","table","all"],"routes6":["ip","-j","-6","route","show","table","all"],"filters4":["iptables-save"],"filters6":["ip6tables-save"],"policies":["ip","xfrm","policy"],"xfrm":["ip","-s","xfrm","state","list","nokeys"],"macsec":["ip","-s","macsec","show"],"neighbors":["ip","-j","neighbor","show"],"nft":["nft","-a","-j","list","ruleset"]}.items():
                r=self.run(cmd,name,False)
                values[name][key]={"observation_id":self.commands[-1]["id"],"returncode":r.returncode,"value":r.stdout}
        (self.root/(label+".json")).write_text(json.dumps(values,indent=2)+"\n")
        return values
    def finish(self,error=None):
        if error is not None:error=self.sanitize(error)
        evidence={"schema_version":"csfc-mechanism-evidence/v1","configuration_id":self.name,"runtime_backend":"supplemental-Linux-network-namespaces-static-XFRM","started_at":self.started,"ended_at":utc(),"devices":self.nodes,"links":self.links,"tunnels":self.tunnels,"probes":self.probes,"error":error,"limitations":["Virtual namespace graph; no physical independence or product approval","Manually provisioned SAs do not establish IKE/MKA/certificate authentication","Test keys generated by Python secrets; no NSA KGS approval claim"]}
        (self.root/"evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
        (self.root/"commands.json").write_text(json.dumps(self.commands,indent=2)+"\n")
        (self.root/"collector.source.py").write_bytes(Path(__file__).read_bytes())
        files=[{"path":str(p.relative_to(self.root)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size} for p in sorted(self.root.iterdir()) if p.is_file()]
        (self.root/"manifest.json").write_text(json.dumps({"schema_version":"csfc-mechanism-evidence/v1","started_at":self.started,"ended_at":utc(),"configuration_id":self.name,"code_sha256":CODE_SHA256,"code_hashes":self.code_hashes,"files":files,"error":error},indent=2)+"\n")
        for node in reversed(self.nodes):
            subprocess.run(["ip","netns","delete",self.prefix+node["id"]],capture_output=True)
        print(json.dumps({"configuration":self.name,"error":error,"probes":self.probes}),flush=True)


def ipv4v6(root,red,gray,black):
    lab=Lab(root,"families-%s%s%s"%(red,gray,black))
    try:
        for n,r in [("HA","host"),("IA","inner"),("OA","outer"),("FA","outer-firewall"),("FB","outer-firewall"),("OB","outer"),("IB","inner"),("HB","host")]:
            lab.node(n,r,n[-1])
        rednets=["10.1.0.","10.2.0."] if red==4 else ["fd10:1::","fd10:2::"]
        graynets=["10.11.0.","10.21.0."] if gray==4 else ["fd20:1::","fd20:2::"]
        blacknets=["192.0.2.","192.0.3."] if black==4 else ["fd30:1::","fd30:2::"]
        rp=24 if red==4 else 64;gp=30 if gray==4 else 64;bp=30 if black==4 else 64
        middle="198.51.100." if black==4 else "fd30:3::"
        for site,idx in [("A",0),("B",1)]:
            rn=rednets[idx];gn=graynets[idx];bn=blacknets[idx];peer=1-idx
            lab.link("H"+site,"red","I"+site,"red",rn+"2/"+str(rp),rn+"1/"+str(rp),"red")
            lab.link("I"+site,"gray","O"+site,"gray",gn+"1/"+str(gp),gn+"2/"+str(gp),"gray")
            lab.link("O"+site,"black","F"+site,"inside",bn+"1/"+str(bp),bn+"2/"+str(bp),"black")
            lab.route("H"+site,rednets[peer]+"0/"+str(rp),rn+"1")
            lab.route("I"+site,rednets[peer]+"0/"+str(rp),gn+"2") if red==gray else lab.run(["ip","route","replace",rednets[peer]+"0/"+str(rp),"dev","gray"],"I"+site)
            lab.route("I"+site,graynets[peer]+"1/"+str(32 if gray==4 else 128),gn+"2")
            lab.route("O"+site,graynets[peer]+"1/"+str(32 if gray==4 else 128),bn+"2") if gray==black else lab.run(["ip","route","replace",graynets[peer]+"1/"+str(32 if gray==4 else 128),"dev","black"],"O"+site)
            lab.route("O"+site,blacknets[peer]+"1/"+str(32 if black==4 else 128),bn+"2")
        lab.link("FA","outside","FB","outside",middle+"1/"+str(bp),middle+"2/"+str(bp),"black")
        lab.route("FA",blacknets[1]+"0/"+str(bp),middle+"2")
        lab.route("FB",blacknets[0]+"0/"+str(bp),middle+"1")
        lab.esp("IA","IB",graynets[0]+"1",graynets[1]+"1",rednets[0]+"0/"+str(rp),rednets[1]+"0/"+str(rp),100,"inner")
        lab.esp("OA","OB",blacknets[0]+"1",blacknets[1]+"1",graynets[0]+"1/"+str(32 if gray==4 else 128),graynets[1]+"1/"+str(32 if gray==4 else 128),200,"outer")
        for node,family,inside,outside,reqid in [("IA",red,"red","gray",100),("IB",red,"red","gray",100),("OA",gray,"gray","black",200),("OB",gray,"gray","black",200)]:
            ipt="iptables" if family==4 else "ip6tables"
            lab.run([ipt,"-P","FORWARD","DROP"],node)
            lab.run([ipt,"-A","FORWARD","-i",inside,"-o",outside,"-m","policy","--dir","out","--pol","ipsec","--reqid",reqid,"-j","ACCEPT"],node)
            lab.run([ipt,"-A","FORWARD","-i",outside,"-o",inside,"-m","policy","--dir","in","--pol","ipsec","--reqid",reqid,"-j","ACCEPT"],node)
        for node in ["FA","FB"]:
            ipt="iptables" if black==4 else "ip6tables"
            lab.run([ipt,"-P","FORWARD","DROP"],node)
            for s,d in [(blacknets[0]+"1",blacknets[1]+"1"),(blacknets[1]+"1",blacknets[0]+"1")]:
                lab.run([ipt,"-A","FORWARD","-s",s,"-d",d,"-p","esp","-j","ACCEPT"],node)
        from gateway_header_policy_v5 import install
        install(lab,["IA","IB","OA","OB"])
        from family_source_policy_v13 import install
        install(lab,red,gray,black)
        time.sleep(1)
        lab.ping("HA",rednets[1]+"2","delivered","same-level-A-B")
        lab.ping("HB",rednets[0]+"2","delivered","same-level-B-A")
        for node in ["OA","OB"]:lab.run(["ip","link","set","black","mtu","1400"],node)
        for source,destination in [("HA",rednets[1]+"2"),("HB",rednets[0]+"2")]:
            for size,expect in [(1350,"size-rejected"),(1100,"delivered")]:
                result=lab.run(["ping","-n","-c","2","-W","1","-M","do","-s",str(size),destination],source,False)
                lab.probes.append({"id":"ordinary-MTU-"+source+"-"+str(size),"source_device":source,"destination":destination,"expected_result":expect,"observed_result":"delivered"if result.returncode==0 else"size-rejected","observation_id":lab.commands[-1]["id"],"scope":"Assigned-address ping with do-not-fragment request and1400-byte Outer Black MTU. Nonzero exit alone does not establish an ICMP/PTB transition; raw ping output and route state retain the reason."})
            lab.run(["ip","route","get",destination],source)
        lab.state("reduced-MTU")
        for node in ["OA","OB"]:lab.run(["ip","link","set","black","mtu","1500"],node)
        lab.state("stable-before")
        ipt="iptables" if black==4 else "ip6tables"
        block=[ipt,"-I","INPUT","1","-i","black","-p","icmp" if black==4 else "ipv6-icmp"]
        if black==6:block.extend(["--icmpv6-type","echo-request"])
        lab.run(block+["-j","DROP"],"OA")
        lab.ping("FA",blacknets[0]+"1","no_reply","temporary-black-icmp-denial")
        lab.state("temporary-black-icmp-denial")
        lab.run([ipt,"-D","INPUT",*block[4:],"-j","DROP"],"OA")
        lab.ping("FA",blacknets[0]+"1","delivered","ordinary-black-adjacent-restored")
        lab.run(["ip","xfrm","state","flush"],"IA")
        lab.ping("HA",rednets[1]+"2","no_reply","inner-SA-loss-fail-closed")
        lab.restore_inner()
        lab.ping("HA",rednets[1]+"2","delivered","restored-useful-traffic")
        lab.state("stable-after")
        lab.finish()
    except Exception as e:
        lab.finish(str(e))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    parser.add_argument("--families",default="all")
    args=parser.parse_args()
    choices=itertools.product([4,6],repeat=3) if args.families=="all" else [tuple(map(int,args.families))]
    for triple in choices:ipv4v6(args.output,*triple)

if __name__=="__main__":main()
