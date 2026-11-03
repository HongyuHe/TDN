"""Record public observations from an isolated EAP-TLS/MACsec experiment."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

CODE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def utc():
    return datetime.now(timezone.utc).isoformat()


class Lab:
    def __init__(self,root,name):
        self.root=Path(root)/name
        self.root.mkdir(parents=True,exist_ok=False)
        self.name=name
        self.prefix="tv31e-"
        self.nodes=[]
        self.links=[]
        self.tunnels=[]
        self.commands=[]
        self.probes=[]
        self.started=utc()
        self.keyvalues=[]
        self.pending=[]
        self.code_hashes={"eap_correlation_lab.py":CODE_SHA256}
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
    def ping(self,source,destination,expect,label):
        r=self.run(["ping","-n","-c",3,"-W",1,"-s",64,destination],source,False)
        self.probes.append({"id":label,"source_device":source,"destination":destination,"expected_result":expect,"observed_result":"delivered" if r.returncode==0 else "no_reply" if r.returncode==1 else "collection_error","observation_id":self.commands[-1]["id"]})
    def state(self,label):
        values={}
        for node in self.nodes:
            name=node["id"]
            values[name]={}
            for key,cmd in {"interfaces":["ip","-j","-d","address"],"namespace":["readlink","/proc/self/ns/net"],"rules4":["ip","-j","-4","rule","show"],"rules6":["ip","-j","-6","rule","show"],"routes4":["ip","-j","-4","route","show","table","all"],"routes6":["ip","-j","-6","route","show","table","all"],"filters4":["iptables-save"],"filters6":["ip6tables-save"],"policies":["ip","xfrm","policy"],"xfrm":["ip","-s","xfrm","state","list","nokeys"],"macsec":["ip","-s","macsec","show"]}.items():
                r=self.run(cmd,name,False)
                values[name][key]={"observation_id":self.commands[-1]["id"],"returncode":r.returncode,"value":r.stdout}
        (self.root/(label+".json")).write_text(json.dumps(values,indent=2)+"\n")
        return values
    def finish(self,error=None):
        if error is not None:error=self.sanitize(error)
        evidence={"schema_version":"csfc-mechanism-evidence/v1","configuration_id":self.name,"started_at":self.started,"ended_at":utc(),"devices":self.nodes,"links":self.links,"tunnels":self.tunnels,"probes":self.probes,"error":error,"limitations":["Virtual namespace graph; no physical independence or product approval","One instrumented authentication exchange per case; no universal implementation-conformance proof","Fresh experimental CA; no external PKI or product approval"]}
        (self.root/"evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
        (self.root/"commands.json").write_text(json.dumps(self.commands,indent=2)+"\n")
        files=[{"path":str(p.relative_to(self.root)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size} for p in sorted(self.root.iterdir()) if p.is_file()]
        (self.root/"manifest.json").write_text(json.dumps({"schema_version":"csfc-mechanism-evidence/v1","started_at":self.started,"ended_at":utc(),"configuration_id":self.name,"code_sha256":CODE_SHA256,"code_hashes":self.code_hashes,"files":files,"error":error},indent=2)+"\n")
        for node in reversed(self.nodes):
            subprocess.run(["ip","netns","delete",self.prefix+node["id"]],capture_output=True)
        print(json.dumps({"configuration":self.name,"error":error,"probes":self.probes}),flush=True)
