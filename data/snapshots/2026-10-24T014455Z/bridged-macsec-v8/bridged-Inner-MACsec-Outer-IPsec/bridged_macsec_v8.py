import argparse,hashlib,json,secrets,subprocess,time
from pathlib import Path
from pairing_execution_v7 import Lab as BaseLab,utc
class Lab(BaseLab):
    def __init__(self,root,name):
        super().__init__(root,name);self.prefix='tcv3e8-'
        for name in ['bridged_macsec_v8.py','opaque_ethernet_v8.py','pairing_headers_v7.py']:
            source=Path(__file__).with_name(name);self.code_hashes[name]=hashlib.sha256(source.read_bytes()).hexdigest();(self.root/name).write_bytes(source.read_bytes())
    def start_headers(self):
        self.capture_phase+=1
        for node in self.nodes:
            name=node["id"]
            cmd=["ip","netns","exec",self.prefix+name,"python3",str(Path(__file__).with_name("pairing_headers_v7.py")),"--output",str(self.root/("phase-"+str(self.capture_phase)+"-headers-"+name+".json"))]
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.captures.append((name,cmd,proc,utc(),self.capture_phase))
        time.sleep(0.4)

def transfer(lab,source,destination,tags,expected,label):
    if not lab.captures:lab.start_headers()
    macs={n:json.loads(lab.run(['ip','-j','link','show','red'],n).stdout)[0]['address']for n in [source,destination]}
    output=lab.root/(label+'.json');token=label
    common=['python3',str(Path(__file__).with_name('opaque_ethernet_v8.py')),'--interface','red','--source',macs[source],'--destination',macs[destination],'--tags',str(tags),'--token',token]
    argv=['ip','netns','exec',lab.prefix+destination,*common,'--mode','receive','--output',str(output)];started=utc();proc=subprocess.Popen(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+3
    while not output.with_suffix('.ready').exists()and proc.poll()is None and time.monotonic()<deadline:time.sleep(.02)
    assert output.with_suffix('.ready').exists(),'Receiver did not become ready'
    lab.run([*common,'--mode','send'],source);stdout,stderr=proc.communicate(timeout=5);row={'id':'cmd-%04d'%len(lab.commands),'started_at':started,'ended_at':utc(),'device_id':destination,'command':argv,'returncode':proc.returncode,'stdout':stdout,'stderr':stderr};lab.commands.append(row);assert proc.returncode==0
    result=json.loads(output.read_text());good=result['matches']and all(r['exact_expected_tags']for r in result['matches']);observed='delivered'if good else'no_reply'
    lab.probes.append({'id':label,'source_device':source,'destination_device':destination,'protected_vlan_tags':tags,'expected_result':expected,'observed_result':observed,'observation_id':row['id'],'application_observation':str(output.name)})
def restore_outer(lab):
    fresh={}
    for n in ['OA','OB']:lab.run(['ip','xfrm','state','flush'],n)
    for node,cmd in lab.pending:
        if node not in ['OA','OB']:continue
        replacement=[]
        for arg in cmd:
            if arg in lab.keyvalues:
                if arg not in fresh:fresh[arg]='0x'+secrets.token_hex(36);lab.keyvalues.append(fresh[arg])
                replacement.append(fresh[arg])
            else:replacement.append(arg)
        lab.run(replacement,node)

def run(root):
    inner="macsec";outer="ipsec";standalone=False
    lab=Lab(root,"bridged-Inner-MACsec-Outer-IPsec")
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
        from pairing_boundary_policy_v7 import install
        install(lab,inner,outer,standalone)
        hosts={n:json.loads(lab.run(['ip','-j','link','show','red'],n).stdout)[0]['address']for n in ['HA','HB']}
        for node in ['HA','HB']:
            lab.run(['ip','address','flush','dev','red'],node);lab.run(['ip','route','flush','table','main'],node)
        for node,index in [('IA',0),('IB',1)]:
            for port in ['red','macsec0']:lab.run(['ip','address','flush','dev',port],node)
            lab.run(['ip','route','flush','table','main'],node);lab.run(['sysctl','-qw','net.ipv4.ip_forward=0','net.ipv6.conf.all.forwarding=0'],node)
            lab.run(['ip','link','add','br_red0','type','bridge','stp_state','0','vlan_filtering','0','mcast_snooping','0'],node)
            for port in ['red','macsec0']:lab.run(['ip','link','set',port,'master','br_red0'],node)
            lab.run(['ip','link','set','br_red0','up'],node)
            for chain in ['INPUT','OUTPUT','FORWARD']:lab.run(['ebtables','-P',chain,'DROP'],node)
            for i,o,s,d in [('red','macsec0',hosts[['HA','HB'][index]],hosts[['HB','HA'][index]]),('macsec0','red',hosts[['HB','HA'][index]],hosts[['HA','HB'][index]])]:
                for proto in ['0x88b5','0x8100','0x88a8']:lab.run(['ebtables','-A','FORWARD','-i',i,'-o',o,'-s',s,'-d',d,'-p',proto,'-j','ACCEPT'],node)
        for node,index in [('OA',0),('OB',1)]:
            lab.run(['ebtables','-F','FORWARD'],node)
            for i,o,s in [('innerframes','l2tpeth0',hosts[['HA','HB'][index]]),('l2tpeth0','innerframes',hosts[['HB','HA'][index]])]:lab.run(['ebtables','-A','FORWARD','-i',i,'-o',o,'-s',s,'-p','0x88e5','-j','ACCEPT'],node)
        lab.state('bridged-before')
        for tags in [0,1,2]:
            transfer(lab,'HA','HB',tags,'delivered','opaque-'+str(tags)+'-A-B')
            transfer(lab,'HB','HA',tags,'delivered','opaque-'+str(tags)+'-B-A')
            lab.run(['ip','link','set','macsec0','down'],'IA')
            transfer(lab,'HA','HB',tags,'no_reply','opaque-'+str(tags)+'-Inner-loss')
            lab.run(['ip','link','set','macsec0','up'],'IA')
            transfer(lab,'HA','HB',tags,'delivered','opaque-'+str(tags)+'-Inner-restored')
            lab.run(['ip','xfrm','state','flush'],'OA')
            transfer(lab,'HA','HB',tags,'no_reply','opaque-'+str(tags)+'-Outer-loss')
            restore_outer(lab)
            transfer(lab,'HA','HB',tags,'delivered','opaque-'+str(tags)+'-Outer-restored')
        lab.state('bridged-after')
        (lab.root/'bridged-scope.json').write_text(json.dumps({'backend':'Supplemental namespace bridge plus actual manual Inner MACsec, L2TPv3 and Outer ESP','data_plane':'HA/HB and Inner data ports have no IPv4 addresses or main-table routes. Inner IP forwarding is disabled. Exact-source/destination Ethernet forwarding traverses br_red0 red/macsec0 only.','tags':'Zero, one and two VLAN tags are constructed inside original Red Ethernet frames. MACsec encrypts those tags; the physical Gray carrier exposes SecTAG only. Actual remote Ethernet recovery must match the exact tag stack and public payload digest.','scope':'Opaque EtherType0x88b5 is an experimental local-use data protocol. Positive finite cases, no MKA/IKE authentication or product approval. Kernel auxiliary VLAN metadata is used to reconstruct offloaded tag headers; no packet or ciphertext bodies are exported.','controls':'The two initial routed-boundary negatives precede the bridge transformation and remain labeled separately. The eighteen opaque-Ethernet controls apply to the final bridged arrangement.'},indent=2)+'\n')
        lab.finish()
    except Exception as exc:lab.finish(str(exc))
p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();run(a.output)
