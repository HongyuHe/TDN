import hashlib,json
from pathlib import Path
from gateway_header_policy_v4 import install as install_raw

def install_early(lab,nodes):
    rules={}
    for node in nodes:
        lab.run(['nft','--version'],node)
        lab.run(['nft','add','table','ip6','EVA6_BEFORE_DEFRAG'],node)
        for hook in ['prerouting','output']:
            lab.run(['nft','add','chain','ip6','EVA6_BEFORE_DEFRAG',hook,'{ type filter hook '+hook+' priority -450; policy accept; }'],node)
            lab.run(['nft','add','rule','ip6','EVA6_BEFORE_DEFRAG',hook,'ip6','nexthdr','!=','{ 6, 17, 50, 58 }','counter','drop'],node)
        r=lab.run(['nft','-a','-j','list','table','ip6','EVA6_BEFORE_DEFRAG'],node);rules[node]={'observation_id':lab.commands[-1]['id'],'ruleset':json.loads(r.stdout)}
    lab.code_hashes['gateway_header_policy_v5.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (lab.root/'gateway_header_policy_v5.py').write_bytes(Path(__file__).read_bytes())
    (lab.root/'early-header-policy.json').write_text(json.dumps({'source_clauses':['MSC-PF-12'],'devices':nodes,'field':'Literal immediate IPv6 Next Header','allowed_values':[6,17,50,58],'hook_priority':-450,'defragmentation_priority':-400,'raw_priority':-300,'rules':rules,'scope':'Owned namespace IPv6 prerouting and output, before netfilter defragmentation. The original raw check remains present. Priority ordering and kernel behavior are separately source-bound. The gate intentionally excludes immediate Fragment Header 44 rather than accepting its reconstructed upper-layer protocol.'},indent=2)+'\n')

def install(lab,nodes):
    install_raw(lab,nodes)
    install_early(lab,nodes)
