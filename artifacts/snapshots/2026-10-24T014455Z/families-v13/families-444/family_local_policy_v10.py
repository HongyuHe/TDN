import hashlib,json
from pathlib import Path

def install(lab,red,gray,black):
    source=Path(__file__)
    lab.code_hashes[source.name]=hashlib.sha256(source.read_bytes()).hexdigest()
    (lab.root/source.name).write_bytes(source.read_bytes())
    lab.state('before-local-policy')
    plan=[]
    for node in ['IA','IB','OA','OB']:
        for tool in ['iptables','ip6tables']:
            for chain in ['INPUT','OUTPUT','FORWARD']:
                lab.run([tool,'-P',chain,'DROP'],node)
            for chain,flag in [('INPUT','-i'),('OUTPUT','-o')]:
                lab.run([tool,'-A',chain,flag,'lo','-j','ACCEPT'],node)
        for link in lab.links:
            endpoints=link['endpoints']
            for index,endpoint in enumerate(endpoints):
                name,iface=endpoint.split(':',1)
                if name!=node:continue
                own=link['addresses'][index]
                other=link['addresses'][1-index]
                if not own or not other:continue
                local=own.split('/')[0];peer=other.split('/')[0]
                v6=':' in local;tool='ip6tables'if v6 else'iptables'
                types=['echo-request','echo-reply','destination-unreachable','time-exceeded','parameter-problem']
                if v6:types+=['packet-too-big']
                for chain,flag,src,dst in [('INPUT','-i',peer,local),('OUTPUT','-o',local,peer)]:
                    for kind in types:
                        lab.run([tool,'-A',chain,flag,iface,'-s',src,'-d',dst,'-p','ipv6-icmp'if v6 else'icmp','--icmpv6-type'if v6 else'--icmp-type',kind,'-j','ACCEPT'],node)
                if v6:
                    for chain,flag in [('INPUT','-i'),('OUTPUT','-o')]:
                        for kind in ['neighbor-solicitation','neighbor-advertisement']:
                            for src in [own,'fe80::/10']:
                                for dst in [local+'/128',peer+'/128','fe80::/10','ff02::/16']:
                                    lab.run(['ip6tables','-A',chain,flag,iface,'-s',src,'-d',dst,'-p','ipv6-icmp','--icmpv6-type',kind,'-m','hl','--hl-eq','255','-j','ACCEPT'],node)
                        lab.run(['ip6tables','-A',chain,flag,iface,'-s','::/128','-d','ff02::1:ff00:0/104','-p','ipv6-icmp','--icmpv6-type','neighbor-solicitation','-m','hl','--hl-eq','255','-j','ACCEPT'],node)
                plan.append({'device':node,'interface':iface,'local':own,'adjacent_peer':other,'icmp':'Exact assigned adjacent-peer pair and interface; explicit echo and error types. NDP only on IPv6 attachment, hop limit255 and scoped source/destination ranges.'})
        family=gray if node.startswith('I')else black
        local=('10.11.0.1'if node=='IA'else'10.21.0.1')if family==4 and node.startswith('I')else('fd20:1::1'if node=='IA'else'fd20:2::1')if node.startswith('I')else('192.0.2.1'if node=='OA'else'192.0.3.1')if family==4 else('fd30:1::1'if node=='OA'else'fd30:2::1')
        peer=('10.21.0.1'if node=='IA'else'10.11.0.1')if family==4 and node.startswith('I')else('fd20:2::1'if node=='IA'else'fd20:1::1')if node.startswith('I')else('192.0.3.1'if node=='OA'else'192.0.2.1')if family==4 else('fd30:2::1'if node=='OA'else'fd30:1::1')
        iface='gray'if node.startswith('I')else'black';tool='iptables'if family==4 else'ip6tables'
        for chain,flag,src,dst in [('INPUT','-i',peer,local),('OUTPUT','-o',local,peer)]:
            lab.run([tool,'-A',chain,flag,iface,'-s',src,'-d',dst,'-p','esp','-j','ACCEPT'],node)
    for node in ['IA','IB','OA','OB']:
        lab.run(['ip','neighbor','flush','all'],node)
    for item in plan:
        peer=item['adjacent_peer'].split('/')[0]
        lab.ping(item['device'],peer,'delivered','assigned-adjacent-'+item['device']+'-'+item['interface'])
    lab.state('after-local-policy')
    (lab.root/'local-policy-scope.json').write_text(json.dumps({
        'request':'C-GENERATED-RESPONSE-008',
        'status':'Defensive policy hardening; proposed copied-response behavior was not tested or confirmed.',
        'defaults':'Both IP families INPUT/OUTPUT/FORWARD DROP on all four VPN gateways.',
        'permits':plan,
        'ESP':'Local ESP only on actual outside interface with exact local and remote SA endpoints.',
        'forwarding':'Existing reqid100/200, interface-bound IPsec forwarding permits retained; other-family forwarding has no permit.',
        'exceptions':'No arbitrary Red-source echo, UDP500, ICMP-error or protocol-only permit. Error delivery is restricted to the exact assigned adjacent peer and attachment.',
        'PMTU_scope':'Explicit local ICMP error types include IPv6 packet-too-big and IPv4 destination-unreachable, with exact adjacent endpoints and interface. The new collection does not claim an active PMTU transition. A routed authority beyond the adjacent peer is not enabled by these finite rules.',
        'NDP_scope':'NDP is limited to configured IPv6 attachment prefixes or link-local sources, interface, NS/NA types, hop limit255 and local/peer/link-local/multicast destination scopes. DAD source:: may send NS to solicited-node multicast.',
        'control_scope':'Ordinary assigned-address adjacent pings and bidirectional protected Red connectivity are checked after neighbor-cache flush. No forged or crafted packet experiment runs.',
        'hypothesis':'Linux weak-host copied-response escape remains unconfirmed. Formal checks must inspect complete effective local hooks and response provenance rather than infer universal safety from finite pings.'
    },indent=2)+'\n')
