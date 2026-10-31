import hashlib,json
from pathlib import Path
from family_local_policy_v10 import install as install_local

def install(lab,red,gray,black):
    install_local(lab,red,gray,black)
    source=Path(__file__)
    lab.code_hashes[source.name]=hashlib.sha256(source.read_bytes()).hexdigest()
    (lab.root/source.name).write_bytes(source.read_bytes())
    captures={}
    for node in ['IA','IB','OA','OB']:
        index=0 if node.endswith('A')else 1
        peer=1-index
        rules=['add table inet EVA_SOURCE_V13','add chain inet EVA_SOURCE_V13 ingress { type filter hook prerouting priority -460; policy accept; }']
        def permit(iface,addr,reqid=None):
            family='ip6'if':'in addr else'ip'
            rule='add rule inet EVA_SOURCE_V13 ingress iifname "'+iface+'" '+family+' saddr '+addr
            if reqid is not None:rule+=' ipsec in reqid '+str(reqid)
            rules.append(rule+' counter accept')
        for link in lab.links:
            for i,endpoint in enumerate(link['endpoints']):
                name,iface=endpoint.split(':',1)
                if name!=node:continue
                own=link['addresses'][i];adjacent=link['addresses'][1-i]
                if not own or not adjacent:continue
                if iface=='red':
                    permit(iface,('10.1.0.0/24'if index==0 else'10.2.0.0/24')if red==4 else('fd10:1::/64'if index==0 else'fd10:2::/64'))
                else:permit(iface,adjacent.split('/')[0])
                if node.startswith('I')and iface=='gray':
                    permit(iface,('10.21.0.1'if index==0 else'10.11.0.1')if gray==4 else('fd20:2::1'if index==0 else'fd20:1::1'))
                    permit(iface,('10.2.0.0/24'if index==0 else'10.1.0.0/24')if red==4 else('fd10:2::/64'if index==0 else'fd10:1::/64'),100)
                if node.startswith('O')and iface=='black':
                    permit(iface,('192.0.3.1'if index==0 else'192.0.2.1')if black==4 else('fd30:2::1'if index==0 else'fd30:1::1'))
                    permit(iface,('10.21.0.1'if index==0 else'10.11.0.1')if gray==4 else('fd20:2::1'if index==0 else'fd20:1::1'),200)
                rules.append('add rule inet EVA_SOURCE_V13 ingress iifname "'+iface+'" ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } counter accept')
                rules.append('add rule inet EVA_SOURCE_V13 ingress iifname "'+iface+'" ip6 saddr ::/128 ip6 daddr ff02::1:ff00:0/104 ip6 hoplimit 255 icmpv6 type nd-neighbor-solicit counter accept')
                rules.append('add rule inet EVA_SOURCE_V13 ingress iifname "'+iface+'" meta nfproto { ipv4, ipv6 } counter drop')
        policy=lab.root/(node+'-source-policy.nft');policy.write_text('\n'.join(rules)+'\n')
        lab.run(['nft','-f',str(policy)],node)
        record=lab.run(['nft','-a','-j','list','table','inet','EVA_SOURCE_V13'],node)
        captures[node]={'observation_id':lab.commands[-1]['id'],'ruleset':json.loads(record.stdout)}
    for node in ['IA','IB','OA','OB']:
        lab.run(['ip','neighbor','flush','all'],node)
        for link in lab.links:
            for i,endpoint in enumerate(link['endpoints']):
                if endpoint.split(':')[0]!=node:continue
                peer=link['addresses'][1-i]
                if peer:lab.ping(node,peer.split('/')[0],'delivered','source-guard-adjacent-'+node+'-'+endpoint.split(':')[1])
    (lab.root/'source-policy-scope.json').write_text(json.dumps({
        'request':'C-GENERATED-RESPONSE-008',
        'phase':'Defensive configuration only. Copied-response hypothesis is unconfirmed and was not exercised.',
        'priority':-460,
        'ordering':'Before the existing IPv6 immediate-header gate at-450 and documented implementation-family defragmentation at-400; before route lookup and INPUT/FORWARD.',
        'sources':'Red ingress accepts its attached Red subnet. Other ingress accepts assigned adjacent or remote SA peer addresses. Decapsulated remote payload source prefixes additionally require incoming XFRM reqid100/200.',
        'NDP':'Only NS/NA link-local source with hop limit255, or DAD unspecified-source NS to solicited-node multicast, precedes the other-source IP drop.',
        'identity_limit':'Source-prefix validation is a routing boundary rule, not independent host authentication. The incoming IPsec requirement binds decapsulated source ranges to an actual security path.',
        'quote_limit':'No quoted-body parser is introduced. Source validation constrains pre-route errors; local output rules constrain exact response egress. Construction must separately establish protection provenance for a modeled quoted body.',
        'backend':'Actual nftables expressions and effective rules captured on Ubuntu6.8.0-138-generic worker. Upstream6.8 is an implementation-family reference, not asserted identical vendor source.',
        'rules':captures
    },indent=2)+'\n')
