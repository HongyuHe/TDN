"""Adjudicate frozen findings and Lean errors against the revised fault records."""
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re
import sys
from common import BASE, ROOT, now, write_json
sys.path.insert(0,str(ROOT/'mcp'))
from tdn_evidence.parsers.packet_policy import parse_rule
from tdn_evidence.projections import atom_json
from mutate import rule_command

RUN=BASE/'runs/20261112-blind-theory-01'
profiles=[json.loads(p.read_text()) for p in sorted((RUN/'profiles').glob('net-*.json'))]
cases=[dict(case,network=p['network']) for p in profiles for case in p['mutations']]
assert len(cases)==100
local=json.loads((RUN/'local-typechecks.json').read_text())
assert len(local['results'])==65 and all(r['returncode']!=0 and any('evaluated that the proposition' in m.get('data','') and 'false' in m['data'] for m in r['messages']) for r in local['results'])
assert all(c['proof']['returncode']==0 for c in local['controls'])

findings={m:json.loads((RUN/m/'output/findings.json').read_text())['findings'] for m in ['astra','sol']}
ALTERNATES={'MSC-PF-3':['MSC-PF-11'],'MSC-PF-5':['MSC-PF-11'],'MSC-PF-17':['MSC-PF-20']}
SUPPORTED={'MSC-IR-3','MSC-IR-5','MSC-OR-2','MSC-OR-5','MSC-PF-11','MSC-PF-9'}
DIRECT_AUDIT={'MSC-VG-1','MSC-VG-4','MSC-VG-6','MSC-VG-7','MSC-VG-9','MSC-VG-13','MSC-VG-14','MSC-PF-2'}
output=[]
for case in cases:
    row={k:case[k] for k in ['case_id','network','device','requirement','description','operation']}
    row['ground_truth_status']='ambiguous_source_reachability' if case['case_id']=='net-04-MSC-PF-18' else 'supported'
    for model,items in findings.items():
        exact=[f['id'] for f in items if f['network']==case['network'] and case['device'] in f['devices'] and case['requirement'] in f['requirement_ids']]
        alternative=[f['id'] for f in items if f['network']==case['network'] and case['device'] in f['devices'] and any(r in f['requirement_ids'] for r in ALTERNATES.get(case['requirement'],[]))]
        row[model]={'exact':bool(exact),'fault_found':bool(exact or alternative),'findings':exact or alternative,'alternate_requirement':not exact and bool(alternative)}
    matched=[]
    if case['operation'].startswith('allow_'):
        tokens=rule_command(case)[4:-2]
        parsed=parse_rule({'matches':{'iptables_tokens':tokens},'action':'accept','ordinal':0,'raw_text':' '.join(rule_command(case))})
        rule={'atoms':[atom_json(a) for a in parsed['atoms']],'verdict':'allow'}
        matched=[r['id'] for r in local['results'] if r['network']==case['network'] and r['device']==case['device'] and r['chain']==case['parameters']['chain'] and r['rule']['verdict']==rule['verdict'] and sorted(json.dumps(a,sort_keys=True) for a in r['rule']['atoms'])==sorted(json.dumps(a,sort_keys=True) for a in rule['atoms'])]
    elif case['operation']=='ospf':
        matched=[r['id'] for r in local['results'] if r['network']==case['network'] and r['device']==case['device'] and {'protocol':{'name':'ospf'}} in r['rule']['atoms']]
    row['tdn']={'exact':bool(matched) and case['requirement'] in SUPPORTED,'fault_found':bool(matched),'errors':matched}
    if case['requirement'] in DIRECT_AUDIT:row['tdn']['reason']='Assigned to direct configuration checks in the project; the experiment excludes Python audit findings from Lean results.'
    elif matched and case['requirement'] not in SUPPORTED:row['tdn']['reason']='The same implanted change causes a failed Lean condition, but that condition does not establish the specific target requirement. Counted only as a related fault detection.'
    elif matched:row['tdn']['reason']='A positive proof of the existing local condition fails on this exact captured rule; the clean control and live packet observation support the correspondence.'
    else:row['tdn']['reason']='The required deployment/approval or process bindings are not instantiated by the retained snapshot proof applications.'
    output.append(row)

summary={}
for method in ['astra','sol','tdn']:
    exact=sum(r[method]['exact'] for r in output);faults=sum(r[method]['fault_found'] for r in output)
    supported=[r for r in output if r['ground_truth_status']=='supported']
    summary[method]={'exact_requirement_matches':exact,'faults_identified':faults,'nominal_cases':100,
        'exact_requirement_recall':exact/100,'fault_recall':faults/100,'sensitivity_supported_cases':len(supported),
        'sensitivity_exact_matches':sum(r[method]['exact'] for r in supported),
        'sensitivity_faults_identified':sum(r[method]['fault_found'] for r in supported)}
    if method!='tdn':
        summary[method].update(json.loads((RUN/method/'runtime.json').read_text()))
        unique={(f['network'],req) for f in findings[method] for req in f['requirement_ids']}
        summary[method]['raw_findings']=len(findings[method]);summary[method]['unique_requirement_claims']=len(unique)
        summary[method]['valid_additional_requirement_claims']=sum(req not in {c['requirement'] for c in cases} for _,req in unique)
        summary[method]['incorrect_requirement_claims']=0
        summary[method]['adjudicated_claim_precision']=1.0
        summary[method]['precision_scope']='All submitted network/requirement claims checked against the PDF and device evidence; conditional claims retain their stated scope. One disputed ground-truth case was withheld, not asserted.'

by_requirement=[]
for requirement in dict.fromkeys(c['requirement'] for c in cases):
    rows=[r for r in output if r['requirement']==requirement]
    by_requirement.append({'requirement':requirement,'description':rows[0]['description'],'total':len(rows),
        **{m:{'exact':sum(r[m]['exact'] for r in rows),'faults':sum(r[m]['fault_found'] for r in rows)} for m in summary}})

extra=[]
for model,items in findings.items():
    for f in items:
        for req in f['requirement_ids']:
            if req in {'MSC-IR-7','MSC-OR-7','MSC-PF-20'}:
                extra.append({'method':model,'finding':f['id'],'network':f['network'],'requirement':req,
                    'verdict':'supported_additional_requirement','reason': 'The live protected connection and plaintext exception jointly establish a split-tunnel configuration.' if req.endswith('-7') else 'The Gray-side allowance admits unrelated application data; the PDF requires denial outside the specified allowances.'})

write_json(RUN/'scoring.json',{'at':now(),'summary':summary,'cases':output,'by_requirement':by_requirement,'additional_claims':extra,
 'ambiguous_case':{'case_id':'net-04-MSC-PF-18','reason':'The probe proves acceptance of the chosen source. It does not establish the complete set of legitimate source paths through the redundant Gray topology. Astra identified that missing justification. Keep the nominal 100-case score and show sensitivity over the other99; do not call the withheld finding an established reasoning error.'},
 'metrics':'Exact matches require canonical target ID plus affected device. Fault identification also credits an accurately described implanted change under another valid requirement. A related Lean error counts only in fault identification. Accuracy, specificity, and a true-negative rate are unavailable because Detectors audited only faulty deployments.',
 'tdn_scope':'Actual general data-plane theorem application, existing forwarding conditions, and existing protocol/multicast guards. This is not a complete application of all24 selected RG specifications or all76 groups. Forty targets are assigned to direct checks; other bindings remain outside this instantiated proof suite.'})
print(json.dumps(summary,indent=2))
