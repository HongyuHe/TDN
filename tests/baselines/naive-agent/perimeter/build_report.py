"""Add the validated firewall follow-up to the preserved isolated experiment report."""
import html
import json
from pathlib import Path
import re

try:
    from .run import HERE, ROOT
except ImportError:
    from run import HERE, ROOT


def link(path, text, line=1):
    return f'<a href="vscode://file{html.escape(str(path.resolve()))}:{line}">{html.escape(text)}</a>'


def augment(page, root):
    result=json.loads((root/'validation.json').read_text())
    assert result['status']=='passed'
    rows=[]
    for row in result['rows']:
        net=row['network']
        rows.append(f'<tr><th>{net}</th><td>{len(row["checked_black_ifaces"])}</td>'
            f'<td><span class="badge found">Passed</span></td><td><span class="badge found">HTTP rules rejected</span></td>'
            f'<td>{row["fault_seconds"]:.2f} s</td><td>'+
            link(root/(net+'-clean')/'lean.jsonl','Clean Lean result')+' '+
            link(root/(net+'-MSC-PF-22')/'lean.jsonl','Faulty Lean result')+'</td></tr>')
    section=f'''<section id="firewall-followup"><h2>The Outer Firewall theorem catches all five HTTP-service faults</h2>
<div class="stats"><div class="stat"><small>Additional faulty snapshots rejected</small><strong>5 / 5</strong><span>Both the incoming HTTP allowance and outgoing reply allowance fail the rule check.</span></div>
<div class="stat"><small>Clean snapshot controls</small><strong>5 / 5</strong><span>The same proof template succeeds for every matching clean snapshot.</span></div>
<div class="stat"><small>Combined confirmed detections</small><strong>{result['combined_confirmed_detections']} / 100</strong><span>55 from the original applications, plus the five firewall-service cases.</span></div></div>
<p>The follow-up applies TDN's existing Outer Firewall theorem to the saved one-fault snapshots. The theorem establishes that accepted local-service traffic on a Black data interface is IPsec traffic or explicitly approved control traffic. Each clean snapshot supplies the required rule checks. Each faulty snapshot produces one failed Lean condition identifying its two HTTP allowances.</p>
<p>The added proof covers packets consumed by the firewall and packets originated by the firewall, including service replies. A general Lean lemma transfers INPUT and OUTPUT acceptance from the full imported deployment to the local-service proof. The imported rules retain their captured order, addresses, ports, and defaults.</p>
<div class="table-wrap"><table><thead><tr><th>Network</th><th>Black firewall interfaces</th><th>Clean control</th><th>Faulty snapshot</th><th>Faulty-snapshot check</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<h3>The approval policy is separate from observed firewall allowances</h3>
<p>The experiment approves OSPF between each Outer Firewall and its directly linked Black transport router. The declared links and interface addresses determine the approved peers. The same approval list is supplied to each clean/faulty pair. The policy permits no additional application service, so an observed HTTP allowance cannot approve itself.</p>
<h3>The full firewall check also exposed a separate UDP-framing obligation</h3>
<p>The saved FORWARD rules admit UDP on ports 500 and 4500. Applying the complete firewall rule condition requires checking that those packets carry the expected IKE/ESP format. The retained diagnostics identify those existing rules in both the clean and faulty snapshots. The local-service theorem isolates the HTTP-service claim and provides a successful clean control for that claim.</p>
<p>The five additional detections come from ten Lean proof attempts on the existing snapshots: five clean and five faulty. The original 100-case experiment remains preserved below. Combining the disjoint detected cases gives 60 of 100 intended faults, or 59 of 99 supported cases. The other 95 cases retain their original proof results. Forty remaining cases concern direct configuration checks.</p>
<div class="source-links">{link(HERE/'FirewallCompliance.lean','Snapshot theorem and general acceptance lemma')}{link(ROOT/'TDN/Requirements/OuterFirewallControlAcl.lean','Existing general firewall theorem',20)}{link(root/'approved-control-policy.json','Independent control-traffic policy')}{link(root/'validation.json','All results, coverage and trust audits')}{link(HERE/'run.py','Reproduce the theorem applications')}{link(HERE/'validate.py','Check the retained evidence')}</div>
<p>The trust audit checked all five successful proofs. The accepted checking assumptions include Lean's native evaluation and its compiler toolchain.</p></section>'''
    page=page.replace('<a href="#results">Updated results</a>', '<a href="#firewall-followup">Firewall follow-up</a><a href="#results">Original results</a>')
    page=page.replace('<section id="results">', section+'\n<section id="results">',1)
    page=page.replace('<h2>Lean rejected 55 of the 100 individually faulty snapshots</h2>', '<h2>The original two applications rejected 55 of 100 faulty snapshots</h2>')
    page=page.replace('<h2>The accepted faulty snapshots show the checks\' coverage gaps</h2>', '<h2>The original accepted snapshots identify where additional checks belong</h2>')
    page=page.replace('The following injected cases passed both Lean applications.', 'The following injected cases passed the original two Lean applications. The firewall follow-up above now detects the five PF-22 cases.')
    old="The project's selected proof suite does not test algorithm choices, certificate uniqueness, authentication settings, lifetime limits, spare-interface shutdown, or the Outer Firewall's HTTP application restriction. Passing the packet-processing proofs therefore leaves those requirements unchecked. Eight of these requirement types, covering forty cases, are assigned to direct configuration checks in TDN's current design. The five HTTP-service cases account for the remaining gap. No Python configuration-audit findings supplement the Lean detection score."
    page=page.replace(old, 'Forty cases concern configuration checks for algorithm choices, certificate identity, authentication settings, lifetime bounds, and unused interfaces. Those checks can compare the saved configuration records against the document requirements. The added Outer Firewall theorem application detects the five HTTP-service cases. All reported detections come from actual Lean checks; direct configuration-audit results remain a separate next step.')
    page=page.replace('<h2>Each requirement type was tested separately on all five networks</h2>', '<h2>Original two-application results by requirement</h2>')
    page=page.replace('<h2>Inspect the snapshot and Lean result for any case</h2>', '<h2>Inspect each original snapshot and its two original Lean applications</h2>')
    page=page.replace('<th>TDN isolated proof applications</th>', '<th>TDN original isolated proof applications</th>')
    page=page.replace('<h2>Runtime separates live experiments from Lean checking</h2>', '<h2>Original experiment runtime separates live work from Lean checking</h2>')
    page=page.replace('Blind audits and isolated fault tests</title>', 'Blind audits, isolated faults and firewall follow-up</title>')
    return page


def main():
    root=HERE.parent/'runs/20261112-perimeter-theory-02'
    destination=ROOT/'.lavish/blind-theory-comparison.html'
    previous=root/'previous-report.html'
    if not previous.exists():
        previous.write_bytes(destination.read_bytes())
    page=augment(previous.read_text(),root)
    assert page.count('id="firewall-followup"')==1
    destination.write_text(page)
    (root/'report.html').write_text(page)
    print(json.dumps({'report':str(destination),'bytes':destination.stat().st_size}))


if __name__=='__main__':
    main()
