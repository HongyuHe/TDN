"""Report paired blind audits using the same fault and the same four network identities."""
import json
import re
from textwrap import shorten

from snapshot_inputs import digest, NETS


def load(path):
    return json.loads(path.read_text())


def excerpt(path, lines, esc):
    original = path.read_text().splitlines()
    choices = [original[i-1].strip() for i in lines if i and i <= len(original)]
    line = next((s for s in choices if len(s) > 35 and not re.match(r"I (found|substantiated) (one|two|three|four|[0-9]) ", s, re.I)),
                choices[0] if choices else "")
    cleaned = line.strip("| ").replace("**","").replace("`","")
    cleaned = re.sub(r"^#{1,6} +|^[-*] +", "", cleaned)
    return "<blockquote>“" + esc(shorten(cleaned, width=205, placeholder="…")) + "”</blockquote>" if cleaned else ""


def fault_record(live_root, row, esc, link):
    family,network,device=row["type"],row["network"],row["target"]
    folder=live_root/"trials"/family/network
    change=load(folder/"change.json")
    if "inserted_rule" in change:
        native=live_root/"raw/trials"/family/network/"snapshot/native"
        snap=load(native/"snapshot.json")
        candidates=[r for r in snap["filters"] if r["device_id"]==device and r["family"]==4]
        rules=[(r,rule) for r in candidates for rule in r["ordered_rules"] if rule["raw_text"]==change["inserted_rule"]]
        if len(rules)!=1 or rules[0][1]["ordinal"]!=0:
            raise ValueError("Expected one first-position rule on the affected device")
        record,rule=rules[0]
        raw=next(x["raw_path"] for x in snap["observations"] if x["id"]==rule["observation_ids"][0])
        explanation={
            "delivery-outage":"The Black router dropped every IPv4 packet it was asked to forward. The later rule allowing forwarding could never take effect.",
            "outer-eligible-deny":"The Outer gateway dropped traffic between its designated Inner gateway and the matching gateway at the other site before their permit rules could apply.",
            "gray-eligible-deny":("The Site A Gray Firewall dropped its designated workstation’s TCP connection to the management service on port 8443." if network=="net-05" else
                                "The Site A Gray Firewall dropped the authorized exchange between the two Inner gateway addresses before reaching the permit rules."),
            "inner-empty-ipv4-header":"The Inner gateway accepted an empty IPv4 packet from its Red host using protocol number 253, outside its allowed set.",
            "firewall-local-empty-udp":"The Outer Firewall accepted an empty UDP datagram to local port 65432 from the adjacent Black router. The recorded approval covered OSPF. A closed UDP port still receives the packet after the firewall admits it.",
        }[family]
        return explanation, f'<p>The first IPv4 rule on <code>{esc(device)}</code> was <code>{esc(rule["raw_text"])}</code>.</p>',link(native/raw,"Captured rule")
    if "ports" in change:
        captured=load(folder/"snapshot.json")
        links=[r for r in captured["links"] if any(r[k]["device"]==device and r[k]["interface"] in change["ports"] for k in ("a","b"))]
        if len(links)!=len(change["ports"]) or any(l["reciprocal"] for l in links):
            raise ValueError("Disconnected interfaces must match the saved reciprocal peer checks")
        names=[" ↔ ".join(l[k]["device"]+"."+l[k]["interface"] for k in ("a","b")) for l in links]
        explanation=("The Site A Gray Firewall lost every link toward its Inner gateways. None of those gateways could reach it through the remaining Gray links." if family=="gray-firewall-detached" else
                     ("The Outer gateway lost its connection to the inside of the Site A Outer Firewall." if "inside" in family else
                      "The Site A Outer Firewall lost its outside connection to the Black router."))
        return explanation, "<p>The saved interface readings showed no matching peer on "+", ".join("<code>"+esc(x)+"</code>" for x in names)+".</p>",link(folder/"snapshot.json","Captured interface readings")
    modes=load(folder/"snapshot.json")[network]
    observed=next(r for r in modes if r["device"]==device)
    if family=="inner-peer-loopback":
        assert "127.0.0.2" in observed["output"]
        return ("The Inner gateway used its own loopback address as the remote peer for a connection that should have reached the other site.",
                "<p>The running connection named <code>127.0.0.2</code>. The intended remote gateway was <code>10.200.1.2</code>.</p>",
                link(folder/"snapshot.json","Captured running peer"))
    assert observed["mode"]=="TRANSPORT" and family in {"inner-mode","outer-mode"}
    return (f"The {family.split('-')[0].title()} gateway had transport mode loaded for a connection that required tunnel mode.",
            '<p>The gateway’s saved connection listing reported <code>TRANSPORT</code>.</p>',link(folder/"snapshot.json","Captured connection mode"))


def paired_report(live_root,root,live,esc,link,seconds,*,result=None):
    if result is None:
        result=load(root/"score.json")
    if result["live_score_sha256"]!=digest((live_root/"score.json").read_bytes()) or result["source_run"]!=live_root.name:
        raise ValueError("Paired report does not match its original scores")
    rows=result["rows"]; stats=result["stats"]
    old={(i["type"],i["network"]):i for i in live["rows"]}
    names={"astra":"Astra","sol":"Sol","tdn":"TDN"}
    summary=(f'With saved snapshots, Astra identified <strong>{stats["astra"]["hit"]} of 43</strong> observed faults and Sol identified '
             f'<strong>{stats["sol"]["hit"]} of 43</strong>. With live read access they identified {live["stats"]["astra"]["trials"]["hit"]} '
             f'and {live["stats"]["sol"]["trials"]["hit"]}, respectively. TDN detected {live["stats"]["tdn"]["trials"]["hit"]} on the same captures.')
    def verdict(v):
        return '<span class="tag '+v+'">'+("Found" if v=="hit" else "Missed")+"</span>"
    bench=[]
    for method,condition in (("astra","Live"),("astra","Snapshot"),("sol","Live"),("sol","Snapshot"),("tdn","Snapshot")):
        previous=live["stats"][method]
        if method=="tdn" or condition=="Live":
            hit=previous["trials"].get("hit",0)
            complete=sum(all(r["old"][method]=="hit" for r in rows if r["type"]==family) for family in live["types"])
            median,low,high=previous["median_seconds"],previous["min_seconds"],previous["max_seconds"]
        else:
            s=stats[method]; hit=s["hit"];complete=s["complete_types"]
            median,low,high=s["median_seconds"],s["min_seconds"],s["max_seconds"]
        bench.append(f'<tr><th scope="row">{names[method]} · {condition}</th><td><span class="mini-track" aria-hidden="true"><i style="width:{100*hit/43:.3f}%"></i></span><strong>{hit}/43</strong></td><td>{hit+1}/44</td><td>{complete}/11</td><td>{seconds(median)}<small>{seconds(low)} to {seconds(high)}</small></td></tr>')
    paired=[]
    for m in ("astra","sol"):
        p=stats[m]["paired"]
        paired.append(f'<tr><th scope="row">{names[m]}</th>'+''.join(f'<td>{p[k]}</td>' for k in ("hit_hit","hit_miss","miss_hit","miss_miss"))+'</tr>')
    family_table=[]
    for family,t in live["types"].items():
        subset=[r for r in rows if r["type"]==family]
        counts=[]
        for m in ("astra","sol"):
            for leg in ("old","new"):
                hits=sum((r["old"][m] if leg=="old" else r["new"][m]["verdict"])=="hit" for r in subset)
                counts.append(f'<td>{hits}/{len(subset)}</td>')
        family_table.append(f'<tr><th scope="row">{esc(t["title"])}</th>{"".join(counts)}</tr>')
    answer_rows=[]
    miss_cards={"miss_miss":[],"miss_hit":[],"hit_miss":[]}
    for r in rows:
        family,n=r["type"],r["network"]; title=live["types"][family]["title"]
        c=family+"/"+n; folder=root/"trials"/c; past=live_root/"trials"/c
        found=[]
        for m in ("astra","sol"):
            a=r["new"][m]
            found.append(f'<td>{verdict(a["verdict"])}<details><summary>Evidence</summary><p>{esc(a["reason"])}</p><p>'
                    +link(folder/m/"answer.md","Final answer",a["lines"][0])+" · "+link(folder/m/"access.jsonl","Reader requests")
                    +f'</p><small>{seconds(a["seconds"])} for the complete audit.</small></details></td>')
        answer_rows.append(f'<tr><th scope="row">{esc(title)}<small>{n} · {esc(r["target"])}</small></th>{"".join(found)}</tr>')
        pair=r["old"]["astra"]+"_"+r["new"]["astra"]["verdict"]
        if pair not in miss_cards:
            continue
        prev=old[(family,n)]["methods"]["astra"]; curr=r["new"]["astra"]
        prev_ref=link(past/"astra/answer.md","Live answer",prev.get("lines",[1])[0])
        old_quote=excerpt(past/"astra/answer.md",prev.get("lines",[]),esc)
        new_quote=excerpt(folder/"astra/answer.md",curr["lines"],esc)
        new_ref=link(folder/"astra/answer.md","Snapshot answer",curr["lines"][0])
        obs=r["snapshot_astra_reads"]; exposed=obs["direct_text"]
        if exposed:
            evidence="A returned page showed "+" and ".join(esc(x) for x in exposed)+". "+link(folder/"astra/events.jsonl","Returned page",obs["first_matching_event_line"])
        elif obs["identified_target_views"]:
            evidence="Returned pages identified the affected device in "+", ".join("<code>"+esc(k)+"</code>" for k in obs["identified_target_views"])+". The page audit could not confirm that the exact changed record reached Astra."
        else:
            evidence=f'The reader returned {obs["pages_for_network"]} observation pages for {n}. The page audit could not attribute a returned record to the affected device.'
        observed=prev.get("observations",{})
        exact=observed.get("visible_target_settings",[])
        live_visible=("The live reader returned "+", ".join(esc(x) for x in exact)+"." if exact else
            ("The live reader returned "+", ".join(esc(k) for k in observed["target_operations_visible"])+" for the affected device." if observed.get("target_operations_visible") else
             "The live transcript has no identifiable successful device row for the affected device."))
        timeouts=observed.get("reader_timeouts_by_network",{}).get(n,0)
        if timeouts:
            live_visible+=f' On {n}, {timeouts} live reader '+("request timed out." if timeouts==1 else "requests timed out.")
        explanation,details,source=fault_record(live_root,r,esc,link)
        card=(f'<article class="fault-card" id="paired-{esc(family)}-{n}"><h4>{n} · {esc(r["target"])}</h4>'
              f'<p><strong>{esc(title)}</strong></p><p>{esc(explanation)}</p>{details}'
              f'<p>{esc(r["oracle"])} {source} · '+link(past/"adjudication.json","Original trial record")+f' · <a href="#trial-{esc(family)}-{n}">Trial details</a></p>'
              f'<div class="two"><div><h5>Live access · {verdict(r["old"]["astra"])}</h5><p>{esc(prev["reason"])}</p>{old_quote}<p class="sidenote">{live_visible} {prev_ref} · '
              + link(past/"astra/events.jsonl","Live transcript")+'</p></div>'
              +f'<div><h5>Snapshot access · {verdict(curr["verdict"])}</h5><p>{esc(curr["reason"])}</p>{new_quote}<p class="sidenote">{evidence} {new_ref}</p></div></div></article>')
        miss_cards[pair].append(card)
    inside=[r for r in rows if r["type"]=="firewall-inside-disconnected"]
    inside_old=sum(r["old"]["astra"]=="hit" for r in inside)
    inside_new=sum(r["new"]["astra"]["verdict"]=="hit" for r in inside)
    counts=stats["astra"]["paired"]
    snapshot_missed = [r for r in rows if r["new"]["astra"]["verdict"]=="miss"]
    exact_returned = sum(bool(r["snapshot_astra_reads"]["direct_text"]) for r in snapshot_missed)
    transit = [r for r in rows if r["type"]=="delivery-outage"]
    udp = next(r for r in rows if r["type"]=="firewall-local-empty-udp" and r["network"]=="net-04")
    detached = next(r for r in rows if r["type"]=="gray-firewall-detached" and r["network"]=="net-05")
    def phrase(row):
        return "found" if row["new"]["astra"]["verdict"]=="hit" else "again missed"
    reading=(f'<p>The six original Astra misses involved three kinds of faults. Four involved a Black router whose first IPv4 rule dropped every forwarded packet. '
             f'Astra found {sum(r["new"]["astra"]["verdict"]=="hit" for r in transit)} of those four outages from the saved captures. '
             f'It {phrase(udp)} the local UDP exception on net-04 and {phrase(detached)} the lost Gray Firewall links on net-05.</p>'
             f'<p>One difference recurred on all four profiles. When the Site A Outer Firewall lost its inside link to the Outer gateway, '
             f'Astra identified {inside_old} of four with live access and {inside_new} of four with snapshots. The saved topology names both ends of the link. '
             'The saved interface readings show that the two ends no longer match. The individual answers below show which findings Astra reported.</p>'
             f'<p>In at least {exact_returned} of the {len(snapshot_missed)} snapshot misses, a returned page contained the changed rule, gateway setting, or explicit evidence of a disconnected link. '
             'That count requires a match to the affected device. Other pages may contain indirect or partial evidence.</p>')
    intro=(f'Across the same 43 faults, Astra missed {counts["miss_miss"]} in both settings, found {counts["miss_hit"]} only with snapshots, '
           f'and found {counts["hit_miss"]} only with live access.')
    cases_html=[]
    for k,h in (("miss_miss","Missed in both settings"),("miss_hit","Found only with snapshots"),("hit_miss","Found only with live access")):
        cards=miss_cards[k]
        cases_html.append(f'<h3>{h} ({len(cards)})</h3>' + (''.join(cards) if cards else '<p>No cases had this outcome.</p>'))
    baselines=len(list((root/"attempts").glob("**/execution.json")))
    notes=(f'<p>{result["sessions"]} fresh sessions used GPT-6 Astra or GPT-6 Sol with high reasoning. Each session received the original PDF, '
           'the affected network’s capture, and one saved clean capture for each of the other three networks. '
           'The prompt named no fault, requirement, or affected network. Each reader could search the PDF and inspect declared links, observed interfaces, routes, firewall rules, running gateway connections, and the original saved command outputs. '
           'Its three tools read local files. They offered no live commands, SSH connection, web search, or packet probes. '
           f'The reader returned observation records from all four networks in {stats["astra"]["all_four_read"]} of 43 Astra sessions and {stats["sol"]["all_four_read"]} of 43 Sol sessions.</p>'
           '<p>The supervisor verified the input files against their collection hashes and used the same sealed inputs for both Detectors. '
           f'The three control captures were saved separately. The affected network has the latest collection time in {result["affected_capture_latest"]} of 43 audits. Comparing timestamps could help locate the affected network. Naming a network alone earned zero credit. '
           'The live reader offered on-demand, read-only device queries. The static reader exposed the recordings collected for TDN, including firewall counters. Its link view matches the interface numbers reported at both ends of a declared link. A missing peer therefore appears as an explicit field in that view. '
           'TDN’s proof also had the recorded approval for Black-side OSPF. Neither Detector received the scoring records, the supervisor’s probe results, or that separate approval. Device counters already present in the capture remained readable, including counters incremented by the original trial traffic.</p>'
           f'<p>Timing starts when a Detector launches and ends when its final answer is written. It includes model and reader time. '
           'The full audit had a one-hour limit. The live comparison recorded a five-minute timeout on individual requests. '
           f'The longest recorded local tool call took {seconds(result["longest_reader_seconds"])}. Snapshot preparation is excluded. TDN’s earlier recorded time covers Lean typechecking after the data were loaded. Independent snapshot audits could run concurrently. '
           f'{baselines} unsuccessful startup attempts were kept outside the scored sessions.</p>'
           '<p>The scores measure recovery of the introduced faults. For example, snapshot Astra named both disconnected links to the net-02 Gray Firewall. It cited the requirement to disable unused switch interfaces. That answer earned credit for finding the actual change. Other design concerns were outside the grading. Measuring precision would require judging every additional finding. '
           'Each Detector ran once per fault and access setting. Differences can reflect both evidence access and variation between runs.</p>')
    sources=" · ".join([link(root/"protocol.json","Blind protocol"),link(root/"matrix.json","Input hashes by trial"),
                         link(root/"score.json","Paired scores"),link(live_root/"score.json","Original scores")])
    comparison=(f'<section id="snapshot-results"><h2>What changed when the Detectors received snapshots?</h2><p>{summary}</p>'
        '<div class="tablewrap"><table><thead><tr><th>Method and access</th><th>Observed faults found</th><th>With assigned point</th><th>Types on all four</th><th>Median time and range</th></tr></thead><tbody>'
        +''.join(bench)+'</tbody></table></div><p>The 43 measured cases cover 11 fault types. The non-applicable Gray Firewall case on net-02 contributes one assigned point to each method. It adds no detection or time measurement.</p>'
        '<h3>How often did an individual answer change?</h3><div class="tablewrap"><table><thead><tr><th>Detector</th><th>Found with both</th><th>Live access only</th><th>Snapshot access only</th><th>Missed with both</th></tr></thead><tbody>'
        +''.join(paired)+'</tbody></table></div><details><summary>Detection by fault type</summary><div class="tablewrap"><table><thead><tr><th>Fault type</th><th>Astra live</th><th>Astra snapshots</th><th>Sol live</th><th>Sol snapshots</th></tr></thead><tbody>'
        +''.join(family_table)+'</tbody></table></div><p>Each denominator counts observed faults of that type.</p></details>'
        +'<details><summary>All 43 snapshot trials and both answers</summary><div class="tablewrap"><table><thead><tr><th>Fault and device</th><th>Astra</th><th>Sol</th></tr></thead><tbody>'
        +''.join(answer_rows)+'</tbody></table></div></details><details><summary>Inputs, timing and scoring</summary>'+notes+'<p>'+sources+'</p></details></section>')
    misses=(f'<section id="astra-misses"><h2>Which violations did Astra miss, and how?</h2><p>{intro}</p>'
        '<p>Each case pairs the same injected fault with the two final answers and the saved observations. A finding about shared Linux hosting could be accurate and still leave the injected fault unidentified. A page match means the reader supplied the value to the agent session. A session could filter a page further before presenting it to the model. Only the final answer earned credit.</p>'
        +reading+''.join(cases_html)+'</section>')
    return {"summary":summary,"comparison":comparison,"misses":misses}
