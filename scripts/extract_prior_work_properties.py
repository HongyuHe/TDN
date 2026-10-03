#!/usr/bin/env python3
"""Extract a source-traceable property inventory without running network verifiers.

The manifest determines dataset boundaries, including nested campus snapshots.
Paper interpretations live in CATALOG; artifact queries retain their original text.
Only the Python standard library is required. Run with --check to detect drift.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
NETWORKS = ROOT / "networks"
PAGES = ROOT / "docs/prior-work"
MODEL = ROOT / "specs/prior_work_network_properties.json"
INDEX = ROOT / "docs/prior_work_network_properties.md"

PAPERS = {
    "DNA": {
        "title": "Differential Network Analysis",
        "venue": "NSDI 2022",
        "file": "dna_nsdi22.pdf",
        "url": "https://www.usenix.org/system/files/nsdi22-paper-zhang_peng.pdf",
        "sections": "§6 differential properties; §7 implementation; §8 experiments; Appendix B OSPF updates",
    },
    "SRE": {
        "title": "Symbolic Router Execution",
        "venue": "SIGCOMM 2022",
        "file": "sre_sigcomm22.pdf",
        "url": "https://aaron.gember-jacobson.com/docs/sigcomm2022sre.pdf",
        "sections": "§6 forwarding properties and analyses; §8 experimental datasets; §9 limitations",
    },
    "Expresso": {
        "title": "Expresso: Comprehensively Reasoning About External Routes Using Symbolic Simulation",
        "venue": "SIGCOMM 2024",
        "file": "expresso_sigcomm24.pdf",
        "url": "https://aaron.gember-jacobson.com/docs/sigcomm2024expresso.pdf",
        "sections": "§2.2 properties; §6 property analysis; §7.3 Internet2; §8 limitations",
    },
    "Config2Spec": {
        "title": "Config2Spec: Mining Network Specifications from Network Configurations",
        "venue": "NSDI 2020",
        "file": "config2spec_nsdi20.pdf",
        "url": "https://vanbever.eu/pdfs/vanbever_config2spec_nsdi_2020.pdf",
        "sections": "§2 and Table 1 policy definitions and failure model; §8 synthetic WAN experiments",
    },
    "NetDice": {
        "title": "Probabilistic Verification of Network Configurations",
        "venue": "SIGCOMM 2020",
        "file": "netdice_sigcomm20.pdf",
        "url": "https://files.sri.inf.ethz.ch/website/papers/sigcomm20-netdice.pdf",
        "sections": "§3 and Table 1 property definitions; §6 failure distribution; §8 WAN experiments",
    },
    "Bagpipe": {
        "title": "Scalable Verification of Border Gateway Protocol Configurations with an SMT Solver",
        "venue": "OOPSLA 2016",
        "file": "bagpipe_oopsla16.pdf",
        "url": "https://homes.cs.washington.edu/~mernst/pubs/bgp-configuration-oopsla2016.pdf",
        "sections": "§3 BGP specifications; §6.2 Internet2 evaluation and refined Gao-Rexford policy",
    },
}

#* Each catalog entry represents one property or one analysis of a property.
#* A paper-defined query family is deliberately not labeled as an operator mandate.
CATALOG = {}


def define(key, name, statement, source, parameters, interpretation):
    CATALOG[key] = dict(name=name, statement=statement, source=source,
                        parameters=parameters, interpretation=interpretation)


define("C2S-R", "Reachability", "Traffic from router r can be delivered to destination prefix p in every environment allowed by the chosen failure model.", "Config2Spec §2, Table 1, PDF p. 3", "r, p; fixed-up links, fixed-down links, symbolic links; failure bound k", "Mine the router/prefix instances that satisfy the predicate. Do not assume that every router must reach every prefix. The evaluation uses k = 1, 2, 3 with all links eligible to fail.")
define("C2S-I", "Destination isolation", "Traffic from router r cannot be delivered to prefix p in any environment allowed by the chosen failure model.", "Config2Spec §2, Table 1, PDF p. 3", "r, p and the failure model", "Isolation is absence of delivery. A mined isolation fact can describe an accidental outage as well as an intended filter; intent needs a separate specification.")
define("C2S-W", "Waypoint traversal", "Traffic from r toward p traverses the nominated router w under the chosen failure model.", "Config2Spec §2, Table 1, PDF p. 3", "r, p, w and the failure model", "The waypoint must be nominated or mined from the candidate router set. Fix the forwarding and ECMP path quantifiers before translating the predicate to Lean, ASP, or Datalog.")
define("C2S-L", "Multiple forwarding paths", "Traffic from r toward p can use at least two forwarding paths under the chosen failure model.", "Config2Spec §2, Table 1, PDF p. 3", "r, p and the failure model", "The requirement concerns path multiplicity. It does not establish equal byte rates, independent failure domains, or link-disjoint paths.")
define("DNA-R", "Reachability additions and removals", "Compute each source/destination/packet-class reachability fact gained or lost between a base configuration and an update.", "DNA §6.1–6.2, PDF p. 9; §7, PDF p. 10", "ordered base/update pair; source and destination edge ports; packet equivalence class", "An added or removed fact is a behavioral difference. Calling the difference a violation requires a separate list of permitted changes. Differential reachability is implemented in the evaluated prototype.")
define("DNA-W", "Waypoint changes", "Compute the waypoint-traversal facts gained or lost by an update for a specified source, destination, packet class, and waypoint.", "DNA §6.1, PDF p. 9; §7, PDF p. 10", "ordered base/update pair; edge ports; packet class; waypoint", "The paper describes the predicate and illustrates differential waypointing. The evaluated prototype centers on reachability; the presence of configurations does not establish a waypoint result.")
define("DNA-L", "Forwarding-path-count changes", "Compute changes in the number of forwarding paths for a source/destination/packet class across an update.", "DNA §6.1, PDF p. 9; §7, PDF p. 10", "ordered base/update pair; edge ports; packet class; path count n", "The paper illustrates changes from n paths to a different count. Treat the predicate as a paper-defined extension, not a claim that all local runs measured load balancing.")
define("DNA-F", "Reachability under individual link failures", "For each eligible link, compare all-pairs reachability before and after disabling that link.", "DNA §8.4, PDF pp. 12–13; EvalLinkFailure.java", "baseline snapshot; edge-port pairs; packet classes; one failed link per comparison", "The experiment enumerates failures and reports changed reachability. The experiment does not assert that all pairs survive every single failure.")
define("SRE-R", "Reachability", "For each selected source s, destination d, and packet class p, determine the failure states in which p can reach d from s.", "SRE §6.1–6.2, PDF p. 7", "s, d, p; link/node failure variables", "The result is a condition on failures. A universal guarantee requires restricting that condition to a declared failure model.")
define("SRE-I", "Destination isolation", "Determine the failure states in which packets in p sent from s cannot reach d.", "SRE §6.1, PDF p. 7", "s, d, p; failure model", "Isolation means no delivery. It is different from NetDice's link-sharing isolation between several flows.")
define("SRE-W", "Waypoint reachability", "Determine the failure states in which packets in p can reach d from s along a path through w.", "SRE §6.1–6.3, PDF pp. 7–8", "s, d, p, w; failure model; ECMP path quantifier", "The paper constructs the waypoint condition by combining qualifying forwarding paths. An assertion that every ECMP path must cross w needs an explicit all-paths formulation. SRE's mining and single-flow checking code use different combinations of qualifying and nonqualifying paths.")
define("SRE-L", "Load balancing over n routes", "Determine when packets in p can reach d from s using n forwarding routes.", "SRE §6.1, PDF p. 7; SpecificationDB.mineLoadBalancing", "s, d, p, n; route-count semantics", "The local mining implementation checks for at least two alternatives and leaves disjoint-path handling as a TODO. Neither equal traffic volume nor disjoint paths follows from the path count.")
define("SRE-T", "Reachability failure tolerance", "Find the largest k for which the chosen reachability predicate holds whenever at most k eligible links fail.", "SRE §6.3, PDF pp. 7–8", "one reachability instance; eligible links; environment constraints", "A tolerance of 0 allows the all-up state but fails under some single-link outage. A value of −1 means that the predicate already fails with all links up.")
define("SRE-TW", "Waypoint failure tolerance", "Find the largest k for which the chosen waypoint predicate survives every allowed failure of at most k links.", "SRE §6.3, PDF p. 8", "one waypoint instance and its path quantifier; eligible links", "Use the waypoint predicate itself, not just endpoint connectivity. A surviving alternate path can bypass the waypoint.")
define("SRE-TI", "Isolation failure tolerance", "Find the largest k for which the chosen no-delivery predicate survives every allowed failure of at most k links.", "SRE §6.3, PDF p. 8", "one destination-isolation instance; eligible links", "Failure can redirect traffic around a filter. Isolation in the all-up state alone does not establish failure-tolerant isolation.")
define("SRE-PR", "Reachability probability", "Compute the probability that a selected reachability predicate holds under a declared distribution of failures.", "SRE §6.4, PDF p. 8; §8.2, PDF p. 10", "reachability instance; joint failure distribution", "The WAN comparison uses link failure probability 0.001 and node failure probability 0.0001. Node failures correlate incident link failures. Those benchmark numbers are not measured reliability or a required SLA.")
define("SRE-PW", "Waypoint probability", "Compute the probability that a selected waypoint predicate holds under a declared distribution of failures.", "SRE §6.4, PDF p. 8; §8.2, PDF p. 10", "waypoint instance; path quantifier; joint failure distribution", "The paper compares probability queries with NetDice at an imprecision target of 0.0001. A historical result file does not by itself bind every distribution or routing assumption used in that run.")
define("SRE-DR", "Reachability changes under failures", "Find the packet/failure combinations for which reachability differs between two selected snapshots.", "SRE §6.5, PDF pp. 8–9; §8.3, PDF pp. 10–11", "ordered snapshot pair; matched endpoints; packet classes; failure bound", "Compare the same environment on both sides. The BICS experiment includes k = 0 and k = 3; a no-failure comparison can miss a change exposed by an outage.")
define("SRE-DT", "Changes in reachability failure tolerance", "Compute the change in each selected reachability instance's link-failure tolerance between two snapshots.", "SRE §6.5, PDF pp. 8–9; §8.3, PDF pp. 10–11", "ordered snapshot pair; common endpoint and failure interpretation", "A decrease is evidence of reduced modeled resilience. Whether the decrease is authorized remains a separate policy question.")
define("SRE-DP", "Changes in reachability probability", "Compute the change in each selected reachability instance's probability between two snapshots under the same failure distribution.", "SRE §6.5, PDF pp. 8–9; §8.3, PDF pp. 10–11", "ordered snapshot pair; reachability instance; common joint distribution", "Do not attribute a probability change solely to configurations if the distribution also changed.")
define("CAMPUS-R", "Access-VLAN reachability changes", "Compare reachability between access VLANs across explicitly selected campus snapshots, respecting their VRFs and ACLs.", "SRE §8.7, PDF p. 12; DNA §8.2, PDF pp. 11–12", "ordered campus snapshots; access VLAN/VRF identities; traffic classes", "The local collection contains more dataset directories than the paper's 67 snapshots. Nested snapshots and alternate representations remain separate. Directory names alone do not prove a chronological experiment sequence.")
define("CAMPUS-T", "Core-to-access-VLAN single-failure reachability", "Test whether each designated core router can reach each access VLAN despite any one eligible link failure.", "SRE §8.7, PDF p. 12", "mapping of paper cores C1/C2 to local devices; access VLANs; eligible links; traffic class", "The paper reports tolerance 1 for its core-to-VLAN checks. The local names do not establish the C1/C2 mapping, and the reported result has not been reproduced on these files.")
define("ND-R", "Reachability probability", "Compute the probability that a selected flow is delivered to its destination.", "NetDice §3.4–3.5, Table 1, PDF p. 5; SRE §8.2, PDF p. 10", "source, destination prefix, external announcements, BGP roles, failure distribution", "A graph alone does not determine delivery. The synthesized routing environment and the failure distribution are part of the query.")
define("ND-W", "Waypoint probability", "Compute the probability that a selected flow traverses a selected waypoint.", "NetDice §3.4–3.5, Table 1, PDF p. 5; §8.2, PDF pp. 10–11", "source, destination prefix, waypoint, routing environment, failure distribution", "The main WAN experiment chooses waypoints and flows for synthetic trials. Keep each recorded trial's router roles and query together; the trials are not operator requirements.")
define("ND-E", "Egress probability", "Compute the probability that a flow exits through a nominated egress router.", "NetDice §3.4–3.5, Table 1, PDF p. 5", "source, destination, required egress, routing environment, failure distribution", "The property is supported by the paper. Most collected inputs provide no nominated egress or corresponding recorded trial.")
define("ND-P", "Exact path-length probability", "Compute the probability that a flow traverses exactly l links.", "NetDice §3.4–3.5, Table 1, PDF p. 5", "source, destination, exact link count l, routing environment, failure distribution", "An exact length differs from an upper bound. The SRE helper compares stored path-list size; check whether that representation counts nodes or links before using it as a NetDice-equivalent checker.")
define("ND-B", "Traffic-load balance probability", "Compute the probability that the loads on a nominated set of links differ by no more than a chosen amount Δ.", "NetDice §3.4–3.5, Table 1, PDF p. 5", "several flows and their volumes; link set; Δ; traffic splitting; failure distribution", "Topology and ECMP path counts alone cannot instantiate the query. Traffic volumes and the allowed imbalance must be supplied.")
define("ND-I", "Flow link-disjointness probability", "Compute the probability that the selected flows use no common links.", "NetDice §3.4–3.5, Table 1, PDF p. 5", "flow set; routing environment; forwarding/splitting semantics; failure distribution", "The flows can each be reachable. The isolation condition concerns shared links, not blocked communication between endpoints.")
define("ND-C", "Congestion-threshold probability", "Compute the probability that the combined traffic of selected flows on one link stays at or below threshold t.", "NetDice §3.4–3.5, Table 1, PDF p. 5; §8.4, PDF pp. 11–12", "flows, volumes, monitored link, threshold t, traffic splitting, failure distribution", "AS-3549 retains explicit congestion trial strings, including volumes and threshold 500. Their symbolic destinations and source-label mapping still need resolution. Other topology-only datasets generally lack those parameters.")
define("EX-L", "Route-leak freedom", "Forbid propagation of a route learned from a noncustomer neighbor to another noncustomer neighbor where the declared relationship policy disallows transit.", "Expresso §2.2, PDF p. 3; §6.1, PDF pp. 8–9", "external-neighbor relationships; symbolic advertisement space; permitted transit policy", "The common runner checks route leaks. Accurate customer/peer/provider classification is required; a BGP neighbor address or AS number alone does not establish a commercial relationship.")
define("EX-R", "Route-hijack freedom", "Prevent an external advertisement from becoming the selected route for a prefix designated as internal.", "Expresso §2.2, PDF p. 3; §6.1, PDF p. 9", "authoritative internal-prefix set; external advertisements; routing abstractions", "An interface subnet is evidence of addressing, not automatically the complete protected-prefix policy. Prefix ownership must be declared before universal checking.")
define("EX-T", "Traffic-hijack freedom", "Prevent traffic destined for designated internal prefixes from being forwarded out of the internal network.", "Expresso §2.2, PDF p. 3; §6.2, PDF pp. 8–9", "internal ingress points and prefixes; external exits; modeled advertisements", "The predicate concerns forwarding. Route selection alone is insufficient because next-hop resolution and the forwarding path also matter.")
define("EX-B", "BlockToExternal", "Prevent export to external neighbors of routes carrying the policy's block-to-external designation.", "Expresso §6.3, PDF p. 9; §7.3, Table 4, PDF p. 11; Bagpipe §3, PDF p. 7", "internal/external boundary; BTE community and its policy semantics; external advertisements", "Internet2 defines BLOCK-TO-EXTERNAL as community 11537:888 in the collected JSON. The paper reports four Expresso violations and five Bagpipe violations with different recognized neighbor counts. Those are historical results, not results of this extraction.")
define("EX-E", "Egress preference", "Select the preferred external egress according to a declared ordering whenever the relevant choices are available.", "Expresso §6.3, PDF p. 9", "destination class; ordered egress preferences; eligible advertisements", "No complete operator-supplied ordering is bundled with the collected datasets. Route-policy settings can suggest an ordering but do not independently specify the intended one.")
define("EX-FL", "Forwarding-loop freedom", "Ensure that modeled packets do not revisit a forwarding node indefinitely.", "Expresso §5.2, PDF p. 8; forwarding/LoopChecker.java", "packet classes; ingress points; symbolic routing/forwarding environment", "The repository contains a loop checker. The common routing-only runner does not execute every forwarding checker.")
define("EX-FB", "Forwarding-blackhole freedom", "Ensure that traffic expected to be delivered does not terminate at an unintended forwarding dead end.", "Expresso §5.2, PDF p. 8; forwarding/BlackholeChecker.java", "intended delivery classes and endpoints; allowed drops; forwarding environment", "Specify permitted ACL drops and unknown destinations first. Not every dropped packet is a policy violation.")
define("BP-M", "NoMartian", "Ensure that a route for a designated martian prefix is unavailable in the selected local BGP RIB.", "Bagpipe §3, PDF pp. 7–8; §6.2, PDF p. 13", "martian-prefix predicate; internal routers; allowed BGP traces", "The formal predicate constrains the selected local route. It should not be strengthened into a claim that a router never receives such an advertisement. The paper also evaluates a separately modified configuration with sanity checks removed; that variant is not identified in this collection.")
define("BP-G", "Internet2's refined Gao-Rexford preference", "Select routes according to Internet2's relationship and community-dependent ranking while retaining its invalid-prefix restrictions.", "Bagpipe §3, PDF p. 8; §6.2, PDF p. 13", "manually classified customers/peers; valid prefixes; ranking rules including HIGH_PEERS", "The paper's refinement allows community-dependent preferences and has no provider neighbors. A generic customer-over-peer assertion would lose that refinement. The collected JSON lacks the paper's complete classification and formal ranking specification.")

FAMILY_NOTES = {
    "dna": "DNA studies changes in forwarding behavior after configuration updates. The configurations identify a candidate domain, but they do not assert that every possible reachability fact should hold. Preserve the direction of each comparison.",
    "c2s": "BICS, Columbus, and USCarrier use Topology Zoo graphs and synthesized configurations in the Config2Spec experiments. Mined predicates describe those configurations under a chosen failure model. They are not the real operators' published service policies.",
    "campus": "Campus snapshots contain VLANs, VRFs, ACLs, and routing configuration. A configuration file can represent a VRF rather than an entire physical router. The source README says campus configurations are excluded, while the collected checkout contains parsed campus files; the exact relationship to the published anonymized dataset is therefore not established.",
    "differential": "The differential folders provide baseline and modified inputs. Sibling names such as aggr, bn, if, lp, mp, net, and sr identify experiment variants. A comparison must use the corresponding base and inspect the actual edits; filenames alone do not prove whether a neighbor or interface was added or removed.",
    "fat": "Fat-tree configurations exercise protocol execution, forwarding analysis, and scaling. Topological redundancy alone does not establish reachability, ECMP multiplicity, or a particular failure tolerance under the routing policies.",
    "probabilistic": "The WAN graph is a substrate for synthesized routing and probabilistic experiments. Router roles and external advertisements are experimental inputs. Randomly selected waypoint trials do not describe an operator's mandatory waypoints.",
    "expresso": "Expresso reasons about external advertisements as part of the environment. The strength of a claim depends on which attributes are symbolic. The paper fixes some attributes, including MED, and documents limitations in AS-path length comparison, aggregation, conditional advertisements, and BGP/IGP dependencies.",
    "example": "The three-router SRE example illustrates how routing policy, ACLs, and link failures interact. The paper's concrete formulas provide regression targets once the local packet and configuration semantics are matched.",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def family(path):
    if path == "sre/paper_example":
        return "example"
    if path.startswith("expresso/"):
        return "expresso"
    if "/campus/" in path:
        return "campus"
    if path.startswith("sre/differential/"):
        return "differential"
    if "/config2spec-networks/" in path or path.startswith("sre/c2s/") or (path.startswith("sre/parallel/") and "fattree" not in path):
        return "c2s"
    if "/mrinfo/" in path or "/zoo/" in path or path.startswith("sre/netdice/"):
        return "probabilistic"
    if path.startswith("dna/"):
        return "dna"
    return "fat"


def catalog_for(path):
    kind = family(path)
    if kind == "expresso":
        keys = ["EX-L", "EX-R", "EX-T", "EX-E", "EX-FL", "EX-FB"]
        if path.endswith("internet2"):
            keys = ["EX-B", "BP-M", "BP-G"] + keys
        return keys
    if kind == "probabilistic":
        return ["ND-R", "ND-W", "ND-E", "ND-P", "ND-B", "ND-I", "ND-C"]
    if path.startswith("dna/"):
        return (["C2S-R", "C2S-I", "C2S-W", "C2S-L"] if kind == "c2s" else []) + ["DNA-R", "DNA-W", "DNA-L", "DNA-F"]
    keys = ["SRE-R", "SRE-I", "SRE-W", "SRE-L", "SRE-T", "SRE-TW", "SRE-TI", "SRE-PR", "SRE-PW"]
    if kind == "c2s" or (path.startswith("sre/parallel/") and "fattree" not in path):
        keys += ["C2S-R", "C2S-I", "C2S-W", "C2S-L"]
    if kind in {"campus", "differential"}:
        keys += ["SRE-DR", "SRE-DT", "SRE-DP"]
    if kind == "campus":
        keys += ["CAMPUS-R", "CAMPUS-T"]
    return keys


def prefix_value(value):
    if isinstance(value, dict) and "ip" in value and "mask" in value:
        try:
            return str(ipaddress.ip_network(f"{value['ip']}/{value['mask']}", strict=False))
        except ValueError:
            return None
    if isinstance(value, str) and "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    return None


def walk_prefixes(value, pointer=""):
    p = prefix_value(value)
    if p:
        yield p, pointer
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            yield from walk_prefixes(child, pointer + "/" + escaped)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from walk_prefixes(child, pointer + f"/{i}")


def has_nonempty_field(value, keys):
    if isinstance(value, dict):
        return any((k in keys and bool(v)) or has_nonempty_field(v, keys) for k, v in value.items())
    if isinstance(value, list):
        return any(has_nonempty_field(v, keys) for v in value)
    return False


def describe_inputs(path):
    base = NETWORKS / path
    names, physical, protocols, prefixes = set(), set(), set(), {}
    cfgs = sorted(p for p in (base / "configs").rglob("*") if p.is_file())
    for f in cfgs:
        raw = f.read_text()
        if f.suffix == ".json":
            d = json.loads(raw)
            node = d.get("node", {})
            if isinstance(node, dict):
                device = node.get("node", d.get("deviceName", d.get("name", f.stem)))
                vrf = node.get("vrf")
            else:
                device, vrf = node or d.get("deviceName", f.stem), None
            physical.add(str(device))
            if d.get("vrfs"):
                names.update(f"{device} [VRF {v}]" for v in d["vrfs"])
            else:
                names.add(str(device) + (f" [VRF {vrf}]" if vrf else ""))
            if has_nonempty_field(d, {"bgpNetworks", "eBgpNeighbors", "iBgpNeighbors", "bgpReflectClients", "bgpProcess"}):
                protocols.add("BGP")
            if has_nonempty_field(d, {"ospfNeighbors", "ospfIntfSetting", "ospfRedises", "ospfProcesses", "ospfProcess"}):
                protocols.add("OSPF")
            if has_nonempty_field(d, {"isisProcess"}):
                protocols.add("IS-IS")
            for p, pointer in walk_prefixes(d):
                prefixes.setdefault(p, {"file": str(f.relative_to(ROOT)), "pointer": pointer})
        else:
            m = re.search(r"^hostname\s+(\S+)", raw, re.M)
            name = m.group(1) if m else f.stem
            names.add(name)
            physical.add(name)
            for proto in ("bgp", "ospf", "isis"):
                if re.search(r"^router\s+" + proto + r"\b", raw, re.M):
                    protocols.add(proto.upper())
            for i, line in enumerate(raw.splitlines(), 1):
                for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", line):
                    p = prefix_value(candidate)
                    if p:
                        prefixes.setdefault(p, {"file": str(f.relative_to(ROOT)), "line": i})
                m = re.search(r"\bip address (\S+) (\S+)", line)
                if m:
                    p = prefix_value({"ip": m.group(1), "mask": m.group(2)})
                    if p:
                        prefixes.setdefault(p, {"file": str(f.relative_to(ROOT)), "line": i})
    graph = None
    for f in sorted(base.glob("*.in")):
        rows = [line.split() for line in f.read_text().splitlines() if line.strip()]
        nodes = [str(i) for i in range(int(rows[0][0]))]
        links = sorted({tuple(sorted((r[0], r[1]))) for r in rows[1:] if len(r) >= 2 and r[0] != r[1]})
        graph = {"file": str(f.relative_to(ROOT)), "nodes": nodes, "links": links, "format": "weighted .in"}
    for f in sorted(base.glob("AS-*.json")):
        d = read_json(f)["topology"]
        nodes = [str(n) for n in d["nodes"]]
        links = sorted({tuple(sorted((str(e["u"]), str(e["v"])))) for e in d["links"] if e["u"] != e["v"]})
        graph = {"file": str(f.relative_to(ROOT)), "nodes": nodes, "links": links, "format": "NetDice JSON"}
    return {"configuration_records": len(cfgs), "device_identities": sorted(physical), "routing_contexts": sorted(names),
            "protocols_detected": sorted(protocols), "prefix_mention_count": len(prefixes),
            "prefix_examples": [{"prefix": p, "source": s} for p, s in sorted(prefixes.items())[:32]],
            "graph": graph, "configuration_files": [str(f.relative_to(ROOT)) for f in cfgs],
            "direct_files": [str(f.relative_to(ROOT)) for f in sorted(base.iterdir()) if f.is_file()],
            "acl_files": [str(f.relative_to(ROOT)) for f in sorted((base / "acls").rglob("*")) if f.is_file()]}


def parse_query(raw):
    waypoint = re.fullmatch(r"Waypoint\(\[src: ([^,]+), dst: ([^\]]+)\], ([^)]+)\)", raw)
    if waypoint:
        src, dst, point = waypoint.groups()
        return {"type": "Waypoint", "source": src, "destination": dst, "waypoint": point}
    congestion = re.fullmatch(r"Congestion\((.*), \((\d+), (\d+)\), ([\d.]+)\)", raw)
    if congestion:
        flows, u, v, threshold = congestion.groups()
        fs = [{"source": s, "destination": d, "volume": int(vol)} for s, d, vol in re.findall(r"\[src: ([^,]+), dst: ([^\]]+)\]\*(\d+)", flows)]
        return {"type": "Congestion", "flows": fs, "link_indices": [int(u), int(v)], "threshold": float(threshold)}
    return {"type": "Unparsed", "raw": raw}


def queries(path, inputs):
    base = NETWORKS / path
    result = []
    graph = inputs["graph"]
    nodes = graph["nodes"] if graph else []
    for f in sorted(base.glob("property*.json")):
        d = read_json(f)
        for i, scenario in enumerate(d["scenarios"]):
            raw = scenario["property"]
            parsed = parse_query(raw)
            missing = []
            if parsed["type"] == "Waypoint":
                if parsed["destination"] == "XXX":
                    missing.append("The destination is the literal placeholder XXX; no destination prefix is bound by the recorded query.")
                for field in ("source", "waypoint"):
                    if nodes and parsed[field] not in nodes:
                        missing.append(f"The {field} label {parsed[field]} is absent from the collected topology's node labels.")
            elif parsed["type"] == "Congestion":
                missing.append("The symbolic destination names dst0, dst1, etc. are not mapped to prefixes or external advertisements in the trial record.")
                if any(flow["source"] not in nodes for flow in parsed["flows"]):
                    missing.append("The trial's IP-address source labels do not match the numeric node labels in the sibling topology; a label mapping is needed.")
                missing.append("The monitored-link pair uses numeric identifiers; the record alone does not establish its mapping to the sibling graph or the units of traffic volume.")
            else:
                missing.append("The query text is retained verbatim but has no parser for its property type.")
            roles = {}
            for role in ("rrs", "brs"):
                indices = scenario.get(role, [])
                roles[role] = {"recorded": indices, "mapped_by_sre_generator": [nodes[j] if isinstance(j, int) and 0 <= j < len(nodes) else None for j in indices]}
                if any(n is None for n in roles[role]["mapped_by_sre_generator"]):
                    missing.append(f"At least one {role} index is outside the collected topology's node list.")
            result.append({"id": f"{f.stem.upper()}-{i + 1:02d}", "kind": "historical artifact query", "raw_query": raw,
                           "parsed": parsed, "source": {"file": str(f.relative_to(ROOT)), "pointer": f"/scenarios/{i}"},
                           "roles": roles, "recorded_scenario": scenario, "unresolved": missing,
                           "validation": "not rerun"})
    f = base / "probability.json"
    if f.exists():
        d = read_json(f)
        env = base / "environment.json"
        result.append({"id": "PROBABILITY-01", "kind": "explicit local query", "source": {"file": str(f.relative_to(ROOT)), "pointer": "/property"},
                       "parsed": d["property"], "failure_model": d.get("failures"), "recorded_input": d,
                       "environment": read_json(env) if env.exists() else None,
                       "unresolved": [], "validation": "not run"})
    return result


def dataset_notes(path, inputs, qs):
    notes = [FAMILY_NOTES[family(path)]]
    base = NETWORKS / path
    graph = inputs["graph"]
    if path.startswith("sre/") and (family(path) == "c2s" or path.startswith("sre/parallel/")):
        notes.append("Paper-defined predicates are listed separately from enabled runner defaults. The Config2spec runner enables reachability by default; its isolation, waypoint, and load-balancing switches are disabled in the inspected source.")
    if graph:
        notes.append("Graph edges and mentioned prefixes are candidate domains, not computed forwarding paths or authorized destinations. No forwarding verifier was run for this inventory.")
        cfg = base / "config.json"
        if cfg.exists():
            d = read_json(cfg)
            notes.append("config.json supplies one generator role assignment. The rrs/brs values are indices into the topology's node list; point is looked up as a node name. The assignment does not automatically apply to every historical scenario.")
            if str(d.get("point")) not in graph["nodes"]:
                notes.append(f"The generator's point value {d.get('point')} is not a node label in the collected graph. The inspected waypoint loader cannot resolve that value. AS-3549 also has congestion trials, so do not reinterpret their threshold as a valid waypoint.")
        else:
            notes.append("No config.json generator role assignment is present. Historical scenario roles remain available where recorded; topology alone does not supply a current routing configuration.")
        if (base / "IpBank").exists():
            notes.append("IpBank is serialized generator state. The SRE generator allocates its external /24 from that state; the inventory does not deserialize it or substitute a guessed prefix for XXX.")
        if path.endswith("/demo"):
            notes.append("The topology is named Demo.in, while the SRE basename-based loader requests demo.in. A case-sensitive filesystem requires an explicit filename adjustment.")
        if not qs:
            notes.append("No instantiated property trial is recorded for this dataset. The listed properties are parameterized paper families.")
        if path.endswith("/Kdl"):
            notes.append("Kdl's property.json contains an empty scenarios array. An empty array supplies no successful check or counterexample.")
    if path.startswith("sre/differential/") and "/campus/" not in path:
        counterpart = str(Path(path).parent / "base")
        notes.append(f"Use {counterpart} as the baseline for a sibling update. The base page lists the same comparison families but needs a chosen sibling update.")
    if path.startswith("dna/") and "example-network" not in path:
        notes.append("The DNA paper evaluates BGP interface, announcement, neighbor, local-preference, multipath, aggregation, and static-route updates. OSPF experiments use interface state, cost, and multipath updates. A specific edit or generated update must be selected before a differential query is fully bound.")
    if path.startswith("sre/parallel/"):
        notes.append("The parallel directory measures execution/scaling on a distinct input variant. Parallel speedup is a tool-performance metric, not a forwarding invariant. Source aliases preserve any exact duplicates merged into other datasets.")
    if path == "sre/paper_example":
        notes.append("The collected C ACL contains an explicit protocol-1 permit after the destination-prefix deny. The paper's figure abstracts packet destinations. A regression must preserve the packet-protocol scope instead of claiming the figure proves unrestricted TCP/UDP delivery.")
    if path == "sre/netdice/example":
        notes[0] = "The hand-authored example supplies routing configurations, a single probability query, and an explicit fixed-link environment. Its declared failure probability differs from the larger WAN experiments."
        notes.append("probability.json binds flow 3 → 42.42.0.0/16 through waypoint 4 with link failure probability 0.1. environment.json fixes four external attachment links up. Those explicit settings take precedence over the WAN benchmark's 0.001/0.0001 defaults.")
    if path.startswith("expresso/"):
        notes.append("The common ExpressoRunner invokes the route-leak check with the routing-hijack switch disabled. ExpressoBlockToExternal is a separate entry point. Available checker classes do not mean every listed property was checked by the default command.")
        if path.endswith("internet2"):
            notes.append("The paper's private CSP old/new snapshots are absent from the collection. Their leak/hijack counts do not belong to Internet2. knownExternalRoutes.xml is a concrete route artifact; it does not establish universal coverage of external advertisements.")
        else:
            notes.append("The example contains pr1 and pr2, with local AS 3000 and external-neighbor AS values 1000 and 2000. The paper does not report a separate experiment result for this two-router folder. No Internet2 BTE policy or operator egress ordering is inferred for it.")
    return notes


def special_targets(path):
    if path == "sre/paper_example":
        return [
            {"id": "EXAMPLE-128", "statement": "For the paper's destination-only packet class 128.0.0.0/2, Reach(A,C) holds exactly when AC is up or both AB and BC are up. Its link-failure tolerance is 1.", "source": "SRE Figures 3–4 and §6.3, PDF pp. 7–8", "status": "paper-reported regression target; local ACL/protocol equivalence not verified"},
            {"id": "EXAMPLE-192", "statement": "For the paper's destination-only packet class 192.0.0.0/2, Reach(A,C) requires both AB and BC. Its link-failure tolerance is 0.", "source": "SRE Figure 4 and §6.3, PDF pp. 7–8", "status": "paper-reported regression target; local ACL/protocol equivalence not verified"},
            {"id": "EXAMPLE-PROB", "statement": "For the paper's 128.0.0.0/2 example, independent link failure probability 0.1 gives reachability probability 0.981.", "source": "SRE §6.4, PDF p. 8", "status": "paper-reported value; local verifier not run"},
            {"id": "EXAMPLE-ACL", "statement": "Removing C's illustrated ACL leaves all-up reachability unchanged but permits A-to-C delivery for 192.0.0.0/2 through AC when AB or BC fails. The alternative path bypasses waypoint B.", "source": "SRE §6.5, PDF p. 8", "status": "paper-defined modification; no second ACL-removed dataset identified"},
        ]
    if path.startswith("dna/example-network/"):
        return [
            {"id": "DEMO-A", "statement": "The DNA README records loss of a → e reachability for 1.1.1.0/24 and 1.1.2.0/24 after applying example-network/update to example-network/base.", "source": "DNA README.md, Workflow demo", "status": "historical README output; not rerun"},
            {"id": "DEMO-B", "statement": "The README's base policy dump records b → e reachability for 1.2.0.0/16, 1.1.1.0/24, and 1.1.2.0/24.", "source": "DNA README.md, Workflow demo", "status": "historical README output; not rerun"},
            {"id": "DEMO-EDIT", "statement": "The collected update adds shutdown to the C–E interface at both ends. The update provides a concrete base/update pair for differential reachability.", "source": "networks/dna/example-network/{base,update}/configs/{C,E}.cfg", "status": "configuration difference inspected; forwarding consequence not recomputed"},
        ]
    return []


def usage(path, key, qs):
    if path.startswith("expresso/"):
        if path.endswith("internet2") and key == "EX-B":
            return "Explicitly evaluated on Internet2 in Expresso and Bagpipe; the copied input has not been rechecked."
        if path.endswith("internet2") and key in {"BP-M", "BP-G"}:
            return "Evaluated on Internet2 in the predecessor Bagpipe study; exact equivalence to the later parsed input is not established."
        return "Paper-defined or implemented property applicable as a candidate; no dataset-specific published or local result is assigned here."
    if key == "ND-W" and any(q["parsed"]["type"] == "Waypoint" for q in qs):
        return "Instantiated by the individual local waypoint queries below; missing bindings and historical results remain attached to each query."
    if key == "ND-C" and any(q["parsed"]["type"] == "Congestion" for q in qs):
        return "Instantiated by the individual local congestion queries below; the unresolved label and destination mappings remain explicit."
    if key.startswith("ND-") and key not in {"ND-R", "ND-W"}:
        return "Supported property family in NetDice; no instantiated local query of this type is present for this dataset."
    if key in {"DNA-W", "DNA-L"}:
        return "Defined and illustrated in DNA; broader than the differential-reachability focus of its evaluated prototype."
    if key.startswith("C2S-"):
        return "Property family mined in the Config2Spec study and reused by SRE; a mined per-instance pass list is not present here."
    if key.startswith("CAMPUS-"):
        return "Campus evaluation target from the papers; local snapshot selection and endpoint mappings still require binding."
    return "Analysis family described for these experimental inputs; the listing supplies a query schema rather than a new result."


def link(from_file, to_file, label=None):
    target = os.path.relpath(to_file, from_file.parent).replace(os.sep, "/")
    return f"[{label or to_file.name}](<{target}>)"


def compact(values, limit=10):
    vals = [str(v) for v in values]
    return ", ".join(f"`{v}`" for v in vals[:limit]) + (f", … ({len(vals)} total)" if len(vals) > limit else "") or "none recorded"


def render_dataset(d):
    page = PAGES / (d["path"] + ".md")
    base = NETWORKS / d["path"]
    inp = d["inputs"]
    lines = [f"# {d['path']}: property inventory", "", f"{link(page, INDEX, 'All datasets')} · {link(page, base, 'Network inputs')} · {link(page, MODEL, 'Machine-readable inventory')}", "",
             "The entries below distinguish paper-defined predicates, recorded experiment queries, and remaining parameters. No network verification was performed while extracting the inventory.", "",
             "## Dataset and evidence", "", f"- **Collected source aliases:** {compact(d['sources'], 30)}.",
             f"- **Collection fingerprint:** `{d['collection_sha256']}`. The fingerprint comes from the collection manifest; individual input hashes are retained in networks/files.tsv.",
             f"- **Configuration records:** {inp['configuration_records']}; **distinct device identities:** {len(inp['device_identities'])}; **protocols detected in configuration fields:** {compact(inp['protocols_detected'])}.",
             f"- **Routing contexts:** {compact(inp['routing_contexts'])}.",
             f"- **Prefix literals mentioned in configurations:** {inp['prefix_mention_count']}. Mentions include interface, route, and filter prefixes; they are not a list of reachable or authorized destinations."]
    if inp["prefix_examples"]:
        lines += [f"- **Example prefix mentions:** {compact([p['prefix'] for p in inp['prefix_examples']], 10)}. The JSON inventory retains up to 32 examples with source locations."]
    if inp["graph"]:
        g = inp["graph"]
        lines += [f"- **Generator topology:** {len(g['nodes'])} node labels and {len(g['links'])} unique undirected non-self endpoint pairs in {link(page, ROOT / g['file'])}. Link counts exclude duplicated reverse rows and do not infer forwarding.",
                  f"- **Node labels:** {compact(g['nodes'])}."]
    evidence = inp["direct_files"] + inp["configuration_files"][:2] + inp["acl_files"][:2]
    lines += ["- **Input references:** " + ", ".join(link(page, ROOT / f, str(Path(f).relative_to(base.relative_to(ROOT)))) for f in evidence) + ".", ""]
    for note in d["notes"]:
        lines += [note, ""]
    cfg = base / "config.json"
    if cfg.exists():
        lines += ["**Current generator settings:**", "", "```json", json.dumps(read_json(cfg), indent=2, ensure_ascii=False), "```", ""]
    lines += ["## Property families", "", "Each entry is a query schema over this dataset. Variables range over the imported routing contexts, candidate packet classes, and declared environment. A schema becomes a concrete obligation only after its remaining parameters and expected outcome are supplied.", ""]
    for key in d["catalog_ids"]:
        p = CATALOG[key]
        lines += [f"### {key}: {p['name']}", "", p["statement"], "", f"**Evidence category:** {d['catalog_usage'][key]}", "", f"**Parameters:** {p['parameters']}.", "", f"**Interpretation and limits:** {p['interpretation']}", "", f"**Source:** {p['source']}.", ""]
    if d["special_targets"]:
        lines += ["## Concrete examples and regression targets", ""]
        for p in d["special_targets"]:
            lines += [f"### {p['id']}", "", p["statement"], "", f"**Evidence status:** {p['status']}.", "", f"**Source:** {p['source']}.", ""]
    lines += ["## Recorded local queries", ""]
    if not d["queries"]:
        lines += ["No instantiated query appears in a local property*.json or probability.json file. Paper examples and parameterized families above remain separate from executable, fully bound local queries.", ""]
    for q in d["queries"]:
        src = q["source"]
        lines += [f"### {q['id']}: {q['parsed']['type']}", "", f"**Kind:** {q['kind']}. **Validation:** {q['validation']}.", "", f"**Source:** {link(page, ROOT / src['file'])}, JSON pointer `{src['pointer']}`.", ""]
        if "raw_query" in q:
            lines += ["```text", q["raw_query"], "```", "", "**Router-role indices in the recorded trial:** " + "; ".join(f"{role} = {data['recorded']}" for role, data in q["roles"].items()) + ".", ""]
            if q["parsed"]["type"] == "Waypoint":
                p = q["parsed"]
                lines += [f"**Single property:** Evaluate the probability that traffic from `{p['source']}` to `{p['destination']}` traverses `{p['waypoint']}` under that trial's routing and failure environment.", ""]
            elif q["parsed"]["type"] == "Congestion":
                p = q["parsed"]
                lines += [f"**Single property:** Evaluate the probability that the {len(p['flows'])} recorded flows jointly stay within threshold `{p['threshold']:g}` on recorded link `{tuple(p['link_indices'])}`. The individual volumes remain in the query string.", ""]
            finished = q["recorded_scenario"].get("finished")
            if finished is not None:
                lines += ["**Historical result fields:** `" + json.dumps(finished, sort_keys=True) + "`. These values were copied from the input file and were not reproduced.", ""]
            else:
                lines += ["**Historical result:** No finished result field is recorded for this trial.", ""]
            lines += ["**Reproduction scope:** The historical record does not fully bind the failure distribution, external advertisements, or checker version. Paper benchmark settings are context, not proof of the settings of this particular saved run.", ""]
        else:
            lines += ["```json", json.dumps(q["recorded_input"], indent=2), "```", "", "**Fixed environment:**", "", "```json", json.dumps(q["environment"], indent=2), "```", ""]
        for issue in q["unresolved"]:
            lines += [f"**Unresolved parameter:** {issue}", ""]
    paper_keys = set()
    for k in d["catalog_ids"]:
        paper_keys.update(p for p in PAPERS if p in CATALOG[k]["source"])
    if d["path"].startswith("dna/"):
        paper_keys.add("DNA")
    if d["path"].startswith("sre/"):
        paper_keys.add("SRE")
    lines += ["## Original papers", ""]
    for k in sorted(paper_keys):
        p = PAPERS[k]
        lines += [f"- **{k}, {p['venue']}:** {link(page, ROOT / 'assets/prior-work' / p['file'], p['title'])}; [original PDF]({p['url']}). {p['sections']}."]
    lines += ["", "PDF page references count from the first page of the archived PDF. Property wording is paraphrased; raw artifact query strings are preserved. The machine-readable inventory lists all detected configuration contexts and a sample of prefix references.", ""]
    return page, "\n".join(lines)


def render_index(model):
    counts = model["summary"]
    lines = ["# Properties of the prior-work networks", "", f"The inventory covers all **{counts['datasets']} collected datasets**, including protocol variants, update snapshots, and distinct representations of the same graph. It preserves **{counts['recorded_queries']} local queries**: {counts['query_types']['Waypoint']} waypoint queries and {counts['query_types']['Congestion']} congestion queries. Every dataset has a separate page below.", "",
             "The original papers define experimental predicates rather than a normative requirements document like the CSfC capability package. Each dataset page therefore distinguishes paper-defined property families, concrete artifact queries, historical results, and missing parameters. The extraction does not establish that a property holds.", "",
             "## Sources and interpretation", "",
             "Six original papers were read because the newer projects reuse datasets and definitions from earlier systems. The archived copies fix the page numbering and support offline reading.", ""]
    for key, p in PAPERS.items():
        lines += [f"- **{key}, {p['venue']}:** {link(INDEX, ROOT / 'assets/prior-work' / p['file'], p['title'])}; [original PDF]({p['url']}). {p['sections']}."]
    lines += ["", "**Reachability and isolation require precise quantifiers.** SRE and Config2Spec isolation prohibit delivery to a destination. NetDice isolation instead prohibits link sharing between flows. Waypoint queries also need a declared choice between some-path and all-paths semantics under ECMP.", "",
              "**Failure tolerance and probability are different questions.** A tolerance of k quantifies over every allowed failure set of size at most k. Probability weights failure states using a specified distribution. The WAN experiments' 0.001 link and 0.0001 node failure probabilities are benchmark inputs, not measured service guarantees.", "",
              "**Configuration differences need an intended-change policy.** DNA and SRE report gained or lost behavior. A change is not automatically a bug. Likewise, Config2Spec mining recovers predicates that the configuration satisfies; it cannot infer whether an accidental outage was intended.", "",
              "**A topology is insufficient to reconstruct many recorded queries.** The historical waypoint strings usually use destination XXX. AS-3549's ten congestion trials retain seven flow volumes and threshold 500, but use symbolic destination names and source labels that differ from the sibling graph. The inventory records those gaps explicitly.", "",
              "**Some collected inputs differ from the experimental descriptions.** The corpus contains 76 campus snapshot directories, including nested variants, while SRE describes 67 evaluated snapshots. Kdl's property.json contains zero scenarios. Four property_with_he.json files retain additional trial records. Exact duplicate datasets are represented by the manifest's source aliases.", "",
              "**Internet2 has source-specific policy evidence.** Its BTE community is 11537:888. Bagpipe's NoMartian constrains the selected local RIB, and its refined Gao-Rexford policy requires neighbor classifications and community-sensitive ranking. Expresso reports four BTE violations versus Bagpipe's five with different recognized neighbor counts. The counts are historical and were not rerun here.", "",
              "## Main questions by network family", "",
              "| Network family | Properties examined in the source studies |", "| --- | --- |",
              "| DNA WANs, fat trees, and example | Which reachability facts appear or disappear after an update or individual link failure? |",
              "| Config2Spec WANs: BICS, Columbus, USCarrier | Which reachability, isolation, waypoint, and multiple-path predicates survive the declared failure model? |",
              "| SRE WANs and fat trees | Which packets are delivered under which failures, how many failures can a property tolerate, and how do those facts change after an update? |",
              "| Campus snapshots | Which VLAN-to-VLAN reachability facts change, and can designated core routers reach access VLANs after one link failure? |",
              "| Topology Zoo and mrinfo probability inputs | What is the probability of a selected flow reaching its destination or traversing a waypoint? AS-3549 also records multi-flow congestion queries. |",
              "| Internet2 | Do exports respect BTE, do selected routes exclude martian prefixes, and do preferences satisfy the refined relationship policy? |",
              "| Expresso's small example | How can external advertisements affect route leaks, route selection, internal traffic, and forwarding? These are candidate applications without an assigned published result for the folder. |",
              "", "## Property catalog", "", "The catalog keeps each predicate and analysis separate. Every dataset page expands the applicable entries and includes local evidence and remaining parameters.", "",
              "| ID | Property | Original source |", "| --- | --- | --- |"]
    for key, p in CATALOG.items():
        lines += [f"| {key} | {p['name']} | {p['source']} |"]
    lines += ["", "## Every collected dataset", "", "The query count includes saved trial records, even when parameters are unresolved or the same query appears in more than one input file. It does not count schema instances obtained by enumerating all routers, prefixes, and failures.", ""]
    groups = collections.defaultdict(list)
    for d in model["datasets"]:
        parts = d["path"].split("/")
        group = "/".join(parts[:2]) if parts[0] != "expresso" else "expresso"
        groups[group].append(d)
    for group, ds in groups.items():
        lines += [f"### {group} ({len(ds)} datasets)", "", "| Dataset inventory | Input size | Property IDs | Local queries |", "| --- | --- | --- | ---: |"]
        for d in ds:
            inp = d["inputs"]
            size = f"{inp['configuration_records']} config records" if inp["configuration_records"] else f"{len(inp['graph']['nodes'])} graph nodes" if inp["graph"] else "supporting inputs"
            lines += [f"| {link(INDEX, PAGES / (d['path'] + '.md'), d['path'])} | {size} | {', '.join(d['catalog_ids'])} | {len(d['queries'])} |"]
        lines += [""]
    lines += ["## Reproduce and extend the inventory", "",
              f"The {link(INDEX, MODEL, 'JSON inventory')} preserves every raw scenario, parsed query, source pointer, source alias, and referenced input hash. It also lists all detected routing contexts, counts distinct prefix mentions, and retains up to 32 prefix examples per dataset with source locations. The {link(INDEX, ROOT / 'assets/prior-work/README.md', 'source notes')} record paper provenance and implementation caveats.", "",
              "```sh", "cd /Users/hongyu/Projects/Formal/TDN", "python3 scripts/extract_prior_work_properties.py", "python3 scripts/extract_prior_work_properties.py --check", "python3 -m unittest discover -s tests -p 'test_prior_work_properties.py'", "```", "",
              "The generator uses networks/manifest.json as the dataset boundary list. It checks collected file hashes against networks/files.tsv and preserves nested snapshot boundaries. It reads configurations for identifiers and prefix references, but does not execute the routing semantics. Regeneration requires the archived papers and collected inputs; the sibling source repositories are not required.", "",
              "A future proof project should select one fully bound property, define the modeled routing and failure semantics, and state the expected outcome. Lean, Datalog, or ASP can then consume that model. A saved result scalar, a graph path, or a paper's benchmark result does not replace that step.", ""]
    return "\n".join(lines)


def build():
    manifest = read_json(NETWORKS / "manifest.json")
    rows = list(csv.DictReader((NETWORKS / "files.tsv").open(), delimiter="\t"))
    file_hashes = {}
    for row in rows:
        f = NETWORKS / row["destination"]
        data = f.read_bytes()
        if len(data) != int(row["bytes"]) or sha(data) != row["sha256"]:
            raise ValueError(f"Collected input differs from files.tsv: {f}")
        file_hashes["networks/" + row["destination"]] = row["sha256"]
    papers = {}
    for key, value in PAPERS.items():
        f = ROOT / "assets/prior-work" / value["file"]
        papers[key] = {**value, "sha256": sha(f.read_bytes())}
    datasets = []
    for item in manifest["datasets"]:
        path = item["path"]
        inp = describe_inputs(path)
        qs = queries(path, inp)
        datasets.append({"path": path, "sources": item["sources"], "collection_sha256": item["sha256"],
                         "inputs": inp, "catalog_ids": catalog_for(path), "queries": qs,
                         "catalog_usage": {key: usage(path, key, qs) for key in catalog_for(path)},
                         "special_targets": special_targets(path), "notes": dataset_notes(path, inp, qs)})
    kinds = collections.Counter(q["parsed"]["type"] for d in datasets for q in d["queries"])
    model = {"schema_version": 1, "purpose": "property extraction, not network verification", "papers": papers,
             "source_commits_inspected": {"dna": "6dc8c7f0e519653f21358ac7b3eb22acdb27e1d2", "sre": "bf1bc5508b0e8da43fee7e2a385eb11ce69c3db3", "expresso": "210196714193718ed74ea14ce55f3ae984480274"},
             "summary": {"datasets": len(datasets), "recorded_queries": sum(kinds.values()), "query_types": dict(kinds), "catalog_properties": len(CATALOG)},
             "catalog": CATALOG, "input_sha256": file_hashes, "datasets": datasets}
    return model


def outputs(model):
    yield MODEL, json.dumps(model, indent=2, ensure_ascii=False) + "\n"
    yield INDEX, render_index(model)
    for d in model["datasets"]:
        yield render_dataset(d)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check generated files without writing")
    args = parser.parse_args()
    model = build()
    different = []
    for path, content in outputs(model):
        if args.check:
            if not path.exists() or path.read_text() != content:
                different.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if different:
        raise SystemExit("Generated inventory needs regeneration:\n" + "\n".join(different))
    print(json.dumps(model["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
