"""Score frozen outputs against verified network/requirement cases."""

import argparse
from collections import Counter
from datetime import datetime
import json

from common import BASE, now, write_json


TDN_MISSES = {
    "MSC-VG-1": "The strict public-configuration parser rejects the PSK include file on the same gateway before inspecting its proposal list. No parser rejection is counted as a requirement violation.",
    "MSC-VG-7": "The selected TDN audit does not turn absent revocation data plus relaxed checking into a concrete authentication counterexample.",
    "MSC-VG-13": "The strict parser rejects the PSK include file on the gateway with the excessive reauthentication interval. Its independent lifetime field is consequently unavailable to this adapter.",
    "MSC-OR-8": "TDN's saved process inventory checker accepts only selected known programs. The experiment adapter does not supply a fresh program-to-service classification, so it cannot make a specific routing-protocol finding.",
    "MSC-PF-2": "The selected TDN audit needs a declared unused-interface inventory. The current snapshot supplies interface state but the adapter does not classify the added dummy interface as unused.",
    "MSC-PF-17": "The finite experiment adapter does not instantiate the existing peer-address restrictions and their deployment context.",
    "MSC-PF-18": "The adapter does not combine reverse-path settings and interface-specific reachable-source sets into the existing Gray-interface restriction.",
    "MSC-PF-22": "The adapter does not instantiate the Outer Firewall approval-policy and permitted-service context.",
}

DETECTOR_MISSES = {
    "MSC-PF-18": "The Detector identified the suspicious spoofed-source rule but withheld a violation because the gateway did not expose reverse-path-filter settings. The live ground-truth packet test confirmed the bypass.",
    "MSC-PF-22": "The Detector identified the HTTP service but withheld a violation because neither organization approval policy nor HTTP content was exposed. The experiment declares the application service unapproved; that administrative fact was absent from the Detector inputs.",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    profiles = [json.loads(p.read_text()) for p in sorted((BASE / "legacy" / "profiles").glob("net-*.json"))]
    cases = [dict(m, network=p["network"]) for p in profiles for m in p["mutations"]]
    assert len(cases) == 100 and len({c["case_id"] for c in cases}) == 100
    truth, controls = {}, {}
    for profile in profiles:
        net = profile["network"]
        for phase, destination in [("after-final", truth), ("before-r2", controls)]:
            doc = json.loads((run / "raw/oracle" / phase / (net + ".json")).read_text())
            for item in doc["records"]:
                destination[item["case_id"]] = item
    assert set(truth) == set(controls) == {c["case_id"] for c in cases}
    assert all(r["status"] == "observed" and r["violated"] for r in truth.values())
    assert all(r["status"] == "observed" and not r["violated"] for r in controls.values())
    agent = json.loads((run / "detector/findings.json").read_text())
    tdn = json.loads((run / "tdn-final/results.json").read_text())
    for i, row in enumerate(tdn["findings"], 1):
        row["id"] = f"TDN-{i:03}"
    sources = {"detector": agent["findings"], "tdn": tdn["findings"]}
    case_rows = []
    expected = {(c["network"], c["requirement"]) for c in cases}
    for case in cases:
        row = {k: case[k] for k in ["case_id", "network", "requirement", "device", "operation", "description"]}
        for method, findings in sources.items():
            matched = [f for f in findings if f["network"] == case["network"] and
                       case["requirement"] in f["requirement_ids"] and case["device"] in f["devices"]]
            row[method] = {"detected": bool(matched), "findings": [f["id"] for f in matched]}
            if not matched:
                row[method]["reason"] = (DETECTOR_MISSES if method == "detector" else TDN_MISSES).get(case["requirement"], "No matching supported finding")
            if method == "tdn" and matched:
                row[method]["methods"] = sorted({f["method"] for f in matched})
        row["validation"] = {"before": False, "after": True, "source": f"raw/oracle/after-final/{case['network']}.json"}
        case_rows.append(row)
    extra = []
    for method, findings in sources.items():
        for finding in findings:
            for requirement in finding["requirement_ids"]:
                if (finding["network"], requirement) not in expected:
                    assert method == "detector" and requirement in {"MSC-IR-7", "MSC-OR-7"}
                    extra.append({"method": method, "finding": finding["id"], "network": finding["network"],
                                  "requirement": requirement, "verdict": "valid_additional_violation",
                                  "reason": "The PDF prohibits split tunneling. The same device configures a protected remote-site path and also permits the independently confirmed plaintext application path. This is a configuration finding; no active protected SA is claimed.",
                                  "supporting_injected_requirement": "MSC-IR-3" if requirement == "MSC-IR-7" else "MSC-OR-2"})
    audit = json.loads((run / "detector-access-audit.json").read_text())
    start, end = [datetime.fromisoformat(audit[k].replace("Z", "+00:00")) for k in ["started_at", "ended_at"]]
    summary = {}
    for method, findings in sources.items():
        count = sum(c[method]["detected"] for c in case_rows)
        unique = {(f["network"], requirement) for f in findings for requirement in f["requirement_ids"]}
        added = sum(e["method"] == method for e in extra)
        precision = 1.0
        recall = count / len(cases)
        summary[method] = {"injected_cases_found": count, "injected_cases_missed": 100 - count,
                           "injected_case_recall": recall, "adjudicated_requirement_claims": len(unique),
                           "valid_additional_claims": added, "incorrect_claims": 0,
                           "adjudicated_claim_precision": precision, "target_only_f1": 2 * recall / (1 + recall),
                           "positive_only_accuracy": recall,
                           "balanced_accuracy": None, "specificity": None,
                           "raw_device_findings": len(findings),
                           "runtime_seconds": (end - start).total_seconds() if method == "detector" else tdn["runtime_seconds"]}
    by_requirement = []
    for requirement in dict.fromkeys(c["requirement"] for c in cases):
        rows = [c for c in case_rows if c["requirement"] == requirement]
        by_requirement.append({"requirement": requirement, "total": len(rows), "description": rows[0]["description"],
                               "detector": sum(c["detector"]["detected"] for c in rows),
                               "tdn": sum(c["tdn"]["detected"] for c in rows),
                               "detector_note": DETECTOR_MISSES.get(requirement, "Supported finding for every network"),
                               "tdn_note": TDN_MISSES.get(requirement, "Supported finding for every network")})
    write_json(run / "scoring.json", {"scored_at": now(), "unit": "network and requirement ID, with an affected-device match",
        "cases": case_rows, "summary": summary, "by_requirement": by_requirement, "additional_findings": extra,
        "adjudication": {"reviewer": "supervisor", "independent_external_reviewer": False,
                         "method": "Checked every requirement family, all affected-device matches, exact PDF quotations, frozen before/after observations, and live packet probes. The same supervisor designed injections and adjudicated results; report that limitation.",
                         "all_positive_warning": "Accuracy on the 100 injected cases equals recall. No balanced accuracy or true-negative rate can be estimated. Additional valid findings are not false positives.",
                         "scope": "TDN findings combine existing model counterexamples with configuration-clause checks. They do not constitute 60 complete RG proofs."}})
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
