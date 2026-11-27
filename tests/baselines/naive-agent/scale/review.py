"""Record a detection decision against a frozen Astra answer or Lean result."""

from pathlib import Path
import argparse
import json
import hashlib
import os
import re
from tempfile import NamedTemporaryFile


def save_review(dest, review):
    with NamedTemporaryFile(dir=dest.parent, delete=False, mode="w", encoding="utf-8") as tmp:
        path = Path(tmp.name)
        try:
            json.dump(review, tmp, indent=2, ensure_ascii=False)
            tmp.write("\n")
            tmp.flush()
            try:
                os.link(path, dest)
            except FileExistsError:
                if json.loads(dest.read_text()) != review:
                    raise ValueError("A different decision is already recorded for this trial.")
        finally:
            path.unlink(missing_ok=True)


def record(root, network, kind, decision, description, quotation):
    protocol = root / "protocol.json"
    if protocol.exists() and json.loads(protocol.read_bytes()).get("method_version",1) >= 2:
        raise ValueError("Review every finding using --findings on this study")
    cell = root / "measurements" / network / kind
    proof = json.loads((cell / "cell.json").read_text())
    run = root / "trials" / kind / network / "astra"
    session = json.loads((run / "execution.json").read_text())
    if session["status"] != "completed" or not proof["observed"]:
        raise ValueError(
            "Only a completed session on an observed case can be adjudicated"
        )
    answer = (run / "answer.md").read_text()
    if quotation and quotation not in answer:
        raise ValueError("Quotation missing from the frozen answer")
    if not description.strip() or (decision == "detected" and not quotation):
        raise ValueError("Explain the decision and quote any credited identification")
    review = {
        "network": network,
        "case": kind,
        "decision": decision,
        "explanation": description,
        "quotation": quotation,
        "answer_sha256": hashlib.sha256(answer.encode()).hexdigest(),
        "bundle": proof["bundle"],
    }
    save_review(cell / "astra-adjudication.json", review)


def lean_verdict(checks, control):
    if not checks or set(checks) != set(control) or any(v["status"] != "pass" or not v.get("source_sha256") for v in control.values()):
        raise ValueError("A passing control is required for every proof file")
    for key, check in checks.items():
        source = check.get("source_sha256")
        if ((check["status"] in {"pass", "rejected", "proof_error"} or source)
                and source != control[key]["source_sha256"]):
            raise ValueError("The control and trial used different proof programs")
    failures = {k: v["failed_obligations"] for k,v in checks.items()
                if v["status"] in {"rejected", "proof_error"} and v.get("failed_obligations")
                and v.get("source_sha256") == control[k].get("source_sha256") and v.get("source_sha256")}
    errors = {k: v["status"] for k,v in checks.items() if v["status"] != "pass" and k not in failures}
    return ("detected" if failures else "needs_repair" if errors else "missed"), failures, errors


def record_lean(root, network, kind, decision=None, description="", assertion=""):
    from scale.design import BASE_CONTROL, PANEL_REVISION, control_run_root
    cell = root / "measurements" / network / kind
    trial = json.loads((cell / "cell.json").read_text())
    result = (cell / "tdn/verification.json").read_bytes()
    checks = json.loads(result)
    if not trial["observed"]:
        raise ValueError("Only observed faults are scored")
    protocol = root / "protocol.json"
    variant = BASE_CONTROL
    if protocol.exists() and json.loads(protocol.read_bytes()).get("panel_revision") == PANEL_REVISION:
        plan = json.loads((root / "placement-plan.json").read_bytes())
        variant = plan["cells"][network + "/" + kind]["control_variant"]
        if trial.get("control_variant") != variant:
            raise ValueError("Fault capture differs from its registered control")
    clean_run = control_run_root(root, network, variant)
    clean_result = (clean_run / "controls" / (network + "-frozen") / "verification.json").read_bytes()
    control = json.loads(clean_result)
    errors = {"control/" + k: v["status"] for k, v in control.items() if v["status"] != "pass"}
    if errors:
        calculated, failures = "needs_repair", {}
    else:
        calculated, failures, errors = lean_verdict(checks, control)
    if decision and decision != calculated:
        raise ValueError(f"Recorded typecheck outcomes give {calculated}")
    review = {
        "network": network,
        "case": kind,
        "decision": calculated,
        "explanation": description,
        "failed_assertions": failures,
        "incomplete_checks": errors,
        "bundle": trial["bundle"],
        "verification_sha256": hashlib.sha256(result).hexdigest(),
    }
    if trial.get("control_variant"):
        review.update(control_variant=variant, control_verification_sha256=hashlib.sha256(clean_result).hexdigest())
    save_review(cell / "tdn-adjudication.json", review)


CATEGORIES = {"target", "consequence", "other_real", "false_positive", "unresolved"}

def identifies_device(answer, device, snapshot, finding):
    def mentioned(value):
        return re.search(r"(?<![\w.-])" + re.escape(value) + r"(?![\w-]|\.[\w])", answer) is not None
    if mentioned(device):
        return True
    if not snapshot:
        return False
    inventory = json.loads((Path(snapshot)/"native/snapshot.json").read_bytes())
    owners = {}
    for interface in inventory["interfaces"]:
        for addr in interface.get("addresses", []):
            value = addr.get("local") if isinstance(addr,dict) else addr
            if isinstance(value,str):
                owners.setdefault(value.split("/")[0],set()).add(interface["device_id"])
    if any(devices == {device} and mentioned(addr) for addr, devices in owners.items()):
        return True
    selector=finding.get("device_description",{})
    quote=finding.get("location_quotation","")
    if not isinstance(selector,dict) or not selector or not set(selector)<={"role","site","security_level_id","network_id"} or not quote or quote not in answer:
        return False
    matches=[d["id"] for d in inventory["devices"] if all(d.get(k)==v for k,v in selector.items())]
    return matches == [device]


def record_findings(root, network, kind, review):
    from scale.design import cases_for, controls_for
    protocol_file = root / "protocol.json"
    protocol = json.loads(protocol_file.read_bytes()) if protocol_file.is_file() else {}
    is_clean = kind in controls_for(protocol)
    names = {c.key for c in cases_for(protocol)}
    cell = root / "measurements" / network / kind
    trial = json.loads((cell / "cell.json").read_bytes())
    run = root / "trials" / kind / network / "astra"
    answer = (run / "answer.md").read_bytes()
    answer_text = answer.decode()
    session = json.loads((run / "execution.json").read_bytes())
    fingerprint = hashlib.sha256(answer).hexdigest()
    if (session["status"] != "completed" or session["bundles"] != {"network":trial["bundle"]}
        or review["answer_sha256"] != fingerprint or review["complete"] is not True
        or (not is_clean and (kind not in names or not trial["observed"]))):
        raise ValueError("Review must cover the complete frozen answer for this capture")
    findings = review["findings"]
    if not isinstance(findings,list):
        raise ValueError("Expected a list of separate findings")
    seen = set()
    for f in findings:
        text = f["quotation"].strip()
        category = f["classification"]
        if (category not in CATEGORIES or not text or text not in answer_text or text in seen
                or not f["reason"].strip() or not f["evidence"].strip()):
            raise ValueError("Each finding needs a distinct verbatim quotation, evidence and a judgment")
        if category == "target" and (is_clean or not isinstance(f.get("devices"), list) or
                not f["devices"] or f.get("identified_fault") != kind or
                (trial.get("anchor") and trial["anchor"] not in f["devices"])):
            raise ValueError("A target detection must identify the affected device and the actual fault")
        if category == "target":
            locations = [trial["anchor"]] if trial.get("anchor") else f["devices"]
            if not any(identifies_device(answer_text, d, trial.get("snapshot"), f) for d in locations):
                raise ValueError("The frozen answer must identify the device by name, unique address or quoted location")
        if is_clean and category == "consequence":
            raise ValueError("A clean trial has no planted cause")
        seen.add(text)
    hits = [f for f in findings if f["classification"] == "target"]
    decision = ("control" if is_clean else "detected" if hits else "missed")
    save_review(cell / "astra-adjudication.json", {
        "network":network,"case":kind,"bundle":trial["bundle"],"answer_sha256":fingerprint,
        "decision":decision,"explanation":hits[0]["reason"] if hits else "",
        "quotation":hits[0]["quotation"] if hits else "", "findings":findings, "complete":True})


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("results", type=Path)
    p.add_argument("network")
    p.add_argument("case")
    p.add_argument("decision", nargs="?", choices=("detected", "missed", "needs_repair"))
    p.add_argument("reason", nargs="?", default="")
    p.add_argument("--findings", type=Path, help="Complete per-finding review JSON for Astra")
    p.add_argument("--method", choices=("astra", "tdn"), default="astra")
    p.add_argument("--quote", default="", help="Text from the answer or failed Lean assertion.")
    a = p.parse_args()
    if a.findings:
        record_findings(a.results, a.network, a.case, json.loads(a.findings.read_bytes()))
    else:
        review = record_lean if a.method == "tdn" else record
        review(a.results, a.network, a.case, a.decision, a.reason, a.quote)
