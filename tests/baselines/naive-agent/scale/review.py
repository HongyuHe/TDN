"""Record a detection decision against a frozen Astra answer or Lean result."""

from pathlib import Path
import argparse
import json
import hashlib
import os
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


def record_lean(root, network, kind, decision, description, assertion=""):
    cell = root / "measurements" / network / kind
    trial = json.loads((cell / "cell.json").read_text())
    result = (cell / "tdn/verification.json").read_bytes()
    checks = json.loads(result)
    if not trial["observed"] or not checks or not description.strip():
        raise ValueError("A Lean review needs an observed fault, completed checks, and an explanation.")
    failures = {
        name: check["failed_obligations"]
        for name, check in checks.items()
        if check["status"] == "rejected" and check.get("failed_obligations")
    }
    if decision == "detected" and not (
        assertion.strip() and any(assertion in line for lines in failures.values() for line in lines)
    ):
        raise ValueError("Quote a failed Lean assertion that reflects the observed fault.")
    review = {
        "network": network,
        "case": kind,
        "decision": decision,
        "explanation": description,
        "failed_assertions": failures,
        "bundle": trial["bundle"],
        "verification_sha256": hashlib.sha256(result).hexdigest(),
    }
    save_review(cell / "tdn-adjudication.json", review)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("results", type=Path)
    p.add_argument("network")
    p.add_argument("case")
    p.add_argument("decision", choices=("detected", "missed"))
    p.add_argument("reason")
    p.add_argument("--method", choices=("astra", "tdn"), default="astra")
    p.add_argument("--quote", default="", help="Text from the answer or failed Lean assertion.")
    a = p.parse_args()
    review = record_lean if a.method == "tdn" else record
    review(a.results, a.network, a.case, a.decision, a.reason, a.quote)
