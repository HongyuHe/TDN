"""Record human adjudications against the exact frozen answer and observed trial."""

from pathlib import Path
import argparse
import json
import hashlib


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
    dest = cell / "astra-adjudication.json"
    if dest.exists() and json.loads(dest.read_text()) != review:
        raise ValueError(
            "An adjudication already exists. Archive the previous decision before revising it."
        )
    dest.write_text(json.dumps(review, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("results", type=Path)
    p.add_argument("network")
    p.add_argument("case")
    p.add_argument("decision", choices=("detected", "missed"))
    p.add_argument("reason")
    p.add_argument("--quote", default="")
    a = p.parse_args()
    record(a.results, a.network, a.case, a.decision, a.reason, a.quote)
