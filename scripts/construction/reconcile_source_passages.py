"""Link extraction fragments to original source units and separate clause records."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def preserve(path):
    data = path.read_bytes()
    saved = RUN / "assessment-revisions" / (hashlib.sha256(data).hexdigest() + "-" + path.name)
    saved.parent.mkdir(exist_ok=True)
    if not saved.exists():
        saved.write_bytes(data)


def fragment_kind(text):
    value = text.strip()
    if value in {"nsa.", "gov.", "niapccevs."}:
        return "split_url"
    if re.fullmatch(r"(?:[0-9]+[.)]|[Sge]\.)", value):
        return "split_reference_or_abbreviation"
    if value.startswith(("gov/resources/", "gov/Resources/", "org/")):
        return "split_url_continuation"
    return None


def main():
    path = RUN / "theorem_register.json"
    register = json.loads(path.read_text())
    source_path = Path("data/extraction/source/source_index.jsonl")
    indexed = [json.loads(line) for line in source_path.read_text().splitlines()]
    buckets = {}
    for row in indexed:
        unit = re.sub(r"\.s[0-9]+$", "", row["source_id"])
        buckets.setdefault(unit, []).append(row)
    source = {}
    for unit, rows in buckets.items():
        rows.sort(key=lambda row: row["document_order"])
        if len(rows) == 1:
            source[unit] = rows[0]
        else:
            raw = "".join(row["raw_text"] for row in rows)
            locations = []
            for row in rows:
                for location in row["locations"]:
                    if location not in locations:
                        locations.append(location)
            source[unit] = {"text": re.sub(r"\s+", " ", raw).strip(), "locations": locations,
                            "reconstructed_from": [row["source_id"] for row in rows]}
    preserve(path)
    ledger = {"at": datetime.now(timezone.utc).isoformat(),
              "source_index_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
              "scope": "Table requirements have distinct source-clause records. Narrative units retain their original context and need explicit decomposition where several obligations occur. Fragment classification never discharges a parent obligation.",
              "groups": []}
    totals = {"groups": 0, "source_passages": 0, "extraction_fragments": 0,
              "numbered_clause_records": 0, "narrative_units": 0}
    for group in register["groups"]:
        units = {}
        clauses = {row["source_id"]: row for row in group["clause_progress"]}
        passage_links = []
        for passage in group["source_passages"]:
            sid = passage["source_id"]
            unit_id = re.sub(r"\.s[0-9]+$", "", sid)
            if unit_id not in source:
                raise ValueError("Original source unit absent: " + unit_id)
            units.setdefault(unit_id, []).append(passage)
            kind = fragment_kind(passage["text"])
            link = {"source_id": sid, "source_unit_id": unit_id,
                    "role": "extraction_fragment" if kind else "source_passage",
                    "fragment_kind": kind, "counted_as_independent_requirement": False}
            if kind:
                row = clauses[sid]
                row["status"] = "context_only"
                row["reason"] = "Extraction fragment linked to original source unit " + unit_id + ". The parent source obligation retains its own status."
                row["formalization_work_remaining"] = ""
                row["parent_source_unit"] = unit_id
                row["current_scoped_applications"] = []
                totals["extraction_fragments"] += 1
            passage_links.append(link)
        records = []
        for unit_id, passages in units.items():
            original = source[unit_id]
            match = re.match(r"(MSC-[A-Z]+-[0-9]+)\b", original["text"])
            source_ids = [p["source_id"] for p in passages]
            explicit = [clauses[sid] for sid in source_ids if clauses[sid]["status"] == "established"]
            alternatives = [clauses[sid] for sid in source_ids if clauses[sid]["status"] == "not_applicable"]
            record = {"source_unit_id": unit_id, "source_passage_ids": source_ids,
                      "original_text": original["text"], "locations": original["locations"],
                      "source_reconstruction": original.get("reconstructed_from", [unit_id]),
                      "clause_id": match[1] if match else None,
                      "record_kind": "numbered_requirement" if match else "narrative_unit",
                      "applicability": group["applicability"],
                      "threshold_objective_marker": (
                          "threshold_equals_objective" if "T=O" in original["text"] else
                          "see_original_table" if match else "see_original_context"),
                      "decomposition_complete": bool(match),
                      "formal_specification": group.get("formal_definition"),
                      "exact_clause_result": explicit if match and len(passages) == 1 else [],
                      "status": "established_selected_scope" if match and len(passages) == 1 and explicit
                                else "not_applicable_selected_alternative" if match and len(passages) == 1 and alternatives
                                else "clause_application_review_pending" if match else "narrative_decomposition_review_pending",
                      "completion_claim": bool(match and len(passages) == 1 and explicit),
                      "alternative_accounting": alternatives}
            records.append(record)
            totals["numbered_clause_records" if match else "narrative_units"] += 1
        group["source_clause_records"] = records
        group["source_passage_links"] = passage_links
        ledger["groups"].append({"group_id": group["group_id"], "clauses": records,
                                 "passage_links": passage_links})
        totals["groups"] += 1
        totals["source_passages"] += len(passage_links)
    if totals["groups"] != 76 or totals["source_passages"] != 749:
        raise ValueError("Source accounting changed")
    ledger["counts"] = totals
    output = RUN / "source-clause-accounting.json"
    if output.exists():
        preserve(output)
    output.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n")
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(totals))


if __name__ == "__main__":
    main()
