"""Index every Enterprise Gray table row without conflating reused requirement IDs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from validate_evidence import require

SOURCE_PIN = "ae7341370e5fa45f6de0edb3727c03bdd54e62172f22c895f61cce3e240315fc"
TABLE_COUNTS = {8: 23, 9: 5, 10: 21, 11: 23, 12: 2, 13: 1}
CAPABILITIES = {8: "general", 9: "multiple capability packages", 10: "centralized management",
                11: "scalability", 12: "site survivability", 13: "testing"}


def extract(text):
    rows = []
    table = None
    current = None
    for raw in text.splitlines():
        match = re.fullmatch(r"L(\d+)@P([\d-]+): (.*)", raw)
        if match is None or not 785 <= int(match[1]) <= 1294:
            continue
        line, pages, body = int(match[1]), match[2], match[3]
        heading = re.match(r"Table (\d+)\.", body)
        if heading:
            table = int(heading[1])
            current = None
            continue
        if re.match(r"10\.\d+ ", body):
            current = None
            continue
        #* Alternative IDs can occupy a line alone. A row starts with its ID and actual text.
        start = re.match(r"(EG-[A-Z]{2}-\d+)\s+([A-Za-z].*)", body)
        if start:
            require(table in CAPABILITIES, "Unknown requirement table")
            current = {"key": f"EG-v1.2.0-T{table:02d}-{start[1]}", "table": table,
                       "requirement_id": start[1], "capability_section": CAPABILITIES[table],
                       "first_indexed_line": line, "pdf_pages": [], "raw_indexed_lines": [],
                       "construction_status": "requires_clause_specific_formalization_and_evidence"}
            rows.append(current)
        if current is not None:
            current["raw_indexed_lines"].append(raw)
            current["pdf_pages"] = sorted(set(current["pdf_pages"]) |
                {int(p) + 1 for p in pages.split("-")})
    counts = Counter(row["table"] for row in rows)
    require(dict(counts) == TABLE_COUNTS, "Requirement table coverage changed")
    require(len({row["key"] for row in rows}) == len(rows), "Duplicate table-scoped requirement key")
    identifiers = Counter(row["requirement_id"] for row in rows)
    for row in rows:
        row["id_reused_in_another_table"] = identifiers[row["requirement_id"]] > 1
        row["source_text"] = "\n".join(re.sub(r"^L\d+@P[\d-]+: ", "", line)
                                         for line in row["raw_indexed_lines"])
        if "Requirement has been relocated" in row["source_text"]:
            row["construction_status"] = "delegated_to_named_key_management_annex"
        if row["table"] == 8 and row["requirement_id"] in {
                "EG-FW-1", "EG-FW-2", "EG-FW-3", "EG-FW-4", "EG-FW-5", "EG-FW-6",
                "EG-FW-8", "EG-FW-9", "EG-FW-10", "EG-FW-11", "EG-FW-12", "EG-FW-13"}:
            row["next_work"] = "Define the actual traffic/address/interface condition, preserve explicit control-service exceptions, and bind local rule checks plus required positive traffic."
        elif row["requirement_id"].startswith("EG-PS") or row["requirement_id"] == "EG-FW-18":
            row["next_work"] = "Separate product/approval provenance from technical placement or mechanism facts; no approval is inferred from emulation."
        elif row["table"] == 10:
            row["next_work"] = "Bind selected Gray encryption arrangement, management/data tunnels, processing order, split-tunnel prevention, MTU and selected algorithm branch; preserve source alternatives."
        elif row["table"] == 11:
            row["next_work"] = "Make dynamic-routing/VRF applicability explicit; check permitted components/interfaces, peer authentication, route separation and most-specific permitted routes against actual route policies."
        elif row["table"] == 12:
            row["next_work"] = "Model the selected loss-of-connection case and local authentication/DNS service behavior; finite snapshots alone do not establish every failure schedule."
        elif row["table"] == 13:
            row["next_work"] = "Resolve the referenced EG Testing Annex and enumerate actual required tests and retained results."
        else:
            row["next_work"] = "Formalize the source condition individually and identify its complete applicability and concrete evidence."
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown", required=True)
    args = parser.parse_args()
    path = Path(args.source)
    require(hashlib.sha256(path.read_bytes()).hexdigest() == SOURCE_PIN, "Reviewed source capture changed")
    rows = extract(path.read_text())
    data = {"source": str(path), "source_sha256": SOURCE_PIN,
            "table_rows": len(rows), "table_counts": TABLE_COUNTS,
            "linked_groups": ["RG-011", "RG-044", "RG-046"], "complete_annex_formalization": False,
            "limitations": ["The index preserves original table text, designations and alternatives together. It does not infer a selected branch from the letters T or O.",
                           "Narrative requirements in sections5–9 and delegated annex duties need additional clause-level accounting. The75 rows do not claim exhaustive sentence extraction.",
                           "Three rows relocate requirements to named key-management annexes. They remain tracked without inventing new requirements.",
                           "EG-AR-25 and EG-AR-26 have different meanings in Tables8 and11. Table-scoped keys preserve both."],
            "rows": rows}
    Path(args.output).write_text(json.dumps(data, indent=2) + "\n")
    parts = ["# Enterprise Gray annex table obligations", "", "The source contains 75 rows across Tables 8–13. Each row uses a table-scoped key because EG-AR-25 and EG-AR-26 are reused for different requirements. The index records open construction work; it does not establish annex compliance.", "", "| Table | Capability section | Rows |", "| --- | --- | ---: |"]
    parts += [f"| {table} | {CAPABILITIES[table]} | {count} |" for table, count in TABLE_COUNTS.items()]
    parts += ["", "The original table text below retains its threshold/objective designation and alternative references. Narrative requirements and delegated annexes remain additional obligations. Optional management does not become a premise of management-free data-path proofs.", ""]
    for row in rows:
        parts += ["## " + row["key"], "", "PDF pages: " + ", ".join(map(str, row["pdf_pages"])), "", "```text", row["source_text"], "```", "", "Construction status: " + row["construction_status"] + ".", "", "Next work: " + row["next_work"], ""]
    Path(args.markdown).write_text("\n".join(parts))
    print(json.dumps({"table_rows": len(rows), "table_counts": TABLE_COUNTS,
                      "complete_annex_formalization": False}))


if __name__ == "__main__":
    main()
