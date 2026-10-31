"""Inspect a continuation's source boundaries and declared requirement coverage."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


def without_comments(source):
    #* Preserve line numbers while removing nested Lean comments and string contents.
    output = []
    depth = 0
    quoted = False
    index = 0
    while index < len(source):
        pair = source[index:index + 2]
        char = source[index]
        if depth:
            if pair == "/-":
                depth += 1
                output.extend("  ")
                index += 2
                continue
            if pair == "-/":
                depth -= 1
                output.extend("  ")
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
        elif quoted:
            if char == "\\" and index + 1 < len(source):
                output.extend("  ")
                index += 2
                continue
            if char == '"':
                quoted = False
            output.append("\n" if char == "\n" else " ")
        elif pair == "/-":
            depth = 1
            output.extend("  ")
            index += 2
            continue
        elif pair == "--":
            end = source.find("\n", index)
            end = len(source) if end == -1 else end
            output.extend(" " * (end - index))
            index = end
            continue
        elif char == '"':
            quoted = True
            output.append(" ")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-current-map", action="store_true")
    args = parser.parse_args()
    root = args.workspace.resolve()
    records = []
    violations = []
    forbidden = []
    declarations = {}
    for path in sorted((root / "TDN").rglob("*.lean")):
        relative = path.relative_to(root)
        source = path.read_text()
        clean = without_comments(source)
        imports = [name for line in re.findall(r"^import[ \t]+([^\n]+)", clean, re.MULTILINE)
                   for name in line.split()]
        layer = relative.parts[1]
        for imported in imports:
            allowed = True
            if layer == "Semantics" and imported.startswith("TDN."):
                allowed = imported.startswith("TDN.Semantics.")
            if layer == "Targets" and imported.startswith("TDN."):
                allowed = imported.startswith(("TDN.Semantics.", "TDN.Targets."))
            if not allowed:
                violations.append({"path": str(relative), "import": imported})
        found = []
        for match in re.finditer(r"^\s*(?:(?:private|protected|noncomputable)\s+)*(def|theorem|lemma|axiom)\s+([\w.]+)", clean, re.MULTILINE):
            entry = {"kind": match[1], "name": match[2], "path": str(relative),
                     "line": clean.count("\n", 0, match.start(1)) + 1}
            found.append(entry)
            declarations.setdefault(match[2], []).append(entry)
        for match in re.finditer(r"\b(sorry|admit|axiom)\b", clean):
            forbidden.append({"path": str(relative), "token": match[1],
                              "line": clean.count("\n", 0, match.start()) + 1})
        records.append({"path": str(relative), "sha256": hashlib.sha256(source.encode()).hexdigest(),
                        "imports": imports, "declarations": found})
    register_path = root / "artifacts/construction" / args.run / "theorem_register.json"
    register = json.loads(register_path.read_text())
    targets = []
    for group in register["groups"]:
        name = group["top_level_target"].split(".")[-1]
        targets.append({"group_id": group["group_id"], "name": name,
                        "declarations": declarations.get(name, [])})
    ids = [group["group_id"] for group in targets]
    expected = [f"RG-{n:03d}" for n in range(1, 77)]
    map_path = register_path.with_name("current_declaration_map.json")
    map_issues = []
    checked_locations = 0
    source_records = {item["path"]: item for item in records}
    if not map_path.is_file():
        map_issues.append({"issue": "declaration_map_missing"})
    else:
        mapping = json.loads(map_path.read_text())
        if sorted(item["group_id"] for item in mapping) != expected:
            map_issues.append({"issue": "declaration_map_group_ids"})
        for group in mapping:
            entries = [group.get("specification", {})]
            entries.extend(group.get("general_and_supporting_results", []))
            entries.extend(group.get("checked_applications", []))
            for entry in entries:
                locations = entry.get("locations", [])
                if entry.get("location"):
                    locations = [*locations, entry["location"]]
                if not locations:
                    map_issues.append({"group_id": group["group_id"],
                                       "name": entry.get("name"), "issue": "location_missing"})
                for location in locations:
                    checked_locations += 1
                    source = source_records.get(location.get("path"))
                    issue = None
                    if source is None:
                        issue = "source_not_in_active_theory"
                    elif location.get("source_sha256") != source["sha256"]:
                        issue = "source_hash_changed"
                    else:
                        name = entry.get("name", "").split(".")[-1]
                        matches = [decl for decl in source["declarations"]
                                   if decl["name"].split(".")[-1] == name
                                   and decl["line"] == location.get("line")
                                   and decl["kind"] == location.get("kind")]
                        if len(matches) != 1:
                            issue = "declaration_location_mismatch"
                    if issue:
                        map_issues.append({"group_id": group["group_id"],
                                           "name": entry.get("name"),
                                           "path": location.get("path"), "issue": issue})
    result = {
        "at": datetime.now(timezone.utc).isoformat(), "workspace": str(root),
        "run": args.run, "scope": "Static source inspection; compilation, source fidelity, and premise sufficiency require separate validation.",
        "all_76_register_ids": sorted(ids) == expected,
        "targets_with_named_declaration": sum(bool(t["declarations"]) for t in targets),
        "declaration_map_locations_checked": checked_locations,
        "declaration_map_issues": map_issues,
        "module_boundary_violations": violations, "unproved_tokens": forbidden,
        "targets": targets, "sources": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    summary = {key: result[key] for key in ["all_76_register_ids", "targets_with_named_declaration", "module_boundary_violations", "unproved_tokens"]}
    summary["declaration_map_issue_count"] = len(map_issues)
    print(json.dumps(summary))
    if (violations or forbidden or sorted(ids) != expected
            or any(not target["declarations"] for target in targets)
            or (args.require_current_map and map_issues)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
