"""Migrate active typed interfaces while preserving each retained raw capture."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from outer_gray_records import project


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def interface_rows(value):
    if isinstance(value, dict):
        if {"id", "device", "zone", "address", "physical", "mtu"}.issubset(value):
            yield value
        else:
            for child in value.values():
                yield from interface_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from interface_rows(child)


def migrate(root, record):
    directory = root / "data/evidence/continuation"
    canonical = {}
    sources = {}
    for stem in ["OuterToGray_Baseline", "OuterToGray_Shared", "Perimeter_Baseline", "Perimeter_Shared", "GrayFirewallShared"]:
        path = directory / (stem + ".json")
        saved = json.loads(path.read_text())
        raw = saved.get("rawBundle", saved.get("native", {}).get("rawBundle"))
        projected = project(raw)
        rows = {row["id"]: row for row in projected["interfaces"]}
        canonical[stem] = rows
        sources[stem] = {"path": str(path.relative_to(root)), "rawSHA256": digest(json.dumps(raw, sort_keys=True).encode())}
    changes = []
    before_dir = record / "before"
    before_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(directory.glob("*.json")):
        saved = json.loads(path.read_text())
        if not any("namespaceAddresses" not in row for row in interface_rows(saved)):
            continue
        original = path.read_bytes()
        before = copy.deepcopy(saved)
        provenance = []
        if path.stem == "BoundaryMACsec":
            from macsec_boundary_records import prepare
            saved = prepare(saved["rawBundle"], saved["sourceSha256"])
        else:
            for row in interface_rows(saved):
                if row["id"].startswith("V31B_"):
                    stem = "OuterToGray_Baseline" if path.stem.startswith("OuterGray") else "Perimeter_Baseline"
                elif row["id"].startswith("V31F_"):
                    stem = "OuterToGray_Shared" if path.stem.startswith("OuterGray") else "GrayFirewallShared" if path.stem.startswith("GrayFirewall") else "Perimeter_Shared"
                else:
                    raise ValueError("typed interface has no recorded phase: " + row["id"])
                selected = canonical[stem][row["id"]]
                row["zone"] = selected["zone"]
                row["namespaceAddresses"] = selected["namespaceAddresses"]
                provenance.append(stem)
        if "records" in saved and "interfaces" in saved["records"]:
            old_raw = before.get("rawBundle", before.get("native", {}).get("rawBundle"))
            new_raw = saved.get("rawBundle", saved.get("native", {}).get("rawBundle"))
            if old_raw != new_raw:
                raise ValueError("raw capture changed")
            if len(before["records"]["interfaces"]) != len(saved["records"]["interfaces"]):
                raise ValueError("interface inventory changed")
        (before_dir / path.name).write_bytes(original)
        result = (json.dumps(saved, indent=2, sort_keys=True) + "\n").encode()
        path.write_bytes(result)
        changes.append({"path": str(path.relative_to(root)), "beforeSHA256": digest(original),
                        "afterSHA256": digest(result), "typedInterfaces": len(list(interface_rows(saved))),
                        "phases": [sources[stem] for stem in sorted(set(provenance))]})
    record.mkdir(parents=True, exist_ok=True)
    (record / "manifest.json").write_text(json.dumps({"normalizer": "migrate_local_projection.py",
        "changes": changes, "scope": "Only active typed interface zone and complete per-interface namespace addresses; original raw captures and all port/rule inventories remain preserved."}, indent=2) + "\n")
    return changes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=Path("."))
    parser.add_argument("--record", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(migrate(args.workspace, args.record), indent=2))


if __name__ == "__main__":
    main()
