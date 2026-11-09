"""One-time migration: Lean exports v3 values; Python edits only command locations."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def candidates():
    for path in sorted((ROOT / "TDN/Deployments").glob("*.lean")):
        text = path.read_text()
        namespace = re.search(r"^namespace ([\w.]+)", text, re.M)
        if not namespace:
            continue
        pattern = r'^def (\w+)\s*:\s*([^\n]+?)\s*(?::=\s*(?=[\[{⟨"0-9])|where(?=\s*\n))'
        declarations = []
        for match in re.finditer(pattern, text, re.M):
            name, ty = match[1], match[2]
            if "Config" in ty or "ProvisioningExecutor" in ty or "MACsecProtection" in ty:
                continue
            start = match.start()
            next_decl = re.search(r'\n(?=(?:def |lemma |theorem |instance |end |/--|/-!))', text[match.end():])
            end = match.end() + next_decl.start() if next_decl else len(text)
            stack = []
            for scope in re.finditer(r"^(namespace|end)\b\s*([\w.]*)", text[:start], re.M):
                if scope[1] == "namespace":
                    stack.append(scope[2])
                elif stack:
                    stack.pop()
            declarations.append({"name": name, "type": ty.strip(), "start": start, "end": end,
                                 "qualified": ".".join(stack) + "." + name})
        if declarations:
            yield path, declarations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if any("load_network_records " in p.read_text() for p in (ROOT / "TDN/Deployments").glob("*.lean")):
        raise SystemExit("The active sources are already migrated. Re-export from an isolated checkout of v3.")
    directory = ROOT / "data/evidence"
    directory.mkdir(parents=True, exist_ok=True)
    items = list(candidates())
    if args.export:
        lines = ["import TDN", "import TDN.Import.SnapshotLoader", "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0", "set_option maxErrors 10000"]
        for path, declarations in items:
            output = directory / (path.stem + ".json")
            output.unlink(missing_ok=True)
            for declaration in declarations:
                lines.append(f'export_network_records {declaration["qualified"]} to "{output}" ["{declaration["qualified"]}"]')
        temp = Path(tempfile.mkdtemp(prefix="tdn-migrate-")) / "Export.lean"
        temp.write_text("\n".join(lines) + "\n")
        print(str(temp), flush=True)
        with (directory / "migration.log").open("w") as log:
            result = subprocess.run(["lake", "env", "lean", str(temp)], cwd=ROOT, stdout=log, stderr=log)
        print("export exit", result.returncode, flush=True)
    report = []
    for path, declarations in items:
        output = directory / (path.stem + ".json")
        exported = json.loads(output.read_text()) if output.exists() else {}
        text = path.read_text()
        selected = [d for d in declarations if d["qualified"] in exported]
        report.append({"module": str(path.relative_to(ROOT)), "exported": len(selected),
                       "remaining": [d["name"] for d in declarations if d["qualified"] not in exported]})
        if args.apply and selected:
            for declaration in reversed(selected):
                command = f'load_network_records {declaration["name"]} : {declaration["type"]} from "../../data/evidence/{path.stem}.json" ["{declaration["qualified"]}"]\n'
                text = text[:declaration["start"]] + command + text[declaration["end"]:]
            text = "import TDN.Import.SnapshotLoader\n" + text
            path.write_text(text)
    (directory / "migration.json").write_text(json.dumps(report, indent=2) + "\n")
    print("modules", len(report), "records", sum(r["exported"] for r in report), "unexported", sum(len(r["remaining"]) for r in report))


if __name__ == "__main__":
    main()
