#!/usr/bin/env python3
"""Audit the required MSC and reusable-network theorems for unapproved axioms."""

from pathlib import Path
import argparse
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"propext", "Classical.choice", "Quot.sound"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-optional", action="store_true", help="also audit full-snapshot and management diagnostics")
    args = parser.parse_args()
    names = []
    for directory in [ROOT / "TDN/MSC", ROOT / "TDN/Network"]:
        for path in directory.glob("*.lean"):
            if not args.include_optional and path.name == "SnapshotDiagnostics.lean":
                continue
            source = path.read_text()
            namespace = re.search(r"^namespace ([\w.]+)$", source, re.M)
            declarations = re.findall(r"^theorem ([\w.]+)", source, re.M)
            if declarations and namespace is None:
                raise SystemExit(f"Missing theorem namespace in {path}")
            names.extend(f"{namespace[1]}.{name}" for name in declarations)
    names.sort()
    if not names or len(names) != len(set(names)):
        raise SystemExit("Missing or ambiguous theorem audit targets")
    lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
    with tempfile.TemporaryDirectory(prefix="msc-axioms-") as temporary:
        source = Path(temporary) / "Audit.lean"
        imports = "import TDN\n" + ("import TDN.MSC.SnapshotDiagnostics\n" if args.include_optional else "")
        source.write_text(imports + "\n".join(f"#print axioms {name}" for name in names) + "\n")
        result = subprocess.run([lake, "env", "lean", str(source)], cwd=ROOT,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    for name in names:
        pattern = rf"'{re.escape(name)}' (?:does not depend on any axioms|depends on axioms: \[([^\]]*)\])"
        match = re.search(pattern, result.stdout)
        if match is None:
            raise SystemExit(f"No axiom audit result for {name}")
        dependencies = set(filter(None, (x.strip() for x in (match[1] or "").split(","))))
        if dependencies - ALLOWED:
            raise SystemExit(f"Unapproved proof axioms for {name}: {sorted(dependencies - ALLOWED)}")
    print(f"Audited {len(names)} MSC and reusable-network theorems; only standard Lean logical axioms were used.")


if __name__ == "__main__":
    main()
