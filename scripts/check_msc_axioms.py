#!/usr/bin/env python3
"""Fail validation if any public MSC theorem depends on an unapproved axiom."""

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
    names = sorted(name for path in (ROOT / "TDN/MSC").glob("*.lean")
                   if args.include_optional or path.name != "SnapshotDiagnostics.lean"
                   for name in re.findall(r"^theorem (\w+)", path.read_text(), re.M))
    if not names or len(names) != len(set(names)):
        raise SystemExit("Missing or ambiguous theorem audit targets")
    lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
    with tempfile.TemporaryDirectory(prefix="msc-axioms-") as temporary:
        source = Path(temporary) / "Audit.lean"
        imports = "import TDN\n" + ("import TDN.MSC.SnapshotDiagnostics\n" if args.include_optional else "")
        source.write_text(imports + "\n".join(f"#print axioms TDN.MSC.{name}" for name in names) + "\n")
        result = subprocess.run([lake, "env", "lean", str(source)], cwd=ROOT,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    for name in names:
        pattern = rf"'TDN\.MSC\.{name}' (?:does not depend on any axioms|depends on axioms: \[([^\]]*)\])"
        match = re.search(pattern, result.stdout)
        if match is None:
            raise SystemExit(f"No axiom audit result for {name}")
        dependencies = set(filter(None, (x.strip() for x in (match[1] or "").split(","))))
        if dependencies - ALLOWED:
            raise SystemExit(f"Unapproved proof axioms for {name}: {sorted(dependencies - ALLOWED)}")
    print(f"Audited {len(names)} MSC theorems; only standard Lean logical axioms were used.")


if __name__ == "__main__":
    main()
