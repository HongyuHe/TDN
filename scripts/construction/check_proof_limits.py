"""Keep increases to Lean's elaboration allowance finite and local to one declaration."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]

def violations(root=ROOT):
    problems = []
    pattern = re.compile(r"\bset_option\s+maxHeartbeats\s+([0-9_]+)\b(.*)")
    for source in [*sorted((root / "TDN").rglob("*.lean")), *sorted((root / "scripts/construction").glob("*.py"))]:
        for number, line in enumerate(source.read_text().splitlines(), 1):
            match = pattern.search(line)
            if match and (int(match[1].replace("_", "")) == 0 or not match[2].strip().startswith("in")):
                problems.append(f"{source.relative_to(root)}:{number}: use a finite per-declaration limit")
    return problems

if __name__ == "__main__":
    errors = violations()
    if errors:
        raise SystemExit("\n".join(errors))
