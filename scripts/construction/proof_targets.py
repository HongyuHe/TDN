"""Read the active Lean declarations from the requirements catalog."""
import json
from pathlib import Path


SCOPE = Path(__file__).resolve().parents[2] / "specs/proof_scope.json"


def proof_targets(path=SCOPE):
    rows = json.loads(Path(path).read_text())["groups"]
    selected = {row["id"]: row.get("specification") for row in rows if row["decision"] == "formal"}
    if not selected or len({row["id"] for row in rows}) != len(rows):
        raise ValueError("The scope must list unique requirements and select at least one proof target.")
    return selected


def check_target_map(rows, scope=SCOPE):
    expected = proof_targets(scope)
    actual = {row["rg_id"]: row["specification"] for row in rows}
    if len(actual) != len(rows) or actual.keys() != expected.keys():
        raise ValueError("The accepted specification map must contain exactly the active proof targets.")
    if len(set(actual.values())) != len(actual) or any(
        name and actual[group] != name for group, name in expected.items()
    ):
        raise ValueError("Each selected requirement must map to its own registered Lean definition.")
    return actual
