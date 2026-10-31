"""Check referenced names and type-check each claimed whole-specification application."""
import json
from source_paths import output_path
from register_claim_validation import NAME, require, validate_group_claim, validate_scoped_specification

register = json.loads(output_path("theorem_register.json").read_text())
claims = {claim["theorem"] for group in register["groups"] for claim in group["claim_dependencies"]}
for group in register["groups"]:
    current = group.get("current_development", {})
    specification = current.get("specification", {}).get("name")
    if specification:
        claims.add(specification)
    for entry in current.get("general_and_supporting_results", []) + current.get("checked_applications", []):
        claims.add(entry["name"])
require(all(NAME.fullmatch(name) for name in claims), "Unsupported declaration reference syntax")
claims = sorted(claims)
applications = []
scoped_applications = []
for group in register["groups"]:
    for claim in group["claim_dependencies"]:
        for key in claim["evidence_keys"]:
            if key not in register["evidence_catalog"]:
                raise ValueError("Dangling evidence dependency")
    application = validate_group_claim(group, register["evidence_catalog"])
    if application:
        applications.append(application)
    for certificate in group.get("scoped_specification_certificates", []):
        scoped_applications.append(validate_scoped_specification(group, certificate, register["evidence_catalog"]))
text = "import TDN\n\n" + "\n".join("#check " + claim for claim in claims)
text += "\n\n" + "\n".join(applications + scoped_applications) + "\n"
output_path("RegisterClaims.lean").write_text(text)
print(json.dumps({"unique_claim_references": len(claims), "groups": len(register["groups"]),
                  "closed_whole_specification_applications": len(applications),
                  "closed_scoped_specification_applications": len(scoped_applications),
                  "limit": "Lean checks the stated specification instance. Source fidelity, applicability and collector correspondence remain independently reviewed."}))
