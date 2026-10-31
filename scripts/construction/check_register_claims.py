import json
from source_paths import output_path

register=json.loads(output_path("theorem_register.json").read_text())
claims=sorted({claim["theorem"] for group in register["groups"] for claim in group["claim_dependencies"]})
for group in register["groups"]:
    for claim in group["claim_dependencies"]:
        for key in claim["evidence_keys"]:
            if key not in register["evidence_catalog"]:raise ValueError("dangling evidence dependency")
text="import TDN\n\n"+"\n".join("#check "+claim for claim in claims)+"\n"
output_path("RegisterClaims.lean").write_text(text)
print(json.dumps({"unique_claim_references":len(claims),"groups":len(register["groups"])}))
