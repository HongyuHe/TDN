"""Retain full raw address views for the two boundary-policy captures."""
import hashlib
import ipaddress
import json
from pathlib import Path


def main():
    for profile in ["Baseline", "Shared"]:
        source = Path(f"data/evidence/continuation/Boundary{profile}.json")
        saved = json.loads(source.read_text())
        raw = saved["native"]["rawBundle"]
        by_id = {record["id"]: record for record in raw["sourceInterfaces"]}
        if set(by_id) != {record["id"] for record in saved["records"]["interfaces"]}:
            raise ValueError("The projection must retain every raw interface identifier")
        interfaces = []
        for interface in saved["records"]["interfaces"]:
            addresses = [item for item in by_id[interface["id"]]["addresses"] if item["family"] == "inet"]
            if len(addresses) > 1:
                raise ValueError("Multiple raw IPv4 addresses require an explicit expansion")
            interfaces.append({**interface, "address": int(ipaddress.ip_address(addresses[0]["local"])) if addresses else None})
        result = {"rawInterfaces": interfaces, "source": str(source),
                  "sourceSHA256": hashlib.sha256(source.read_bytes()).hexdigest()}
        target = source.with_stem(f"BoundaryProjection{profile}")
        target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"target": str(target), "interfaces": len(interfaces)}))


if __name__ == "__main__":
    main()
