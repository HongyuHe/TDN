"""Convert an earlier typed Lean JSON export to the current overlay field names."""

import argparse
import json
from pathlib import Path


TUNNEL_RECORDS = (
    {"id", "sender", "receiver", "layer", "keyContext", "espTunnelMode", "associatedIPTunnel"},
    {"id", "device", "peer", "layer", "mode", "status", "observationIds"},
    {"id", "espTunnelMode", "associatedIPTunnel", "outboundMACPolicy", "inboundMACPolicy"},
    {"firstSite", "secondSite", "firstComponent", "secondComponent", "layer", "forwardTunnel", "reverseTunnel"},
    {"component", "site", "firewall", "outer", "separateEncryptorSelected", "internalInterfaces"},
)

ZONE_FIELDS = (
    ({"id", "device", "address", "namespaceAddresses", "physical", "externalData"}, ("zone",)),
    ({"location", "level", "tunnelStack"}, ("zone",)),
    ({"sourceZone", "destinationZone", "operation"}, ("sourceZone", "destinationZone")),
    ({"name", "network", "layer", "enabled", "neededForOperation", "aoApproved"}, ("network",)),
    ({"component", "product", "version", "manufacturerGroup", "cryptographicLibraries"}, ("siemZone",)),
)


def upgrade_typed_records(value):
    if isinstance(value, list):
        return [upgrade_typed_records(item) for item in value]
    if not isinstance(value, dict):
        return value

    fields = value.keys()
    renames = {}
    tunnel_header = fields - {"protocol", "mechanism"} == {"layer", "source", "destination"}
    if tunnel_header or any(required <= fields for required in TUNNEL_RECORDS):
        renames["mechanism"] = "protocol"
    if {"innerComponent", "outerComponent", "innerKeyContext", "outerKeyContext", "communicatingSites"} <= fields:
        renames.update(innerMechanism="innerProtocol", outerMechanism="outerProtocol")
    if {"routes", "source_sha256"} <= fields:
        renames["certificates"] = "hints"
    if "index" in value and isinstance(value["index"], dict) and {"earlierRules", "allowed"} <= value["index"].keys():
        renames["witnesses"] = "permitHints"
    if any(old in value and new in value for old, new in renames.items()):
        raise ValueError("The typed record contains both the old field and its replacement")

    updated = {}
    for key, item in value.items():
        #* Replaying the original inventory must reproduce the recorded input, including its old field names.
        if key.startswith("raw") and key != "rawInterfaces":
            updated[key] = item
        else:
            updated[renames.get(key, key)] = upgrade_typed_records(item)
    for required, zone_fields in ZONE_FIELDS:
        if required <= fields:
            for field in zone_fields:
                if updated.get(field) == "local":
                    updated[field] = "hostLocal"
    return updated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path, help="New output path. The original export is preserved.")
    args = parser.parse_args()
    result = upgrade_typed_records(json.loads(args.input.read_text()))
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, ensure_ascii=False)
        output.write("\n")


if __name__ == "__main__":
    main()
