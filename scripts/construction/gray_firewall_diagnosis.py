"""Construct actual supported Gray firewall packet cases from fixed captures."""
import json
from pathlib import Path

from outer_gray_cases import make_case
from boundary_application_cases import firewall_case


def main():
    result = {}
    for profile, prefix in [("Baseline", "V31B"), ("Shared", "V31F")]:
        data = json.loads(Path("data/evidence/continuation/Boundary" + profile + ".json").read_text())
        records = data["records"]
        pair_index = next(i for i, p in enumerate(records["pairs"])
                          if p["endpoints"]["source"] == prefix + "_I_B1" and
                          p["endpoints"]["destination"] == prefix + "_I_A1")
        pair = records["pairs"][pair_index]
        source, destination = pair["endpoints"]["sourceAddress"], pair["endpoints"]["destinationAddress"]
        entry = "g1" if profile == "Shared" else "s1"
        reply = make_case(records, prefix + "_GF_A:" + entry, pair_index, 500, 9999)
        esp = firewall_case(records, prefix + "_GF_A", entry, source, destination, "inbound")
        def guard(protocol, framing):
            atoms = [{"protocol": {"name": protocol}},
                     {"sourceRange": {"low": source, "high": source}},
                     {"destinationRange": {"low": destination, "high": destination}}]
            if framing:
                atoms.append("ipsecUDPReplyFramingWithOptions")
            return {"atoms": atoms, "verdict": "allow"}
        result[profile.lower()] = {"reply": reply, "esp": esp, "pair": pair,
                                   "replyGuard": guard("udp", True), "espGuard": guard("esp", False),
                                   "sourcePhase": data["provenance"]}
        result[profile.lower() + "Reply"] = reply
        result[profile.lower() + "Pair"] = pair
        result[profile.lower() + "ReplyGuard"] = guard("udp", True)
        result[profile.lower() + "ESP"] = esp
        result[profile.lower() + "ESPGuard"] = guard("esp", False)
        print(json.dumps({"profile": profile, "replyIngress": records["ifaceNames"][reply["entryIface"]],
                          "replyEgress": records["ifaceNames"][reply["route"]["egress"]],
                          "source": source, "destination": destination}))
    Path("data/evidence/continuation/GrayFirewallDiagnosis.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
