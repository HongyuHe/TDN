"""Check declared links against saved live interface and peer identifiers."""

import argparse
import json

from common import BASE, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    capture = json.loads((run / "supervisor-live-interfaces.json").read_text())
    assert capture["returncode"] == 0
    devices = json.loads(capture["stdout"])
    assert all(d["returncode"] == 0 for d in devices)
    lookup = {(d["device"], i["ifname"]): i for d in devices for i in d["interfaces"]}
    results, extras = [], []
    for network in json.loads((run / "deployments.json").read_text()):
        for connection in network["spec"]["links"]:
            a, b = [lookup[(connection[s]["device"], connection[s]["interface"])] for s in ("a", "b")]
            results.append({
                "network": network["id"], "a": connection["a"], "b": connection["b"],
                "a_ifindex": a["ifindex"], "a_peer_index": a.get("link_index"),
                "b_ifindex": b["ifindex"], "b_peer_index": b.get("link_index"),
                "reciprocal": a.get("link_index") == b["ifindex"] and b.get("link_index") == a["ifindex"],
                "up": "UP" in a["flags"] and "UP" in b["flags"],
            })
        for device in network["spec"]["devices"]:
            expected = {i["name"] for i in device["interfaces"]}
            for (name, iface), interface in lookup.items():
                if name == device["id"] and iface not in expected and interface.get("linkinfo", {}).get("info_kind") == "veth":
                    extras.append({"network": network["id"], "device": name, "interface": iface})
    result = {"declared_links": len(results), "reciprocal_links": sum(r["reciprocal"] for r in results),
              "up_links": sum(r["up"] for r in results), "unlisted_veth_interfaces": extras, "links": results,
              "scope": "Declared virtual Ethernet links, checked against reciprocal Linux interface and peer indices. Other kernel processing and host configuration are outside this link correspondence check."}
    output = run / "supervisor-link-validation.json"
    if output.exists():
        assert json.loads(output.read_text()) == result
    else:
        write_json(output, result)
    print(json.dumps({k: v for k, v in result.items() if k != "links"}))


if __name__ == "__main__":
    main()
