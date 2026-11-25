"""Replay TDN-generated packet witnesses on the selected worker namespaces."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
from pathlib import Path

from packet_probe import probe
from worker import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployments", required=True)
    parser.add_argument("--witnesses", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    deployments = {d["id"]: d for d in json.loads(Path(args.deployments).read_text())}
    witnesses = json.loads(Path(args.witnesses).read_text())["witnesses"]
    def check(sample):
        packet = sample["packet"]
        if packet["protocol"] not in {"tcp", "udp", "gre"}:
            return {"id": sample["id"], "status": "not_replayed", "reason": "The live probe supports TCP, UDP and GRE"}
        parameters = {"chain": sample["chain"], "source": str(ipaddress.IPv4Address(packet["source"])),
                      "destination": str(ipaddress.IPv4Address(packet["destination"])),
                      "protocol": packet["protocol"], "ingress": packet["ingress"], "egress": packet["egress"],
                      "destination_port": packet["destinationPort"]}
        try:
            result = probe({"topology": deployments[sample["network"]]["spec"]},
                           {"case_id": sample["id"], "device": sample["device"], "parameters": parameters})
            return {"id": sample["id"], "status": "observed", "result": result}
        except Exception as error:
            return {"id": sample["id"], "status": "error", "error": str(error)}
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(check, witnesses))
    write_json(args.output, results)
    print(json.dumps({"replayed": sum(r["status"] == "observed" for r in results),
                      "confirmed": sum(r["status"] == "observed" and r["result"]["result"]["observed"] for r in results),
                      "errors": [r for r in results if r["status"] == "error"]}))


if __name__ == "__main__":
    main()
