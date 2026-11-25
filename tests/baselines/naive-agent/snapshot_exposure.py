"""Find fault-specific evidence on the actual result pages returned to the snapshot Detector."""
import json
import re

from snapshot_inputs import LIVE, RUN


def read(path):
    return json.loads(path.read_text())


def visible(case, target, method="astra"):
    family, network = case.split("/")
    change = read(LIVE/"trials"/case/"change.json")
    subject = set(change.get("ports", []))
    features = set()
    views = set()
    pages = 0
    witness = None
    with (RUN/"trials"/case/method/"events.jsonl").open() as records:
        for line_number, line in enumerate(records, 1):
            event = json.loads(line)
            item = event.get("item", {})
            args = item.get("arguments", {})
            if (event.get("type")!="item.completed" or item.get("tool")!="observe"
                    or args.get("network")!=network or item.get("status")!="completed"):
                continue
            for block in (item.get("result") or {}).get("content", []):
                try:
                    envelope = json.loads(block.get("text",""))
                except ValueError:
                    continue
                if not isinstance(envelope,dict) or not envelope.get("data"):
                    continue
                pages += 1
                view = args["view"]
                for part in envelope["data"].splitlines():
                    try:
                        row = json.loads(part)
                    except ValueError:
                        row = {}
                    if not isinstance(row,dict):
                        row = {}
                    endpoints = [row.get(k,{}) for k in ("a","b")]
                    owners = {row.get("device_id"),row.get("device"), *[x.get("device") for x in endpoints if isinstance(x,dict)]}
                    if args.get("devices")!=[target] and target not in owners:
                        continue
                    views.add(view)
                    previous = len(features)
                    if change.get("inserted_rule") and change["inserted_rule"] in part:
                        features.add("the exact inserted IPv4 rule")
                    if family=="inner-peer-loopback" and "127.0.0.2" in part and view in {"raw","tunnels","gateway-connections"}:
                        features.add("the loopback address in the gateway records")
                    if family in {"inner-mode","outer-mode"} and view in {"raw","tunnels","gateway-connections"}:
                        if re.search(r'"mode"\s*:\s*"transport"|mode\s*=\s*transport|mode\s*:\s*TRANSPORT|\bTRANSPORT,',part,re.I):
                            features.add("transport mode in the gateway records")
                    if view=="link-census" and row.get("reciprocal") is False:
                        for endpoint in endpoints:
                            if endpoint.get("device")==target and endpoint.get("interface") in subject:
                                features.add("the unpaired "+endpoint["interface"]+" interface")
                    if len(features)>previous and witness is None:
                        witness=line_number
    return {"pages_for_network":pages,"identified_target_views":sorted(views),
            "direct_text":sorted(features),"first_matching_event_line":witness}
