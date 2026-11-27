"""Prepare offline reader inputs and audit the rendered evidence for operator metadata."""

from collections import defaultdict
from datetime import datetime
from ipaddress import ip_interface
import gzip
import hmac
import json
import re

from scale.design import ALL_BY_NAME
from snapshot_inputs import digest, validate_reader_bytes

LABELS = {
    "operator namespace": rb"\b(?:tdn-disconnected-[a-z0-9]+|tns-[0-9a-f]{6,}|tdn-m-[0-9a-f]{5,}|tdm[0-9a-f]{8})\b",
    "operator lease or temporary configuration": rb"(?:tdn-rg-rollback-|tdn-naive-rg-mode-lease|tdn-extra-child\.conf|/var/tmp/tdn-scale-study)",
    "private requirement identifier": rb"\bRG-[0-9]{3}(?:\.[0-9]+)?\b",
}


def canonical_mount(data):
    return re.sub(
        rb"/var/tmp/tdn-scale-study/(?:Base|10xLevels|10xDevices)/state(?![\w-])",
        b"/[deployment]",
        data,
    )


def marker_counts(data):
    lower = data.lower()
    counts = {
        kind: n for kind, pattern in LABELS.items() if (n := len(re.findall(pattern.lower(), lower)))
    }
    counts.update({case: n for case in ALL_BY_NAME if (n := lower.count(case.encode()))})
    return counts


def encoding(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()


def anonymize_collector_ids(views, seed):
    refs = {}
    for view in ("links", "raw", "processing"):
        for entry in views.get(view, []):
            key = entry["record"].get("id")
            if isinstance(key, str) and re.fullmatch(r"(?:link|obs|processing)-[0-9]+", key):
                prefix = key.split("-")[0]
                token = hmac.digest(seed, b"ref/" + key.encode(), "sha256").hex()[:24]
                refs[key] = prefix + "-" + token
                entry["record"]["id"] = refs[key]
    if len(set(refs.values())) != len(refs):
        raise ValueError("Two collector references mapped to the same public identifier")

    def update_references(record):
        if isinstance(record, list):
            for item in record:
                update_references(item)
        elif isinstance(record, dict):
            for field, value in record.items():
                if field == "observation_ids":
                    record[field] = [refs[v] for v in value]
                elif field == "observation_id":
                    record[field] = refs[value]
                elif field in {"expected_device_ids", "expected_interface_ids"}:
                    record[field] = sorted(
                        value,
                        key=lambda i: hmac.digest(seed, b"inventory/" + i.encode(), "sha256"),
                    )
                elif isinstance(value, (list, dict)):
                    update_references(value)

    for rows in views.values():
        update_references(rows)


def nft_rule_counters(value):
    if isinstance(value, list):
        for item in value:
            nft_rule_counters(item)
    elif isinstance(value, dict):
        counter = value.get("counter")
        if isinstance(counter, dict):
            counter.pop("packets", None)
            counter.pop("bytes", None)
        for item in value.values():
            nft_rule_counters(item)


_UNIT = r"\d+(?:\.\d+)?\s*(?:milliseconds?|seconds?|minutes?|hours?|days?|weeks?|ms|s|m|h|d|w)\b"
_DURATION = _UNIT + r"(?:(?:\s+|,\s*)" + _UNIT + r")*"
_TEST_NET = re.compile(
    r"(?<![\d.])(?:192\.0\.2|198\.51\.100|203\.0\.113)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)"
)


def fixture_signature(kind, output, assigned_addresses=()):
    if not isinstance(output, str):
        return None
    if _TEST_NET.search(output):
        return "an RFC 5737 documentation address"
    if re.fullmatch(r"(?:convergence-)?filters[46]", kind):
        if re.search(r"(?m)(?:^|\s)(?:-p|--protocol)\s+253(?=\s|$)", output):
            return "the historical experimental IP protocol"
        if re.search(r"--(?:s|d)?ports?\s+[^\s]*\b3910[1-8]\b", output):
            return "a historical diagnostic service port"
        for candidate in re.findall(r"(?:^|\s)-(?:s|d)\s+((?:\d{1,3}\.){3}240)(?:/32)?(?=\s|$)", output):
            if candidate not in assigned_addresses:
                return "an unassigned historical diagnostic endpoint"
    if kind == "nft-hooks" and output.lstrip().startswith("{"):
        for command in json.loads(output).get("nftables", []):
            for expression in command.get("rule", {}).get("expr", []):
                match = expression.get("match", {})
                left = match.get("left")
                if not isinstance(left, dict):
                    continue
                field = left.get("payload", {}).get("field", left.get("meta", {}).get("key"))
                right = match.get("right")
                values = right.get("set", []) if isinstance(right, dict) else [right]
                if field in {"protocol", "nexthdr", "l4proto"} and any(str(v) == "253" for v in values):
                    return "the historical experimental IP protocol"
                if field in {"sport", "dport"} and any(
                    str(v) in {str(p) for p in range(39101, 39109)} for v in values
                ):
                    return "a historical diagnostic service port"
    if kind == "traffic-control-filters":
        for rule in json.loads(output):
            if rule.get("kind") == "matchall" and re.search(
                r'"(?:drop|shot)"', json.dumps(rule.get("options", {})), re.I
            ):
                return "the historical all-packet drop filter"
    return None


def validate_traffic_control(rows, devices):
    expected, observed, qdiscs = set(), set(), set()
    for item in rows:
        r = item["record"]
        if r["kind"] not in {"traffic-control-qdiscs", "traffic-control-filters"}:
            continue
        dev = r["device_id"]
        if dev not in devices or r["returncode"] != 0:
            raise ValueError("Incomplete traffic-control observation")
        entries = json.loads(r["stdout"])
        if not isinstance(entries, list):
            raise ValueError("Invalid traffic-control observation")
        if r["kind"] == "traffic-control-qdiscs":
            if dev in qdiscs:
                raise ValueError("Duplicate traffic-control device observation")
            qdiscs.add(dev)
            for q in entries:
                if q.get("kind") in {"ingress", "clsact"}:
                    expected.add((dev, q["dev"], "ingress"))
                if q.get("kind") == "clsact":
                    expected.add((dev, q["dev"], "egress"))
        else:
            cmd = r["command"]
            if not isinstance(cmd, list) or len(cmd) < 3 or cmd[-3] != "dev":
                raise ValueError("Unidentified traffic-control interface")
            observed.add((dev, cmd[-2], cmd[-1]))
    if qdiscs != set(devices) or observed != expected:
        raise ValueError("Missing device or interface traffic-control observations")


def measurement_text(kind, value):
    if kind == "sas":
        value = re.sub(
            r"(?i)\b(?:rekeying|reauth(?:enticating)?|expires?) in\s+" + _DURATION,
            lambda m: m[0].split()[0] + " in [time omitted]",
            value,
        )
        value = re.sub(r"(?i)\b" + _DURATION + r"\s*ago\b", "[age omitted]", value)
        value = re.sub(
            r"\b(established|install-time|rekey-time|reauth-time|use-in|use-out|life-time)=\d+\b",
            r"\1=[time omitted]",
            value,
        )
        value = re.sub(
            r"(?i)\b\d+[ \t]+(bytes_[io])\b(?:[ \t]*\([ \t]*\d+[ \t]+(?:pkts?|packets?)\b[^)\n]*\))?",
            r"[count omitted] \1", value,
        )
        value = re.sub(
            r"(?im)^([ \t]*(?:in|out)[ \t]+[^,\n]+,)[ \t]*\d+[ \t]+bytes?,[ \t]*\d+[ \t]+(?:packets?|pkts?)"
            r"(?:,[ \t]*(?:\[age omitted\]|never|unused))?[ \t]*$",
            r"\1 [traffic counters omitted]", value,
        )
        value = re.sub(
            r'(?i)("(?:bytes|packets|pkts)[-_](?:in|out|i|o)"[ \t]*:[ \t]*)(?:"\d+"|\d+)',
            r'\1"[count omitted]"', value,
        )
        return re.sub(
            r"(?i)\b((?:bytes|packets|pkts)[-_](?:in|out|i|o)[\"']?[ \t]*[:=][ \t]*[\"']?)\d+\b",
            r"\1[count omitted]", value,
        )
    if kind in {
        "states",
        "convergence-states",
        "policies",
        "convergence-policies",
        "xfrm-states-detailed-nokeys",
        "xfrm-policies-detailed",
        "xfrm-policy-main",
        "xfrm-policy-sub",
    }:
        value = re.sub(
            r"(?m)^(\s*lifetime current:[ \t]*\n[ \t]*)\d+\(bytes\),[ \t]*\d+\(packets\)",
            r"\1[count omitted](bytes), [count omitted](packets)", value,
        )
        value = re.sub(r"(?m)^[ \t]*lastused [^\n]+\n?", "", value)
        value = re.sub(
            r"(?m)^(\s*anti-replay context:) seq \S+, oseq \S+, bitmap \S+",
            r"\1 [sequence counters omitted]", value,
        )
        return re.sub(
            r"(?m)^(\s*)add (?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d|-|0) use [^\n]+$",
            r"\1add [time omitted] use [time omitted]",
            value,
        )
    if re.fullmatch(r"(?:convergence-)?filters[46]", kind):
        value = re.sub(r"(?m)^\[\d+:\d+\]\s+(?=-A\s)", "", value)
        value = re.sub(r"(?m)^(:\S+\s+\S+)\s+\[\d+:\d+\](?=\s*$)", r"\1", value)
        tokens = r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?<!\S)-c[ \t]+\d+[ \t]+\d+(?=\s|$)'''
        return re.sub(tokens, lambda match: match.group(1) or "", value)
    if kind == "nft-hooks" and value.lstrip().startswith("{"):
        rules = json.loads(value)
        nft_rule_counters(rules)
        return json.dumps(rules, ensure_ascii=False, separators=(",", ":"))
    return value


def observation_view(data, policy):
    catalogue, source = data["catalogue"], data["views"]
    inventory = [
        {k: d[k] for k in ("id", "role", "site", "level", "network") if k in d}
        for d in catalogue["devices"]
    ]
    devices = {d["id"]: d for d in inventory}
    if len(devices) != len(inventory):
        raise ValueError("Duplicate device in the audit inventory")
    assigned = set()
    inner_levels = defaultdict(set)
    addresses = {
        str(ip_interface(i["address"]).ip)
        for d in catalogue["devices"]
        for i in d.get("interfaces", [])
        if isinstance(i, dict) and i.get("address")
    }
    for entry in source.get("enclave-designations", []):
        row = entry["record"]
        red, inner, admin = row["red"], row["attached_inner"], row["admin"]
        authority = row["record"]
        level = authority["security_level"]
        if (
            authority["red_host"] != red
            or row["interface"]["alias"] != "MSC Red enclave security level " + level
            or not level
            or red in assigned
            or devices[red]["role"] != "host"
            or devices[inner]["role"] != "inner"
            or devices[admin]["role"] != "admin"
        ):
            raise ValueError("The administrative designation and Red interface observation disagree")
        devices[red]["level"] = level
        assigned.add(red)
        inner_levels[inner].add(level)
    expected = {d["id"] for d in inventory if d["role"] == "host"}
    if assigned != expected:
        raise ValueError("The capture lacks an independent security level for each Red host")
    for d in inventory:
        if d["role"] == "inner":
            d.pop("level", None)
            d["levels"] = sorted(inner_levels[d["id"]])
    validate_traffic_control(source["raw"], devices)
    # Device output is kept independently from the collector's interpretation.
    views = {}
    for name in ("raw", "processing"):
        rows = []
        for item in source[name]:
            r = item["record"]
            record = {
                k: r[k]
                for k in (
                    "id",
                    "device_id",
                    "kind",
                    "command",
                    "phase",
                    "returncode",
                    "stdout",
                    "stderr",
                )
                if k in r
            }
            if isinstance(record.get("stdout"), str):
                signature = fixture_signature(record["kind"], record["stdout"], addresses)
                if signature:
                    raise ValueError(
                        f"Unqualified capture: {signature} in {record['kind']} on {record.get('device_id')}"
                    )
                record["stdout"] = measurement_text(record["kind"], record["stdout"])
            metadata = {key: value for key, value in record.items() if key != "stdout" or not isinstance(value, str)}
            if _TEST_NET.search(encoding([item["devices"], metadata]).decode()):
                raise ValueError("Unqualified capture: an RFC 5737 documentation address in observation metadata")
            rows.append({"devices": item["devices"], "record": record})
        views[name] = rows
    views["deployment-policy"] = [{"devices": [], "record": policy}]
    result = {
        "catalogue": {
            "devices": inventory,
            "views": {v: {} for v in views},
            "evidence_scope": "Device roles, effective security levels and recorded device output. The audit copy omits firewall and IPsec traffic counters and IPsec activity times.",
        },
        "views": views,
    }
    if _TEST_NET.search(encoding([inventory, policy]).decode()):
        raise ValueError("Unqualified capture: an RFC 5737 documentation address in the audit copy")
    return result


def neutral_bundle(blob, blobs, seed, *, policy=None):
    packed = blob.read_bytes()
    if blob.name != digest(packed) + ".json.gz":
        raise ValueError("Reader bundle digest mismatch")
    data = json.loads(gzip.decompress(packed))
    if policy is not None:
        data = observation_view(data, policy)
    views, catalogue = data["views"], data["catalogue"]
    anonymize_collector_ids(views, seed)

    def order(label, rows, identity):
        groups = defaultdict(list)
        for r in rows:
            groups[encoding(identity(r))].append(r)
        return [
            r
            for key in sorted(
                groups,
                key=lambda k: hmac.digest(seed, label.encode() + b"\0" + k, "sha256"),
            )
            for r in groups[key]
        ]

    catalogue["devices"] = order("devices", catalogue["devices"], lambda d: d["id"])
    if "links" in catalogue:
        catalogue["links"] = order(
            "links",
            catalogue["links"],
            lambda row: sorted(row.values(), key=lambda e: (e["device"], e["interface"])),
        )
    timings = [
        r["record"].get(k)
        for view in ("processing-settings", "raw", "processing")
        for r in views.get(view, [])
        for k in ("started_at", "ended_at")
    ]
    origin = min((datetime.fromisoformat(s) for s in timings if s), default=None)
    for view, rows in views.items():
        for item in rows:
            row = item["record"]
            if view in {"raw", "processing", "processing-settings"}:
                for key in ("started_at", "ended_at"):
                    if row.get(key):
                        row[key.removesuffix("_at") + "_seconds_from_collection_start"] = round(
                            (datetime.fromisoformat(row.pop(key)) - origin).total_seconds(),
                            6,
                        )
            if view in {"raw", "processing"} and isinstance(row.get("stdout"), str):
                row["stdout"] = re.sub(
                    r"(?m)^(# Generated by (?:ip6?tables|iptables)-save[^\n]*?) on [^\n]*$",
                    r"\1",
                    row["stdout"],
                )
                row["stdout"] = re.sub(r"(?m)^# Completed on [^\n]*$", "# Completed", row["stdout"])
            if view == "capture-settings" and row.get("field") == "snapshot_id":
                row["value"] = "capture"
        views[view] = order(
            view,
            rows,
            lambda r: (
                sorted(r.get("devices", [])) or [r["record"].get("id", r["record"].get("field", ""))]
            ),
        )
        catalogue["views"][view] = {
            "records": len(rows),
            "fields": sorted({k for r in rows for k in r["record"]}),
            "kinds": sorted({r["record"]["kind"] for r in rows if r["record"].get("kind")}),
        }
    if policy is None:
        catalogue["collection_time"] = (
            "Collector timestamps are relative to the start of this capture. Device records retain their own clocks."
        )
    payload = canonical_mount(encoding(data))
    validate_reader_bytes(payload)
    findings = marker_counts(payload)
    if findings:
        raise ValueError(f"Reader input contains operator metadata: {sorted(findings)}")
    output = gzip.compress(payload, compresslevel=1, mtime=0)
    dest = blobs / (digest(output) + ".json.gz")
    blobs.mkdir(exist_ok=True, parents=True)
    if not dest.exists():
        dest.write_bytes(output)
    return dest.name
