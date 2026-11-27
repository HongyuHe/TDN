"""Read an absent, intended link as negative IPv4 evidence from two interface censuses."""

import json
import re


def ipv4_link_view(snapshot, manifest, root, observations):
    from .snapshot import require, safe_path

    configured = [l for l in snapshot["links"] if l["status"] != "observed"]
    if not configured:
        return None
    require(manifest["convergence"]["consistent"], "Unstable interface observations")
    require(
        any(f["path"] == "spec.json" for f in manifest["files"]),
        "Missing hashed topology assignment",
    )
    require(
        set(snapshot["scope"]["expected_device_ids"])
        == {d["id"] for d in snapshot["devices"]},
        "Incomplete device inventory",
    )
    spec = json.loads(safe_path(root, "spec.json").read_text())
    expected_links = {
        frozenset(e["device"] + ":" + e["interface"] for e in l.values())
        for l in spec["links"]
    }
    namespaces = {d["id"]: d["namespace"] for d in snapshot["devices"]}
    readings = {}
    absent, inactive, known = set(), set(), set()

    def census(device, kind):
        k = device, kind
        if k not in readings:
            matches = [
                o
                for o in observations.values()
                if o.get("device_id") == device and o.get("kind") == kind
            ]
            require(len(matches) == 1, "Missing or duplicate interface census")
            o = matches[0]
            require(
                o["returncode"] == 0
                and o["parse_status"] == "parsed"
                and o["command"]
                == [
                    "docker",
                    "exec",
                    namespaces[device],
                    "ip",
                    "-j",
                    "-d",
                    "address",
                    "show",
                ],
                "Missing successful whole-device interface observation",
            )
            ports = json.loads(
                json.loads(safe_path(root, o["raw_path"]).read_bytes())["stdout"]
            )
            readings[k] = {p["ifname"]: p for p in ports}
            require(len(readings[k]) == len(ports), "Duplicate interface in census")
        return readings[k]

    for link in configured:
        ends = link["endpoint_interface_ids"]
        require(
            link["status"] == "configured"
            and link["relation"] == "veth"
            and len(set(ends)) == 2
            and frozenset(ends) in expected_links,
            "Unverified topology relation",
        )
        require(not known.intersection(ends), "Disconnected endpoint reused")
        known.update(ends)
        missing = []
        for key in ends:
            device, iface = key.split(":", 1)
            first, last = (
                census(device, k).get(iface)
                for k in ("interfaces", "convergence-interfaces")
            )
            if first is None and last is None:
                missing.append(key)
            else:
                require(
                    all(
                        p
                        and p.get("linkinfo", {}).get("info_kind") == "veth"
                        and p.get("operstate") == "DOWN"
                        and "LOWER_UP" not in p.get("flags", [])
                        for p in (first, last)
                    ),
                    "Unresolved live or unstable link",
                )
                inactive.add(key)
        require(missing, "Neither configured link endpoint is confirmed absent")
        absent.update(missing)
    actual = {p["id"] for p in snapshot["interfaces"]}
    expected = set(snapshot["scope"]["expected_interface_ids"])
    require(
        expected - actual == absent and not actual - expected,
        "Unexpected interface inventory difference",
    )
    failures = set()
    for entry in manifest["collection_failures"]:
        o = observations[entry["observation_id"]]
        device = o.get("device_id")
        require(
            device in namespaces
            and o.get("kind") == "ipv6-settings"
            and o["command"][:4] == ["docker", "exec", namespaces[device], "sysctl"]
            and o["returncode"] != 0,
            "Collection failure outside the confirmed absence",
        )
        raw = json.loads(safe_path(root, o["raw_path"]).read_bytes())
        messages = raw["stderr"].splitlines()
        require(messages, "Unexplained settings failure")
        for line in messages:
            match = re.fullmatch(
                r"sysctl: cannot stat /proc/sys/net/ipv6/conf/([^/]+)/(disable_ipv6|forwarding): No such file or directory",
                line,
            )
            require(
                match
                and device + ":" + match[1] in absent
                and "net.ipv6.conf." + match[1] + "." + match[2] in o["command"][4:],
                "Unrelated settings failure",
            )
        failures.add(o["id"])
    for d in snapshot["devices"]:
        if failures.intersection(d["observation_ids"]):
            d["observation_ids"] = [
                k for k in d["observation_ids"] if k not in failures
            ]
            d.pop("ipv6_settings", None)
    snapshot["links"] = [l for l in snapshot["links"] if l["status"] == "observed"]
    snapshot["scope"]["expected_interface_ids"] = sorted(expected - absent)
    snapshot["absentIfaces"] = sorted(absent)
    snapshot["unlinkedIfaces"] = sorted(inactive)
    return {
        "absent_interfaces": sorted(absent),
        "unlinked_interfaces": sorted(inactive),
        "omitted_ipv6_observations": sorted(failures),
    }
