"""Build a read-only catalogue for each captured network and retain source hashes separately."""
from collections import defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
LIVE = HERE / "runs/20261122-rg-clauses-01"
RUN = HERE / "runs/20261123-rg-snapshots-01"
PDF = HERE.parents[2] / "data/extraction/source/CSfC_documentation_v1.3.0.pdf"
NETS = ("net-02", "net-03", "net-04", "net-05")
FORBIDDEN = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----|(?:AKIA|ASIA)[A-Z0-9]{16}|(?:^|[\s\x22])(?:PASSWORD|ACCESS_TOKEN|SECRET_ACCESS_KEY)=[^\s\x22]+", re.I)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    if path.exists():
        if path.read_text() != payload:
            raise ValueError(f"Existing experiment input differs: {path}")
        return
    path.write_text(payload)


def build_capture(family, name):
    path = LIVE / "raw" / ("controls" if family == "control" else "trials")
    if family != "control":
        path /= family
    source = path / name / "snapshot"
    signatures = {}
    def load(path):
        data = path.read_bytes()
        signatures[str(path.relative_to(LIVE))] = digest(data)
        return json.loads(data)
    declared = load(source / "spec.json")
    native_spec = load(source / "native/spec.json")
    native = load(source / "native/snapshot.json")
    processing = load(source / "processing/observations.json")
    manifest = load(source / "native/manifest.json")
    manifest_hashes = {f["path"]: f["sha256"] for f in manifest["files"]}
    if manifest_hashes["snapshot.json"] != signatures[str((source / "native/snapshot.json").relative_to(LIVE))]:
        raise ValueError("Native snapshot does not match its collection manifest")
    proc_manifest = load(source / "processing/manifest.json")
    for item in proc_manifest["files"]:
        if item["path"] == "observations.json" and item["sha256"] != signatures[str((source / "processing/observations.json").relative_to(LIVE))]:
            raise ValueError("Processing snapshot does not match its collection manifest")
    trial = LIVE / "trials" / family / name
    extra = None
    if family == "control":
        modes = load(LIVE / "controls" / (name + ".json"))
        inventories = load(LIVE / "control-inventory.json")["networks"]
        extra = next(n for n in inventories if n["network"] == name)
    elif (trial / "mode-observations.json").exists():
        modes = load(trial / "mode-observations.json")
        if (trial / "snapshot.json").exists():
            extra = load(trial / "snapshot.json")
    else:
        modes = load(trial / "snapshot.json")[name]
    views = defaultdict(list)
    def add(view, record, devices=()):
        views[view].append({"devices": [d for d in devices if d], "record": record})
    for label, spec in (("declared", declared), ("collector-spec", native_spec)):
        add(label+"-settings", {k:v for k,v in spec.items() if k not in {"devices","links"}})
        for dev in spec["devices"]:
            add(label+"-devices", dev, [dev["id"]])
        for row in spec["links"]:
            add(label+"-links", row, [row["a"]["device"],row["b"]["device"]])
    interface_readings = {}
    for record in native["observations"]:
        relative = Path(record["raw_path"])
        if not re.fullmatch(r"raw/obs-\d+\.json", str(relative)):
            raise ValueError("Unexpected archive member")
        raw_file = source / "native" / relative
        raw = load(raw_file)
        if signatures[str(raw_file.relative_to(LIVE))] != record["raw_sha256"] or record["raw_sha256"] != manifest_hashes[str(relative)]:
            raise ValueError("Native raw record does not match the snapshot and manifest")
        device = record["device_id"]
        add("raw", {**{k:v for k,v in record.items() if k not in {"raw_path","collector"}}, **raw}, [device])
        if record["kind"] == "interfaces" and record["returncode"] == 0:
            interface_readings[device] = json.loads(raw["stdout"])
    for key, data in native.items():
        if key == "observations":
            continue
        if not isinstance(data, list):
            add("capture-settings", {"field":key,"value":data})
            continue
        views[key]
        for row in data:
            record = row if isinstance(row, dict) else {"value":row}
            members = [record.get("device_id"),record.get("peer_device_id")]
            members += [i.split(":", 1)[0] for i in record.get("endpoint_interface_ids", [])]
            add(key, record, members)
    for row in processing["records"]:
        add("processing", row, [row["device_id"]])
    add("processing-settings", {k:v for k,v in processing.items() if k != "records"})
    for row in modes:
        add("gateway-connections", row, [row["device"]])
    census_fields = ("ifname","flags","ifindex","link_index","mtu","operstate")
    if extra:
        interface_readings = {d["device"]:d["interfaces"] for d in extra["devices"]}
    short = {(device, i["ifname"]): {k:i[k] for k in census_fields if k in i}
             for device, rows in interface_readings.items() for i in rows}
    for (device, _), iface in short.items():
        add("interface-census", {"device":device, **iface}, [device])
    for row in declared["links"]:
        devices = [p["device"] for p in [row["a"], row["b"]]]
        a,b = [short.get((p["device"], p["interface"]), {}) for p in [row["a"], row["b"]]]
        reciprocal = (a.get("link_index") is not None and b.get("link_index") is not None
                      and a["link_index"] == b.get("ifindex") and b["link_index"] == a.get("ifindex"))
        add("link-census", {**row,"reciprocal":reciprocal,"up":all("UP" in p.get("flags",[]) for p in (a,b))},devices)
    if extra and [e["record"] for e in views["link-census"]] != extra["links"]:
        raise ValueError("Published endpoint census differs from the recorded one")
    inventory = [{k:d[k] for k in ("id","role","site","level","network","interfaces") if k in d} for d in declared["devices"]]
    catalogue = {"devices":inventory,"links":declared["links"],"views":{}}
    for label, rows in sorted(views.items()):
        catalogue["views"][label] = {"records":len(rows),
            "fields":sorted({k for r in rows for k in r["record"]}),
            "kinds":sorted({r["record"]["kind"] for r in rows if isinstance(r["record"].get("kind"), str)})}
    data = json.dumps({"catalogue":catalogue, "views":views},ensure_ascii=False,separators=(",",":")).encode()
    if FORBIDDEN.search(data):
        raise ValueError("Restricted credential material in capture; review locally")
    packed = gzip.compress(data, compresslevel=1,mtime=0)
    blob = RUN / "raw" / (digest(packed)+".json.gz")
    blob.parent.mkdir(parents=True,exist_ok=True)
    if not blob.exists():
        blob.write_bytes(packed)
    put(RUN/"inputs"/family/(name+".json"), {"network":name,"bundle":blob.name,"sources":signatures})
    return blob.name


def main():
    cases = sorted((p.parent.parent.name,p.parent.name) for p in (LIVE/"trials").glob("*/*/adjudication.json"))
    if len(cases)!=43 or len(set(cases))!=43:
        raise ValueError("Expected the 43 separately observed trials")
    controls = {n:build_capture("control",n) for n in NETS}
    matrix = {}
    for family,name in cases:
        bundle = build_capture(family,name)
        matrix[family+"/"+name] = {n:bundle if n==name else controls[n] for n in NETS}
    put(RUN/"matrix.json",matrix)
    print(f"Verified {len(cases)} trial captures and {len(controls)} controls.",flush=True)


if __name__ == "__main__":
    main()
