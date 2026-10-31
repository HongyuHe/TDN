"""Retain official Linux implementation-family sources for fragment review."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

FILES = [
    "net/netfilter/xt_conntrack.c",
    "net/netfilter/nf_conntrack_proto.c",
    "net/ipv4/esp4.c",
    "net/ipv4/ip_input.c",
    "net/netfilter/xt_tcpudp.c",
    "net/netfilter/xt_multiport.c",
    "net/ipv4/netfilter/ip_tables.c",
    "net/netfilter/nft_payload.c",
    "include/net/netfilter/nf_tables_ipv4.h",
]
run = Path(os.environ["TDN_OUTPUT_DIR"])
folder = run / "references" / "fragment-authentication-v6.8"
folder.mkdir(parents=True, exist_ok=True)
records = []
for source in FILES:
    url = "https://raw.githubusercontent.com/torvalds/linux/v6.8/" + source
    path = folder / source.replace("/", "-")
    record = {"source": source, "url": url, "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        response = subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
            "--max-time", "30", "--write-out", "%{stderr}%{url_effective}", url], check=True, capture_output=True)
        data = response.stdout
        record["final_url"] = response.stderr.decode().strip()
        record["transport"] = "curl with system TLS verification"
        if path.exists() and path.read_bytes() != data:
            raise ValueError("Refusing to replace retained source bytes")
        path.write_bytes(data)
        record.update(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), error=None)
    except Exception as error:
        record["error"] = repr(error)
    records.append(record)
manifest = folder / ("capture-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
manifest.write_text(json.dumps({"issuer": "Official Linux upstream repository", "revision": "v6.8",
    "scope": "Implementation-family source, not a byte-identical Ubuntu binary assertion",
    "records": records}, indent=2) + "\n")
print(json.dumps(records, indent=2))
if any(record["error"] is not None for record in records):
    raise SystemExit(1)
