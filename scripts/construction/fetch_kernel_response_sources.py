"""Retain official Linux implementation-family response/output sources and hashes."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(os.environ["TDN_OUTPUT_DIR"]) / "references/kernel-responses-v6.8"
root.mkdir(parents=True, exist_ok=True)
records = []
for source in ["net/ipv4/icmp.c", "net/ipv4/ip_output.c", "net/ipv4/ip_forward.c",
               "net/ipv6/icmp.c", "net/ipv6/ip6_output.c", "net/ipv6/output_core.c"]:
    url = "https://raw.githubusercontent.com/torvalds/linux/v6.8/" + source
    path = root / source.replace("/", "-")
    result = subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                             "--max-time", "30", url, "--output", str(path)], capture_output=True, text=True)
    record = {"source": source, "url": url, "version": "Linux v6.8",
              "retrieved_at": datetime.now(timezone.utc).isoformat(), "exit_code": result.returncode,
              "stderr": result.stderr}
    if result.returncode == 0:
        record.update(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      bytes=path.stat().st_size)
    records.append(record)
(root / "manifest.json").write_text(json.dumps({"issuer": "Linux upstream torvalds/linux",
    "scope": "Implementation-family source. Captured Ubuntu kernel identity is separate; exact deployed binary correspondence is not proved.",
    "web_lookup": "Official raw GitHub URLs opened through web tool; IPv6 icmp.c web fetch timed out, retained curl retrieval attempted separately.",
    "records": records}, indent=2) + "\n")
print(json.dumps(records, indent=2))
if any(row["exit_code"] for row in records):
    raise SystemExit(1)
