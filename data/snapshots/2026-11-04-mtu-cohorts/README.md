# November 4 packet-sizing and IPsec observations

These captures were collected on November 4, 2026 for the active theory. They are retained byte-for-byte from the earlier construction run. The baseline and shared groups contain device snapshots, packet-processing exports and before/after authenticated key inventories. The separate baseline sizing capture and embedded shared sizing capture contain observed packet bytes. Reusing these captures does not describe a new collection. All original manifests and collection times remain unchanged.

Four large daemon-observation files are stored as `.json.gz` files under `compressed/`. Keeping the compressed copies outside the individual capture directories preserves their strict file manifests. Their compressed size is about 9 MB; their decoded size is about 251 MB. `compressed-files.json` records both hashes. The decoded bytes retain the original capture hashes.

Before querying these captures through the MCP server, restore the four JSON files from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
import hashlib
import json

root = Path("data/snapshots/2026-11-04-mtu-cohorts")
manifest = json.loads((root / "compressed-files.json").read_text())
for entry in manifest["files"]:
    compressed = (root / entry["compressed"]).read_bytes()
    assert hashlib.sha256(compressed).hexdigest() == entry["compressed_sha256"]
    decoded = gzip.decompress(compressed)
    assert hashlib.sha256(decoded).hexdigest() == entry["sha256"]
    destination = root / entry["path"]
    if destination.exists():
        assert destination.read_bytes() == decoded
    else:
        destination.write_bytes(decoded)
print("Restored and verified four original observation files.")
PY
```

The MCP parsers then validate each original capture manifest as usual. Compression changes only how the files are stored.
