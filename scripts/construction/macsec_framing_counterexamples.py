from pathlib import Path
import argparse
import hashlib
import json

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
source_bytes = args.source.read_bytes()
source = json.loads(source_bytes)
selected = {}
for label, frame_id in [("integrityOnly", "integrity-only:A:2"), ("fullProtection", "protected:A:2")]:
    frame = next(frame for frame in source["frames"] if frame["id"] == frame_id)
    selected[label] = {name: frame[name] for name in ["header", "headerBytes", "payload"]}
selected["association"] = {"tag": 1, "sci": 144115475838730241, "associationNumber": 0, "keyGeneration": 1}
args.output.mkdir(parents=True, exist_ok=True)
(args.output / "MacsecFramingFrames.json").write_text(json.dumps(selected, indent=2) + "\n")
(args.output / "MacsecFramingOrigin.json").write_text(json.dumps({
    "source": str(args.source), "sourceSha256": hashlib.sha256(source_bytes).hexdigest(),
    "collection": "v31r-macsec-boundary-integrity", "parserVersion": source["projectionVersion"],
    "frames": ["integrity-only:A:2", "protected:A:2"],
    "associationTagAndKeyGeneration": "Model identifiers; SCI and AN come from the captured frame.",
    "claim": "Captured E=0 MACsec PDU is accepted as reduced-confidentiality framing and rejected as full confidentiality. No ciphertext or ICV verification is claimed."
}, indent=2) + "\n")
