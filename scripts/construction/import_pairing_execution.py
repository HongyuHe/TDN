"""Compatibility entry point for the shared mixed-protocol parser."""
import argparse
import evidence_package
from tdn_evidence.parsers.pairing import *


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundles", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(args.bundles.iterdir()):
        if path.is_dir():
            report = parse(path)
            (args.output_dir / (path.name + ".json")).write_text(json.dumps(report, indent=2) + "\n")
            print(path.name, "validated")
