"""Replay the frozen Lean model inputs and check their retained certificates."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess

from common import BASE, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id / "tdn-final"
    subprocess.run(["lake", "env", "lean", "--run", str(BASE / "PacketChecks.lean"), str(run / "samples.json")],
                   cwd=ROOT, check=True)
    target = BASE / ".runtime/tdn-certificates.json"
    target.parent.mkdir(exist_ok=True)
    shutil.copyfile(run / "certificates.json", target)
    count = len(json.loads(target.read_text())["witnesses"])
    if count == 0:
        raise ValueError("The final violation certificates must be nonempty")
    subprocess.run(["lake", "env", "lean", str(BASE / "CertificateChecks.lean")], cwd=ROOT, check=True)
    print(f"Replayed {count} retained violation certificates")


if __name__ == "__main__":
    main()
