#!/usr/bin/env python3
"""Collect extra token API observations from the existing isolated gateways."""

import argparse
from pathlib import Path
import shutil

from key_token_lab import Lab, CLIENT_MODULE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--label", default="001")
    args = parser.parse_args()
    lab = Lab(args.root, "extra-api", args.label)
    error = None
    try:
        for suffix in ["A", "B"]:
            name = "KT31_G_" + suffix
            lab.run(["docker", "cp", lab.root / "token_extra_operations.py", name + ":/lab/token_extra_operations.py"])
            lab.device(name, ["python3", "/lab/token_extra_operations.py", "--module", CLIENT_MODULE,
                              "--credentials", "/credentials/pin.json"])
            lab.device(name, ["sha256sum", CLIENT_MODULE, "/etc/swanctl/x509/cert.pem", "/lab/token_extra_operations.py"])
        binary_directory = lab.root / "public-binaries"
        binary_directory.mkdir(exist_ok=True)
        binary = binary_directory / "p11-kit-client.so"
        lab.run(["docker", "cp", "KT31_G_A:" + CLIENT_MODULE, binary])
        lab.run(["sha256sum", binary])
        lab.run(["nm", "-D", "--defined-only", binary])
    except Exception as failure:
        error = str(failure)
    finally:
        for name in ["token_extra_lab.py", "token_extra_operations.py"]:
            shutil.copy2(lab.root / name, lab.output / name)
        lab.finish(error)
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
