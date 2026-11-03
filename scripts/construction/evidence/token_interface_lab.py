#!/usr/bin/env python3
"""Collect version binding and a valid-session PKCS11 v3 operation."""

import argparse
from pathlib import Path
import shutil

from key_token_lab import Lab, CLIENT_MODULE, BACKEND_MODULE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--label", default="001")
    args = parser.parse_args()
    lab = Lab(args.root, "interface-binding", args.label)
    error = None
    try:
        for suffix in ["A", "B"]:
            for kind, module in [("T", BACKEND_MODULE), ("G", CLIENT_MODULE)]:
                name = "KT31_" + kind + "_" + suffix
                for filename in ["token_extra_operations.py", "token_interface_binding.py"]:
                    lab.run(["docker", "cp", lab.root / filename, name + ":/lab/" + filename])
                arguments = ["python3", "/lab/token_interface_binding.py", "--module", module]
                if kind == "G":
                    arguments += ["--credentials", "/credentials/pin.json"]
                lab.device(name, arguments)
    except Exception as failure:
        error = str(failure)
    finally:
        for filename in ["token_extra_operations.py", "token_interface_binding.py", "token_interface_lab.py"]:
            shutil.copy2(lab.root / filename, lab.output / filename)
        lab.finish(error)
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
