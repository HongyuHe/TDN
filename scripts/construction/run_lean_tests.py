"""Check standalone Lean regression files that the library build omits."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("tests"))
    args = parser.parse_args()
    files = sorted(args.directory.glob("*.lean"))
    if not files:
        raise ValueError("No standalone Lean tests found")
    failures = []
    for path in files:
        print("Checking " + str(path), flush=True)
        result = subprocess.run(["lake", "env", "lean", str(path)])
        if result.returncode:
            failures.append(str(path))
    print(f"Lean regression files: {len(files)}; failed: {len(failures)}", flush=True)
    if failures:
        print("Failed files: " + ", ".join(failures), flush=True)
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
