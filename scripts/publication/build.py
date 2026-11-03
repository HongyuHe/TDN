#!/usr/bin/env python3
"""Rebuild the local explorers and their publication copies from current source."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    (ROOT / '.lavish/theorem-hierarchy').mkdir(parents=True, exist_ok=True)
    commands = [
        ['lake', 'build', 'TDN'],
        ['lake', 'env', 'lean', 'scripts/publication/hierarchy/ExportDependencies.lean'],
        [sys.executable, 'scripts/publication/hierarchy/build_proof_map.py'],
        [sys.executable, 'scripts/publication/build_hierarchy.py'],
        [sys.executable, 'scripts/preprocess/preprocess_csfc_ontology.py'],
        [sys.executable, 'scripts/publication/export_pages.py', '--check'],
    ]
    for command in commands:
        subprocess.run(command, cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
