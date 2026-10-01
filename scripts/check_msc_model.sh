#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
if [[ -f "$HOME/.elan/env" ]]; then
  source "$HOME/.elan/env"
fi

python3 scripts/import_msc_snapshot.py --check
python3 -m unittest discover -s tests -p 'test_*.py'
lake build
python3 scripts/check_msc_axioms.py
lake env lean Playground.lean
lake env lean tests/MSCRegression.lean
lake exe msc_demo
