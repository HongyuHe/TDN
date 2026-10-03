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
lake env lean tests/MSCExecution.lean
lake env lean tests/MSCAuthentication.lean
lake env lean tests/MSCProtection.lean
lake env lean tests/MSCLifecycle.lean
lake env lean tests/MSCFirewallControl.lean
lake env lean tests/MSCSourceReachability.lean
lake env lean tests/MSCControlServices.lean
lake env lean tests/NetworkReuse.lean
lake env lean tests/ExecutionReuse.lean
lake env lean tests/AuthenticationReuse.lean
lake env lean tests/ProtectionReuse.lean
lake env lean tests/HardeningReuse.lean
lake env lean tests/LifecycleReuse.lean
lake env lean tests/LocalControlReuse.lean
lake env lean tests/ServicePathsReuse.lean
lake env lean tests/RequestIDReuse.lean
lake env lean tests/MSCMulticast.lean
lake exe msc_demo
