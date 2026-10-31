#!/usr/bin/env bash
set -euo pipefail
#* Resolve the repository from the launcher, so MCP clients may use any working directory.
service_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$service_dir/../../.." && pwd)"
cd "$repo_dir"
exec uv run --frozen --project "$service_dir" python -m scripts.construction.evidence_service.server --config "${1:-$service_dir/networks.example.json}"
