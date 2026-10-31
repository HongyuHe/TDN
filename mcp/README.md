# TDN network evidence server

The MCP server lets agents collect network observations, query saved snapshots, and export JSON for Lean. Start the server with `./mcp/run.sh` from the repository root. The launcher also works from other directories when called by its absolute path.

The default configuration is `networks.example.json`. Pass another configuration file as the launcher's first argument to select different workers or snapshots. Configuration paths are relative to the configuration file. Prepared JSON goes to `../data/evidence/`; MCP collections and validation records are stored in `artifacts/` within this directory.

The Python package is `tdn_evidence/`. It contains the server, device adapters, shared parsers, export code, and validation tools. The package name keeps TDN's code separate from the installed `mcp` SDK. `pyproject.toml` and `uv.lock` define the environment; the launcher installs it automatically with `uv`.

Git ignores routine collection outputs and validation reports under `artifacts/`. The [capture notes](artifacts/README.md) describe the selected BIRD capture retained to reproduce the Lean import example.

See the [server guide](../docs/evidence_service.md) for tools, supported evidence, vendor extensions, and validation commands.
