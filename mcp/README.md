# TDN network evidence server

The MCP server lets agents collect network observations, query saved snapshots, and export JSON for Lean. Start the server with `./mcp/run.sh` from the repository root. The launcher also works from other directories when called by its absolute path.

The default configuration is `networks.example.json`. Pass another configuration file as the launcher's first argument to select different workers or snapshots. Configuration paths are relative to the configuration file. Prepared JSON goes to `../data/evidence/`; MCP collections and validation records are stored in `artifacts/` within this directory.

[`networks.retained.example.json`](networks.retained.example.json) opens the retained MACsec authentication, MACsec protection, mixed-protocol packet observations, and November 4 IPsec captures used by the continued proof work:

```sh
./mcp/run.sh mcp/networks.retained.example.json
```

That configuration stores new exports under the ignored `mcp/artifacts/retained-exports/` directory. Each capture remains a separate collection; the configuration does not merge collection periods. Before querying the November 4 key inventories, restore their compressed observation files using the [capture instructions](../data/snapshots/2026-11-04-mtu-cohorts/README.md). `list_networks` lists the collections, and `capabilities` reports their supported queries and export views.

The Python package is `tdn_evidence/`. It contains the server, device adapters, shared parsers, export code, and validation tools. The package name keeps TDN's code separate from the installed `mcp` SDK. `pyproject.toml` and `uv.lock` define the environment; the launcher installs it automatically with `uv`.

Git ignores routine collection outputs and validation reports under `artifacts/`. The [capture notes](artifacts/README.md) describe the selected BIRD capture retained to reproduce the Lean import example.

See the [server guide](../docs/evidence_service.md) for tools, supported evidence, vendor extensions, and validation commands.

The `native-authentication-services-v1` adapter exposes public CA and endpoint certificates from the retained native IPsec captures through the `native_authentication_services` view. It binds configured and loaded trust references, certificate identities and public signature checks to the recorded authenticated IKE/CHILD session. The CA records describe logical signing identities. They do not claim a running CA service, current validity or institutional approval. The original `native_ipsec_keys` export remains unchanged.

Use `describe_capabilities(collection="...")` for a saved capture or `describe_capabilities(network="...")` for a live network. The tool accepts one identifier at a time. Omitting both returns the general adapter catalog.

The `mixed-deployment-inventory-v1` adapter joins the retained IPsec-Inner/MACsec-Outer capture to device roles, interfaces and distinct Red networks. Its `mixed_deployment_inventory` view includes Red host attachments, directional installed SAs, static MACsec peer bindings and the unchanged packet-processing export. The view retains both capture phases and selects the final phase for active IPsec key bindings. Roles and security labels remain experiment declarations; manual SA provisioning carries no IKE or MKA authentication claim.
