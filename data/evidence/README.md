# Typed network evidence for TDN v3.2

These JSON files contain the network records loaded by Lean. The record types describe the fields used by the supported models. The import commands reject unknown fields and values outside those types. The original device observations remain under `data/snapshots` and in the selected captured test fixtures.

Version 3.2 renames the typed fields alongside the Lean declarations. IPsec records distinguish `IpsecPolicy` from `InstalledSA`. Installed associations use `reqid` and `spi`. Device records use `ingressPolicies`, `egressPolicies`, and `ifaceSecurityDomain`. Routes use `destPrefixLow` and `destPrefixHigh`. Packet states use `encapLayers` and `egressReady`.

The MCP exporters produce the same field names. Regenerate an export into a new destination when upgrading; the service rejects overwriting an existing export with different contents. The saved view names remain available, while each changed view reports a v3.2 `projectionVersion`.

The manifest retains the original source commit and source-module identity for the initial export. Its file paths and hashes identify the current typed files. The migration base and theory version record the naming update. Later typed refinements also appear in subdirectories; each Lean import identifies the exact file and record it uses. Publication validates the hashes of all imported files used by the current hierarchy.

The [v3.2 migration guide](../../docs/refactoring_v3.2.md) explains the names. The [migration map](../publication/v3.2/renames.json) lists module and declaration changes. The raw observations and historical review records keep their original names and formats.
