# Typed network evidence for TDN v3.4

These JSON files hold the records that Lean reads. Device observations and collection manifests are kept in [the snapshots directory](../snapshots/). The importer reads a record at a named JSON key, converts it to the requested Lean type, and encodes it back to JSON. The two values must match exactly.

In the current overlay records, `protocol` identifies the tunnel protocol and `hostLocal` identifies an interface local to its device. Collectors retain their original field names and values. For example, an IPsec device observation can record `mechanism`, and a loopback interface in a saved inventory can carry the zone `local`. The exporter converts those values when it builds the Lean records. The shared Gray Firewall’s [ACL and route indexes](lookup-hints/) identify the records Lean should check.

To load a typed export produced before the field changes, convert it into a new file:

```sh
python3 scripts/construction/migrate_typed_overlay_records.py previous.json current.json
```

The converter preserves embedded source captures and the JSON keys that identify individual observations. The [evidence manifest](manifest.json) records the paths and SHA-256 hashes of the original collection of typed files. Its source commit and module names identify their origin. Later exports appear in subdirectories. The [formalization map](../../specs/requirement_formalizations.md) links the current requirements to their Lean declarations.
