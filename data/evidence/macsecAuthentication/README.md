# Retained MACsec authentication inputs

`MacsecAuthenticationProfiles.json` is the strict typed Lean import. Regenerate it from a checkout with:

```sh
python3 scripts/construction/build_macsec_authentication.py
```

The generator reads only the retained inputs below. It does not require an `outputs/` directory.

- `CompletionFieldMap.json`: proof-relevant raw-event anchors, causal paths, source IDs, session/key references and export/capture hashes for each distinct role arrangement.
- `exports/eap-tls-forward-v32-complete-causal-authentication_complete_history.json` and the corresponding reverse export: complete public TLS/backend inputs, completion/message bindings and installed-SA observations.
- `../macsecProtection/MacsecProtectionProfiles.json`: the accepted packet-processing fixture inventory used to construct the two source/interface arrangements.

`--project-root`, `--input-dir`, `--mapping`, `--base-profiles` and `--output-dir` accept explicit paths. Relative paths are resolved against `--project-root`, which defaults to the repository root determined from the generator location. Without `--mapping`, the mapping is `CompletionFieldMap.json` inside `--input-dir`; exports are under that input directory's `exports/` subdirectory. Provenance records each input path base and SHA-256. Each export must match both its retained mapping hash and capture-manifest hash.

The generator retains full public authentication bytes and distinct session/MSK/CAK/SAK references. Actual SAK bytes are redacted; the model uses distinct synthetic 32-byte per-run material. Routes, source packets, site/zone labels and abstract wire payloads are curated fixture data. The reverse `transit-router` is an unused attachment with one interface, no route and no allowed traffic origin. The ten-step reverse delivery trace starts at `P0:red`, routes to P0's MACsec interface and traverses P0/P1 only. Reversed authentication roles and the separate Red-facing-to-MACsec route distinguish that application.
