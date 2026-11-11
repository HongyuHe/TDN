# Retained MACsec protection inputs

The Lean applications use two packet-processing configurations built from the observed peer settings in `MkaParametersLive.json`. The direct configuration attaches Red traffic to each MACsec logical interface. The routed configuration uses separate Red-facing interfaces and routes packets to the MACsec interfaces. Both configurations use the same general protection theorem.

Regenerate the imported records from the repository root:

```sh
python3 scripts/construction/macsec_protection_profiles.py --source data/evidence/macsecProtection/MkaParametersLive.json --output data/evidence/macsecProtection
python3 scripts/construction/macsec_framing_counterexamples.py --source data/evidence/macsecProtection/exports/MacsecBoundary.json --output data/evidence/macsecProtection
```

`MacsecProtectionProfiles.json` contains the device, interface, route, association and tunnel records. The observed settings and SCI values come from the retained MCP export. Routes, source attachments, site labels, model key identifiers and example frame bodies are explicit model inputs. `provenance.json` identifies the source export and its hash.

`MacsecFramingFrames.json` retains two captured MACsec frames: one with full confidentiality and one with integrity-only protection. The Lean examples check their framing and distinguish reduced protection from encryption. `MacsecFramingOrigin.json` identifies the exact records in `exports/MacsecBoundary.json`. Those checks do not perform AES-GCM or ICV verification.

The live parameter source is retained under `../../snapshots/2026-11-11T041724Z/`. The source export records its capture hash and observation identifiers. The general proofs establish the configured model's behavior; capture accuracy and correspondence with the running implementation remain evidence assumptions.
