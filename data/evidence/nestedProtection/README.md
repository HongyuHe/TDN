# RG007 nested protection inputs

Run these commands from the repository root:

```sh
python3 scripts/construction/build_nested_protection_inputs.py
python3 scripts/construction/build_mixed_nested_protection_input.py
python3 scripts/construction/build_mixed_protection_trace_inputs.py
lake build TDN.Deployments.SnapshotProof_NestedProtection
```

The generators use Python's standard library. They read retained inputs under `data/evidence`. No construction-run directory is required.

`exports/` retains the selected byte-identical MCP exports: baseline and shared November4 public authentication-service records, and the current mixed r3 inventory. The baseline/shared generators also read the retained `continuation/MtuSizing_Baseline.json` and `continuation/MtuSizing_Shared.json` cohorts. Generated JSON preserves the complete public source records and exact input hashes.

The mixed generator preserves the full current-r3 inventory and supplies typed directional tunnel, material-reference and interface records. The path generator selects both directions from the imported source flows, routes, physical links, bridge edges, SAs and SCI bindings. It emits JSON path witnesses. Ordinary reusable Lean declarations check each move's processing, key agreement, header and link admission, then prove the complete trace by induction over the imported move list.

`BaselineIPsec.json` supports the native whole application. `SharedIPsec.json` is a retained generated input without a claimed third whole RG007 application. `MixedIPsecMACsec.json` supports the mixed whole application. `MixedDeliveryPlans.json` contains the two successful model paths; the plans are not recovered packet-capture traces.

The imported fields and modeled behavior are unchanged by the export-path migration. Only generated provenance paths and their dependent file hashes change. Rejected r1/r2 inventory projections and obsolete proof-string generators remain in construction history, outside the retained active inputs. Public CA validation and cryptographic independence retain the explicit boundaries recorded in the whole application.
