# Outer Firewall theorem application

The follow-up applies `firewall_control_admission_from_local_rule_checks` to local INPUT and OUTPUT traffic on every Outer Firewall Black data interface in five saved clean/faulty snapshot pairs. The final theorem is `snapshot_outer_firewall_local_service_admission` in `FirewallCompliance.lean`. Its general lemma `local_service_admission_preserved` transfers local-hook acceptance from the full imported deployment. Snapshot-specific conditions use `native_decide`.

`run.py` validates and imports the original raw snapshots using the evidence parser. It preserves the device rules, routes, interface inventory and observed links. It connects each firewall's inside link to its Outer encryptor. Management interface ownership and rules remain in the imported data; management interfaces retain their management flag and map to the local zone. The proved service condition selects Black data interfaces.

`approved-control-policy.json` specifies OSPF between a firewall and its directly attached Black transport router. Approval records come from declared links and interface addresses. The policy is independent of observed allow rules and mutation descriptions. Each clean/faulty pair uses exactly the same approval records.

The original captures also contain UDP FORWARD allowances on ports 500 and 4500. The full firewall guard requires IKE/ESP framing evidence for those allowances. The follow-up retains whole-firewall diagnostics alongside the local-service results. The proved local-service condition directly covers the injected HTTP listener and its replies.

Run from the repository root, supplying a new output directory:

```sh
python3 tests/baselines/naive-agent/perimeter/run.py --output tests/baselines/naive-agent/runs/NEW-PERIMETER-RUN
python3 tests/baselines/naive-agent/perimeter/validate.py tests/baselines/naive-agent/runs/NEW-PERIMETER-RUN
```

The retained completed follow-up is `runs/20261112-perimeter-theory-02`. It contains ten Lean outcomes, per-rule diagnostics, hashes, approval records and five trust audits. `validate.py` checks the exact two added HTTP rules, matching clean controls, unchanged policy inputs and the original live fault observations. `build_report.py` updates the existing comparison page from a saved copy of its previous version. The original experiment results remain unchanged.

Lean compilation and native evaluation are included in the accepted checking assumptions. The report distinguishes the original 55 detections from five additional detections established by the follow-up.
