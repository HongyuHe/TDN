# Blind document audit and Lean snapshot validation

The revised experiment lives in `runs/20261112-blind-theory-01/`. It preserves the earlier experiments separately. Two fresh Detectors receive only the original CSfC PDF and read-only access to five emulated networks. Their prompts contain no questions, selected requirements, fault counts, previous findings, or TDN code.

The requested models are GPT-6 Astra High and GPT-6 Sol High. Their recorded execution contexts confirm those settings. The observation gateway limits network access to public, allowlisted device commands. Filesystem restrictions are instructions checked against each agent's tool calls; they are not an operating-system sandbox.

## Network preparation

`prepare_blind_networks.py` restores the clean control, reloads credentials, and establishes Outer connections before Inner connections. The new trial repairs the expected peer identity after certificate duplication. It exposes per-interface IPv4 settings and HTTP service content through generic read-only gateway observations.

The initial Inner and Outer transport-mode mutations prevented CHILD SA establishment. `revise_blind_profiles.py` replaces those two targets with GRE allowances covered by PF-5 and PF-3. Every network still contains twenty distinct requirement targets. The revised profiles and the reasons for the changes are retained in the run directory. All forty-four tunnel endpoints had installed CHILD SAs before the blind agents started.

`validate_live.py` checks each planted configuration or sends the designated packet through the actual device. All one hundred designated behaviors were observed after injection and absent in the clean control. Ninety-nine cases support the intended requirement violation. The net-04 PF-18 case remains ambiguous because the redundant topology complicates whether the accepted source is illegitimate on that interface. The report gives scores both with and without that case.

## Actual Lean checking

`snapshot_collect.py` runs the existing native and processing collectors. The native collector compares routes, filters, interface identities, topology, and policy state before and after collection. The processing collector supplies additional raw state. These sequential observations establish stability over the selected fields; they are not an atomic snapshot.

`normalize_snapshot_inventory.py` preserves the first raw captures and corrects the initial omission of the collector's platform-interface option. The corrected inventory includes the already observed, disabled Linux GRE template interfaces. Future collections pass the option directly.

The evidence parser now retains isolated dummy interfaces and optional management interfaces. Local-interface stack labels follow the device's single declared network zone when there is one. The previous role-based default incorrectly labeled Gray routers and management-only switches. The original rejected imports and first failed controls remain available for inspection. These changes affect importing and supporting labels; no general Lean theorem or packet-processing relation was changed.

`SnapshotCompliance.lean` applies the existing double-encryption theorem to imported devices, routes, interfaces, links, switching, and IPsec state. `run_snapshot_theory.py` invokes Lean on each concrete snapshot and retains its actual errors. A failed local condition blocks the global proof. The failed condition does not by itself prove the negation of the global requirement.

`RuleDiagnostics.lean` evaluates the existing finite conditions to locate failing rules. Its output is diagnostic data. `LocalCompliance.lean` separately attempts positive proofs of those conditions with `native_decide`; those attempts retain actual Lean errors. `localize_theory_errors.py` also reruns the proofs with the independently captured clean filters. The controlled replay deliberately combines records to identify the cause of a failure and is labeled accordingly.

`HeaderCompliance.lean` applies the existing protocol and multicast theorems to the captured firewall chains. All five faulty snapshots fail their required conditions, while all five complete clean snapshots pass. These applications validate conditions already used in the frozen error mapping and add no new detections. The data-plane applications likewise reject all five faulty snapshots and accept all five complete clean snapshots.

The TDN driver receives observations and deployment inventory. It does not read mutation profiles, Detector findings, or planted packet witnesses. Only the later evaluation joins failures to the private fault manifest. Unsupported imports, proof-infrastructure errors, and faults outside the instantiated theory are reported separately from detections. Python configuration audits from the earlier experiment are excluded from the new TDN score.

## Retained evidence

Each Detector has a separate prompt, gateway log, observation directory, output directory, runtime record, and tool-call record. `retain_blind_detector.py` preserves those files without displaying findings before TDN outputs are frozen. Every run uses fresh output locations and preserves earlier results. Access tokens and private keys stay outside retained public records.

The report is a local HTML artifact. No commit, push, or public website publication is performed by these scripts.
