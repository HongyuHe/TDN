# CSfC violation-detection experiment

The experiment compares a document-reading agent with the existing TDN implementation on five modified MSC networks. Each network has 20 deliberately violated requirement IDs. The same ID can occur on different networks, so the experiment contains 100 network/requirement cases.

The five starting layouts are the two-site baseline, two networks at one security level, four levels with shared Outer devices, four levels with redundant Outer paths, and independent management. Their source profiles are under `data/extraction/networks/profiles/`.

## Experimental controls

- Preserve the original configuration and runtime state before modification. Keep private-key backups on the worker with restricted permissions.
- Record pre-existing faults separately. Validate each intended violation against the original PDF and the changed device state. Do not count a proposed mutation as a successful violation without that evidence.
- Freeze the injection list before running either detector. Record source hashes and every revision to the experiment.
- Give the Detector a fresh conversation, the CSfC PDF, and a restricted interface to the five networks. Provide no TDN source, requirement groups, injection list, or construction history. Record and audit its tool use.
- Run TDN on fresh observations. Keep importer failures, failed sufficient conditions, concrete counterexamples, and unsupported requirements separate. An inability to prove a condition is not automatically evidence of a violated requirement.
- Score the 100 injected cases separately from pre-existing and additional violations. Review unmatched findings against actual evidence before labeling them false positives.
- Report accuracy only for a declared set containing verified compliant cases as well as violations. Report undefined metrics as unavailable.
- Record collection time, checking time, Detector elapsed time, and the exact scope of each result. A single Detector trial does not estimate variation across repeated trials.

## Completed run

Run `20261112-agent-baseline-01` verified all 100 target cases on November 12, 2026. The five deliberately noncompliant networks remain running on `hy@clnode176.clemson.cloudlab.us`.

| Network | Device prefix | Devices / links | Detector targets found | TDN targets found |
| --- | --- | --- | --- | --- |
| Two-site baseline | `NB_` | 23 / 24 | 18 / 20 | 12 / 20 |
| Two networks at one security level | `NT_` | 19 / 20 | 18 / 20 | 12 / 20 |
| Four levels with shared Outer devices | `NF_` | 31 / 36 | 18 / 20 | 12 / 20 |
| Four levels with redundant Outer paths | `NR_` | 37 / 56 | 18 / 20 | 12 / 20 |
| Independent management | `NM_` | 35 / 44 | 18 / 20 | 12 / 20 |

The Detector was GPT-6 Astra with high reasoning. It found 90 injected cases and 10 additional split-tunneling violations in 478.743 seconds. TDN with the experiment adapter found 60 injected cases in 13.050 seconds after collection. Thirty TDN cases came from Lean packet-model checks, and thirty came from configuration checks. No incorrect requirement claims were found during supervisor adjudication. The target set contains no negative cases, so balanced accuracy and specificity are unavailable.

The comparison measures the selected checks and the new adapter. It does not measure all capabilities expressible in TDN or establish sixty complete RG proofs. The Detector's ten abstentions involved source validation and organization approval policy that the gateway did not fully expose. The local report is `.lavish/agent-baseline.html` in the TDN checkout. Its scoring record is `runs/20261112-agent-baseline-01/scoring.json` in the baseline directory.

## Files

- `profiles/net-01.json` through `net-05.json` contain the actual deployed topology and twenty mutation operations each. Their validation flags refer to the retained final run, not to a future deployment.
- `requirements.json` preserves the original requirement text, PDF pages, and selected applicability assumptions.
- `worker.py` backs up the selected deployments, renews baseline CRLs, and captures public state. It retains private-key backups on the worker only.
- `mutate.py`, `validate_live.py`, and `packet_probe.py` apply the changes and verify their effects. The probe sends laboratory packets from directly attached containers.
- `rollback.py` restores the renewed pre-injection configuration and runtime filters. It also removes the added routing helpers, services, interface, and host route.
- `gateway.py` supplies the Detector with allowlisted public observations. Its temporary bearer token is stored under ignored `.runtime`, never in a result file.
- `tdn_evaluate.py` reads public captures and ordinary topology inventory. It does not read mutation labels or Detector findings. `PacketChecks.lean` executes the existing TDN filter and IPsec-selector models. `CertificateChecks.lean` typechecks the retained packet witnesses using `native_decide`.
- `construction_review_examples.json` records five historical construction mistakes with links to the original findings and repairs. The report presents them separately from the experiment scores.
- `score_experiment.py` scores network/requirement pairs and retains explanations for missed cases. `build_report.py` generates the Lavish HTML.

The run directory retains frozen inputs, public observations, both outputs, access records, scoring decisions, and validation history. `public-observations.tar.gz` is the selected public capture archive needed for replay. Its expanded `raw/` directory is ignored as a redundant working copy. The Detector's original outputs and scripts are preserved under `detector/`; they are research records rather than reusable library code. Original input hashes resolve under `frozen-inputs/`. `profile-validation-update.json` records the later validation-only metadata update.

## Additional path-property trial

Run `20261112-path-properties-01` asked a fresh GPT-6 Astra Detector with high reasoning to assess four properties on each network: Gray Firewall traversal, Outer Firewall traversal, double encryption before protected Red data reaches Black, and prevention of cross-level plaintext delivery. The task required coverage of arbitrary finite path lengths and all relevant alternative paths. The Detector received the original PDF and live gateway access, with no previous findings, TDN proofs, reference answers, or suggested algorithm.

The Detector finished in 404.275 seconds. It established nine topology claims under explicit assumptions, marked two same-level cases inapplicable, and left nine packet-processing claims unresolved. Its reachability calculations covered arbitrary-length walks without enumerating paths. No timeout or prolonged stall was observed. The Detector stopped normally with unfinished behavioral reasoning and evidence gaps. The original violation-detection scores are unchanged.

The trial directory retains the exact prompt, all twenty original results, analysis scripts, runtime, tool calls, access audit, and supervisor assessment. `detector-derived-records.tar.gz` contains the collected observations and derived files. The live gateway's duplicate working records remain ignored under `detector-session`. `supervisor-topology-reference-v2.json` is the final independent reference; the earlier, narrower P2 check and its correction are preserved separately. All 180 declared links matched live interface peer identifiers.

`path_reference.py` checks topology independently. `check_path_links.py` verifies the saved live link observations. `retain_path_detector.py` archives a completed trial and derives runtime from its execution record. Original Detector scripts retain their observed behavior, including their initial tool setup and self-corrections.

```bash
python3 tests/baselines/naive-agent/path_reference.py 20261112-path-properties-01 --output topology-reference-replay.json
python3 tests/baselines/naive-agent/check_path_links.py 20261112-path-properties-01
python3 tests/baselines/naive-agent/build_report.py 20261112-agent-baseline-01
```

The report includes the new trial in a separate section. Its conclusions are limited to one run on the existing five layouts. The nine unresolved packet-processing questions have no independently established safe/unsafe reference outcome in this trial.

## Inspect the running devices

```bash
ssh hy@clnode176.clemson.cloudlab.us
sudo docker exec -it NB_I_A1 sh
sudo docker exec NB_I_A1 swanctl --list-conns
sudo docker exec NB_I_A1 iptables-save
sudo docker exec -it NB_OF_A1 vtysh
sudo docker exec NB_G_A1 ovs-vsctl show
```

The worker experiment directory is `/users/hy/tdn-agent-baseline-20261112`. It is root-owned and contains restricted backups and the scripts used for the live run. Other deployments and workers were not modified.

## Replay the saved TDN checks

Run the following commands from the TDN repository root. The existing Lean toolchain and dependencies must be available.

```bash
python3 -m venv tests/baselines/naive-agent/.venv
tests/baselines/naive-agent/.venv/bin/pip install -r tests/baselines/naive-agent/requirements.lock.txt
python3 tests/baselines/naive-agent/replay_tdn.py 20261112-agent-baseline-01
python3 tests/baselines/naive-agent/score_experiment.py 20261112-agent-baseline-01
python3 tests/baselines/naive-agent/build_report.py 20261112-agent-baseline-01
```

If the expanded capture directory is absent, extract the retained `public-observations.tar.gz` into `runs/20261112-agent-baseline-01/raw` first. `replay_tdn.py` reuses frozen samples and restores the nonempty final certificate input before invoking Lean. `tdn_evaluate.py` refuses to overwrite an existing result directory.

The original packet search omitted an arrival-source restriction for ten INPUT witnesses. Those local ACL witnesses typecheck, but their first live packets were dropped before reaching the modeled filter. The separate `tdn-live-compatible-certificates.json` uses nonlocal source addresses from the recorded ingress subnets. All thirty supported packet replays then succeeded. Five extra OSPF witnesses were not replayed because the utility only generates TCP, UDP, and GRE. Both attempts are retained.

## Restore the clean deployment

The following command changes the running network back to the saved, renewed baseline. Add `--network net-01` to restore only that network.

```bash
ssh hy@clnode176.clemson.cloudlab.us \
  'sudo python3 /users/hy/tdn-agent-baseline-20261112/rollback.py \
    --profiles /users/hy/tdn-agent-baseline-20261112/profiles \
    --root /users/hy/tdn-agent-baseline-20261112'
```

Rollback reloads credentials and connections and terminates obsolete SAs. It does not initiate every tunnel. Traffic or `swanctl --initiate --child protected` can establish the restored connections. The final experiment intentionally leaves the faulty networks in place; no final rollback was performed.

## Repeat the live experiment

Choose a new run ID and a new worker experiment directory. Run `preflight.py` to locate the five deployed layouts, then `make_profiles.py` to prepare the mutation profiles. Copy `worker.py`, `mutate.py`, `rollback.py`, `packet_probe.py`, `validate_live.py`, the generated deployment inventory, and the profiles to the new worker directory. Run `worker.py baseline` before `mutate.py`. The baseline action creates backups and refuses to overwrite them. Verify with `validate_live.py`, and capture with `worker.py capture`.

The deployment locator currently targets these existing Twinet layouts and their mounted paths. A different worker or newly named topology requires adjusting the locator and profile device mapping. The scripts do not recreate the whole network from scratch. Mutation reruns are guarded by their journals; archive the old journal only after a verified rollback.

Start the read-only gateway with `python3 tests/baselines/naive-agent/gateway.py RUN_ID`. Give a fresh Detector only a copy of the original PDF, the gateway access details, and the restrictions in the retained prompt. Do not provide the target list or previous results. Run TDN independently and freeze its output before opening the Detector response. Keep the new trial separate from the completed run.

No files are committed, pushed, or published automatically.
