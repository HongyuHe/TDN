# Blind audits of the ten MSC proof targets

## Comparing Astra and TDN as the topology grows

The supervisor registers the device and security level before either detector runs. Every faulty snapshot must preserve row 1 of every IPv4 and IPv6 filter chain. The registered comparison mixes 60 fault sessions with nine independent healthy captures. The 20 prospective fault types target 23 distinct clauses. [Current cases and evidence requirements](scale/design.py) Reviewers grade every substantive finding. [Experiment workflow](../../../workflows/benchmark_baseline_agent.md) · [Commands and input format](scale/README.md)

## Replaying the original fixed-location experiment

The original scaling experiment tested 20 fault types on three two-site Twinet networks. Each of the 60 trials exercised one fault. Astra used the Python server `snapshot_reader.py` to inspect the CSfC PDF, intended design and saved device records. TDN applied Lean checks to the same underlying capture. The supervisor kept case names, operator logs and other sessions’ answers private.

| Network | Security levels | Devices | Data links and management links |
| --- | ---: | ---: | ---: |
| [Base](profiles/scale/Base.json) | 2 | 33 | 40 |
| [10xLevels](profiles/scale/10xLevels.json) | 20 | 213 | 292 |
| [10xDevices](profiles/scale/10xDevices.json) | 2 | 321 | 400 |

The larger device profile repeats the two-level site architecture ten times on each side of a shared Black transport. The profile with twenty levels gives each level its own Red host, Inner gateway, Gray switch and Red management equipment at each site. A single Gray router, Gray Firewall, Outer gateway and Outer Firewall serve each site. The benchmark retains the IPsec, administrative access and public transport choices from net-05. In the original experiment, the worker installed a measurement route on each Black test segment. The healthy firewall blocked connections to that endpoint. Red administrative workstations record the operating security level of each Red network. The collector reads the designation separately from the gateway's certificate and tunnel configuration. [Topology generator](scale/profiles.py) · [Twenty fault definitions](scale/catalog.py)

Use the archived snapshots to repeat the original fixed-location checks. The historical runners for cases that altered firewall row 1 are restricted to replay. Run from the benchmark directory with the project’s Lean dependencies built.

```sh
python3 scale/replay.py runs/topology-scaling-20261125 runs/fixed-location-replay --workers 3
```

The supervisor verifies the healthy network, applies one change, records the independent observation, saves the converged snapshot, restores the change, and confirms that the intended Red deliveries work again. Study records include the PDF and snapshot hashes, the SHA of the theory, raw device responses, Astra's complete transcript and reader queries, and Lean's source, diagnostics and timing for each check. The detector has one hour per session. Lean has twenty minutes per file, including loading. The measured Lean interval starts after the file has loaded the evidence. A refused connection or a blocked packet cannot count as an observed successful transfer. An observed violation earns Astra credit when its answer describes that violation on the affected devices, including when the cited requirement number differs. The all-network score credits a type only when the detector finds it on all three networks. [Adjudication](scale/review.py) · [Study runner](scale/study.py)

The archived report preserves the rules and proof programs used to score that run. To check the archived snapshots with today's proof programs, run `python3 scale/replay.py OLD_STUDY NEW_DIRECTORY`. The replay checks each source snapshot against its registered hashes, typechecks all three controls, and checks the same proof programs on each faulty capture. [Report generator](scale/report.py)

The archived captures, logs and replay results are stored under the ignored `runs/` directory.

## Earlier eleven-fault benchmark

The original network profiles are in [profiles/native](profiles/native/). The earlier benchmark tests eleven fault types on three of those networks. Net-03 shares its Outer gateways across four levels. Net-04 adds redundant Outer gateways. Net-05 has two levels and separate management networks. Each trial changes one network and leaves the other two available as clean controls. The design has 33 scored cases. [Net-03](profiles/native/net-03.json) · [Net-04](profiles/native/net-04.json) · [Net-05](profiles/native/net-05.json) · [Clause scope](clause_scope.json)

Twinet builds complete, isolated copies of the three profiles. The copies use their original addresses, links, roles and tunnel settings. Their device names begin with `QF`, `QR` or `QM`, and each copy receives its own credentials and private deployment directory. Using a copy keeps an experiment from interrupting a running reference deployment. [Replica definitions](cohort.py) · [Provisioning](replicas.py)

### Three architectural faults

| CSfC requirement | Change in one trial | Evidence required for a detection |
|---|---|---|
| **RG-008.01** · MSC §4.2.2 requires a dedicated Inner component for each Red network. | Add a second attachment from the Site A Red network at level 2 to the level 1 Inner gateway. Negotiate an additional IPsec child connection on that same gateway for the second subnet. The original level 2 gateway and its connections stay operational. | Match the links at both ends and the installed local traffic selectors. Send one test packet from each Red subnet to an unused remote test address. Each packet must increase its own outbound IPsec counter on the **same** running gateway. |
| **RG-013.01** · MSC-SR-7 requires a Gray Firewall on every Gray path between different-level Inner components. | Add one address-free virtual Ethernet link between the two Site A Inner gateways. It discards incoming frames at both ends. The fault concerns the physical arrangement of Gray links. | Read both interface peer identifiers. Remove the Gray Firewalls from the observed graph and exhibit the new path between unlike-level gateways. A lost connection cannot establish that path. |
| **RG-040.02** · MSC-PF-28 restricts protected Gray traffic to appropriate same-level Inner endpoints. | Add one ESP forwarding rule to the Site A Gray Firewall. It matches only IPv4 ESP from the first Inner gateway to the second on the two selected interfaces. The test uses a fresh key and fixed test addresses. | Capture the encrypted test packet on firewall ingress and egress. Its two addresses, association identifier, sequence number and encrypted bytes must match. The same test reaches only ingress before the change and after restoration. |

The Lean checks read the saved device observations independently of the fault description. They check disjoint gateway assignments, use the general path theorem to establish the Gray Firewall requirement, and check every pair of observed Inner IPv4 addresses against every Gray Firewall’s ordered ESP rules. Lean checks both interface directions and all nonzero 32-bit ESP association identifiers. The verifier derives those checks from the snapshot. Only the separate traffic experiment knows which pair and identifier the test packet uses. The other eight fault types retain their original clause assignments. [Lean checks](MscArchitectureChecks.lean) · [Snapshot importer](architecture_cases.py) · [All fault descriptions](violation_descriptions.json) · [Proof applications](proof_applications.json)

### Running and reviewing trials

Run the commands below from this directory. The earlier runner needs the repository's pinned Lean dependencies, CloudLab access to the benchmark worker and the isolated reader's Python environment under `.runtime/venv`.

```bash
python3 replicas.py up
python3 register_controls.py runs/multilevel-live-01 --freeze
python3 run_series.py runs/multilevel-live-01 --list
python3 run_series.py runs/multilevel-live-01
```

The registration step captures the three clean controls, checks the Lean proofs and records their source and input hashes. Each scored trial holds one fault in place while a fresh GPT-6 Astra High and a fresh GPT-6 Sol High inspect all three networks. They receive the original CSfC PDF and a read-only device interface. The prompts contain no target clauses, expected answers, or fault counts. The supervisor reviews each answer against the independent observations and records its evidence before the series advances. [Registration](register_controls.py) · [Detector prompt](blind_audit.py) · [Live reader](reader.py) · [Review tool](review_trial.py)

The one-case runner also accepts a network and a fault name. The following example runs just the Gray path trial.

```bash
python3 run_case.py runs/multilevel-live-01 net-03 gray-cross-level-path
```

A method earns credit for a type when it identifies the fault on **all three networks**. A detector can cite a different requirement if it identifies the actual fault. TDN earns credit when a fixed proof that passed on the clean network rejects the captured change. Import failures, incomplete checks and timed-out audits are recorded separately. The detector time covers the whole audit. The Lean time starts after importing the data. [Scoring](score_trials.py) · [Timing](measure.py) · [Validation](validate_clause_run.py)

## Repeating the audits with snapshots

The snapshot reader supplies the same three network captures that feed TDN. In each session, one network has a captured fault and two have clean captures. The case records and the supervisor's diagnosis stay outside the reader. After the live cases have been adjudicated, run the following commands in order. Record each snapshot answer's assessment before scoring it.

```bash
python3 score_trials.py runs/multilevel-live-01
python3 snapshot_inputs.py
python3 run_snapshot_audits.py
python3 score_snapshot_audits.py
python3 build_clause_report.py runs/multilevel-live-01
```

The active report is written to `.lavish/naive-agent-multilevel.html`. A pending cell means that the corresponding method has no reviewed result yet. [Snapshot reader](snapshot_reader.py) · [Snapshot scoring](score_snapshot_audits.py)

### Testing the implementation without starting detector sessions

The qualification runner collects a clean reading, applies one change, takes a full snapshot and restores the network. Lean must accept the clean state, reject the specific clause on the faulty snapshot and accept the restored state. Each run uses a new output directory. The independent replay reads the raw observations again and checks all nine network–fault combinations with the same Lean source. These runs have their own records and contribute no detector scores.

```bash
python3 -m unittest test_trial_scoring test_architecture_cases
python3 run_architecture_trial.py runs/qualification net-03
python3 run_architecture_trial.py runs/qualification net-04
python3 run_architecture_trial.py runs/qualification net-05
python3 validate_replacements.py runs/qualification-verified runs/qualification
```

Run `python3 replicas.py down` to remove the dedicated replica containers after testing. The artifacts under `runs/` contain captures, hashes, answers and logs and are ignored by Git. The November 22–23 four-network trials, the corresponding snapshot comparison and their report retain their original scores. The [earlier five-network experiment](legacy/README.md) has its own records.
