# Blind audits of the ten MSC proof targets

The benchmark uses four original CloudLab networks. Each trial changes one device on one network. A fresh GPT-6 Astra High and a fresh GPT-6 Sol High independently inspect all four networks. The active profiles are [net-02](profiles/net-02.json), [net-03](profiles/net-03.json), [net-04](profiles/net-04.json), and [net-05](profiles/net-05.json).

Git contains the network profiles, experiment definitions, runners, Lean checks, and scoring and report code. Each run writes its snapshots, logs, answers, and scores under `runs/`. These records and the local environment under `.runtime/` stay on the machine that runs the experiment.

[The clause scope](clause_scope.json) lists every row in the current [TDN clause guide](../../../specs/requirement_clauses.md). Applicability depends on the original architecture. For example, all four profiles use IPsec and public Black transport. Each has a separate clean snapshot, and each candidate fault needs an independent observation of its effect.

[The individual duties](clause_branches.json) split rows that combine several obligations. Net-02 has two named Red networks at the same full security level. PF-23 makes a Gray Firewall mandatory on the three multi-level profiles. The local scope table also tracks conditional services, missing objective selections and obligations that have an active condition and still need a test.

## What the Detector sees

The [reader](reader.py) provides the original 66-page CSfC PDF, the four inventories, and read-only device commands. Each Detector starts in an empty working directory. It can read or search the document, inspect a figure, and query live interfaces, routing, firewall, IPsec, and switching state. The [launcher](blind_audit.py) disables shell access, other apps, web search, and agent memory. The supervisor checks the reader access log and retains the complete answer even when the two Detectors disagree. The prompt contains no RG numbers, target questions, case counts, mutation names, or expected answers.

## What TDN checks

The [topology checks](TopologyChecks.lean) apply TDN’s public Black firewall placement theorem and its Gray firewall traversal argument to live interface peers. The [attachment check](AttachmentChecks.lean) checks a necessary condition of RG-034 directly against the interfaces present in each network. The [mode checks](ModeChecks.lean) prove that the recorded modes are necessary conditions of RG-029 and RG-030. An installed association can still use tunnel mode while the loaded configuration specifies a different mode for the next negotiation.

The mode application uses the settings loaded by strongSwan for its next negotiation. The original [Inner tunnel binding](../../../TDN/Deployments/InnerTunnelNoBypass_IpsecTunnelBindings.lean) also consults an installed association and policy. The benchmark proves the link to the whole requirement under the explicit `ModeObservationsMatch` premise. The timing covers checking the loaded strings. The individual results name each rejecting application so a reader can see exactly where each detection came from.

The [full suite](full_suite.py) also applies the recorded forwarding, IPv4 header, and local Outer Firewall rules to fresh packet-processing records. The [timing code](measure.py) measures the interval between two monotonic clock readings inside Lean. Both readings follow evidence import. Async elaboration is disabled, and Lean uses one worker. The reported time includes the finite proof checks and theorem applications between those readings. The Detector time runs from process start to its final response, including its own device queries.

The repaired importer lets TDN detect the protocol-253 fault on all four networks. The original importer compared the text `"253"` from iptables with the number `253` from nftables and stopped. The rerun used eight original proof applications on each saved clean and faulty snapshot. All 32 clean checks passed. On every faulty snapshot, Lean rejected the rule admitting protocol 253 and the other seven checks passed. The trial directories retain the original import errors. The [rerun driver](recheck_header_trials.py) writes each network’s result to `runs/20261122-rg-clauses-01/reruns/ipv4-protocol-import/record.json`.

The [delivery check](DeliveryPathChecks.lean) replays all 24 intended Red deliveries, covering 1,440 model steps across the four clean networks. The original TDN witness generator proposes each path using the clean capture. Lean checks every proposed step against the rules, routing table and tunnel state of the capture under evaluation. The [replay driver](delivery_paths.py) keeps the same endpoints and interfaces when an association is renewed. The managed profile also contributes two independently observed management TCP connections. The [proof application list](proof_applications.json) explains which part of each target these checks cover.

## How the comparison is scored

A finding counts when the answer identifies what changed on the affected network. Another RG citation can support the same finding. The supervisor records the supporting lines or the reason for a miss. A TDN rejection counts when a proof obligation fails on the faulty evidence, its clean counterpart passed, and the failure can be traced to the planted change. Collection errors and unsupported input receive separate statuses.

A fault type earns full credit when the method receives a point on all four networks. An observed detection earns one point. The revised comparison also assigns each method one point for RG-040.07 on net-02, where the Gray Firewall requirement does not apply. The 43 live trials and one assigned case give each method 44 network scores across 11 fault types. Coverage counts the 43 live trials. Only measured audits and proof checks contribute runtime. The [score builder](score_trials.py) reads the local trial records in `runs/20261122-rg-clauses-01/`.

The [review tool](review_trial.py) records the supervisor’s reading of both complete answers and the causal interpretation of a Lean result. The [source manifest](freeze_protocol.py) verifies the four clean controls, the current source-clause mapping and the files used for the comparison. The [collection wrapper](capture_stable.py) retains an unsettled capture and collects again while the same single change is present. Each trial restores its original configuration before the next trial begins.

Use [the single-case runner](run_case.py) to select a registered fault and one of the four original profiles. It checks the links, tunnel endpoints and intended deliveries on all four networks before starting. Each completed case retains the supervisor’s observations, both complete answers, each Lean result, and the restoration check. The [path diagnostics](path_diagnostics.py) match a failed forwarding step to the named interface in the same capture.

The full Lean time covers eight proof applications, including the authorized deliveries and the Gray Firewall paths. Each measurement begins after JSON loading. Each completed case records the original six-check time, the seven-check time with delivery replay, and the full time. [Gray connection checker](GrayConnectivityChecks.lean)

Two local trials send one empty packet between directly connected devices. The Red host sends a header to its own Inner gateway. The Black router sends an empty UDP datagram to a closed port on its adjacent Outer Firewall. A capture records the incoming packet in every phase. The receiver’s Linux counters independently report whether it reached local IP processing. [Local diagnostic](local_packet_probe.py)

The [series runner](run_series.py) checks one case, restores the network, waits for the review, and advances to the next applicable case. The report gives each duty a live coverage status. A duty counts toward live coverage only when a recorded trial exhibits it.

## Earlier experiments

The [earlier experiment](legacy/README.md) used five profiles. Its [profile generator](make_profiles.py) builds them under `legacy/profiles/` from the deployment records. The earlier runs kept their validated copies there.

## Repeating the audits with saved snapshots

The snapshot comparison uses the PDF and the original captures already collected for TDN. Each fresh Detector session receives four networks with neutral names. One network has the captured fault. The other three have their original clean captures. The reader lists the available records and lets the Detector select a device, search the saved output, or read the original PDF. All three tools read local files.

1. Run `python3 snapshot_inputs.py` from this directory. It verifies the native data and raw readings against their collection hashes, indexes the supplemental connection and interface readings, and records the four inputs for each trial.
2. Run `python3 run_snapshot_audits.py` to launch the original two models with high reasoning and the original blind prompt. Each session has a one-hour time limit. A restarted batch reuses completed sessions and reruns incomplete sessions in a fresh context. Invalid attempts retain their own transcripts.
3. Read each final answer against the observed fault and record its verdict, supporting line numbers, reason, and answer hash in the session’s `assessment.json`. The scoring rule accepts an observation that identifies the change or its specific effect on the correct network. The Detector can cite a different requirement.
4. Run `python3 score_snapshot_audits.py` to validate the 86 independent sessions and the recorded assessments. Rebuild the report with `python3 build_clause_report.py runs/20261122-rg-clauses-01`.

The generated `runs/20261123-rg-snapshots-01/matrix.json` identifies each snapshot by its content hash. The [static reader](snapshot_reader.py) serves the document and captured network data. Detector answers, request logs, run times, and grading records are stored separately from the reader’s inputs.
