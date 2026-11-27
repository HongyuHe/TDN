# Benchmark Astra and TDN on one network fault at a time

Measure whether GPT-6 Astra with high reasoning can identify a CSfC violation in a saved network and whether TDN rejects the same network in Lean. The **supervisor** is the experimenter who selects each fault, records what changed, and grades the results. A **snapshot** contains the intended network design and the device configuration and operating state recorded after the network settles. A **healthy control** is a snapshot from the same topology with no planted fault. A control can still show genuine limitations of the emulation.

Method version 3 registers 20 fault types on each of three two-site Twinet topologies. The 60 fault sessions are mixed with nine healthy sessions, three per topology. Each healthy session uses a separately collected snapshot. Healthy controls account for 9 of 69 sessions, or 13.0%. [Topology specifications](../tests/baselines/naive-agent/profiles/scale/) · [Registered cases and control designs](../tests/baselines/naive-agent/scale/design.py) · [Historical cases](../tests/baselines/naive-agent/scale/catalog.py)

| Topology | Security levels | Devices | Links |
| --- | ---: | ---: | ---: |
| Base | 2 | 33 | 40 |
| 10xLevels | 20 | 213 | 292 |
| 10xDevices | 2 | 321 | 400 |

## 1. Select a violation from the CSfC document

Start with the original CSfC Multi-Site Connectivity Capability Package. Record the document version, PDF page, exact requirement ID or section, and the wording that makes the proposed behavior a violation. Map the source passage to a clause in one of TDN’s ten target requirement groups (RGs). The targets are RG-007, 008, 013, 029, 030, 034, 035, 038, 039 and 040. Check the conditions and exceptions in the original passage, including the device role, network side and transport type. [Source PDF](../data/extraction/source/CSfC_documentation_v1.3.0.pdf) · [Requirement groups](../specs/requirement_groups.md) · [Clauses](../specs/requirement_clauses.md) · [Formal specifications](../specs/requirement_formalizations.md)

For each proposed fault, the supervisor records the healthy behavior, one intended departure, the devices that could exhibit the fault, and the observation that would distinguish the two behaviors. For example, MSC-PF-25 and RG-040.03 restrict HTTP through a required Gray Firewall to traffic necessary for Inner-layer certificate revocation. A confirmed ordinary HTTP transaction through that firewall to an unrelated destination exercises the prohibition. A connection failure by itself leaves several possible explanations. Record inapplicable clauses and proposed changes that fail to produce the intended behavior separately. [MSC-PF-25, PDF page 46](../data/extraction/source/CSfC_documentation_v1.3.0.pdf#page=46)

The current catalogue targets 23 distinct clauses out of the 53 clauses in the ten groups. The original catalogue targeted 20. The count describes the registered design. The report also counts clauses for which a matching violation was independently observed on every topology. For example, the Outer-protection case requires evidence that the same Red payload actually crossed Black with only its Inner protection. A shared certificate issuer alone cannot establish that Inner and Outer encryption share a key context. MSC-PF-10 is an objective explicitly selected for these study deployments. [Clause interpretations](../specs/requirement_clauses.md)

## 2. Register the locations and observation schedule

Before collecting results, the supervisor runs `scale/panel.py register` in a new study directory. The program counts all eligible device and security-level locations, privately draws one location per trial, and records the assignments, random seed, shared traffic plan, PDF hash, detector model, reasoning setting, prompt and time limits. Use the same fault type on all three topologies. Report how many locations could exhibit each fault. Adding Red security levels creates more Inner gateways, while both sites retain their shared Outer gateway in 10xLevels. [Placement registration](../tests/baselines/naive-agent/scale/panel.py) · [Observation schedule](../tests/baselines/naive-agent/scale/observation-plan.json)

**Never inject a faulty firewall rule at row 1.** Count actual rules in each ordered filter chain, starting at 1. A chain is a list such as `FORWARD` that handles packets passing through a device. Preserve the healthy first rule in every affected IPv4 and IPv6 filter chain, including secondary rules changed as part of another fault. For firewall-rule trials, the supervisor assigns an early, middle or late third among **rows 2 onward** and keeps that third fixed across topologies. A chain with no eligible row cannot supply that trial. Preserve the recorded rule order during collection, verification and display.

Each topology has three healthy configurations. Inner gateways can reach the same subnet through a more-specific route with the same next hop. Gray Firewalls list the same authorized peers in different orders. Inner gateways, Outer gateways and Outer Firewalls also vary the order of neighboring IPv4 permits in their `INPUT` and `FORWARD` chains. Each permutation preserves the first rule and the packet verdicts.

Registration assigns seven, seven and six of the 20 fault types to the three healthy configurations. Each fault type keeps its assigned configuration across all three topologies. The capture receipt records the assignment before independent confirmation. Qualification checks the observed routes and rules against that control. Lean uses the same control for delivery paths and scoring. [Healthy rule ordering](../tests/baselines/naive-agent/scale/control_filters.py) · [Control assignment and qualification](../tests/baselines/naive-agent/scale/panel.py)

## 3. Establish the fault and freeze the scored snapshot

1. Establish the matched control on the isolated emulation. Record the intended assignments, converged routes, firewall rules and ordinary workload. Freeze the control snapshot before any case-specific confirmation. Run the registered TDN checks on the control and record the outcome of the independent healthy observation.
2. Apply one registered fault on the experiment replica. Record the affected devices, the configuration change, and how to restore the previous configuration in the supervisor’s private log. One logical fault may affect both endpoints or require corresponding request and reply rules. Record every change so the reviewer can attribute the observed behavior.
3. Let the faulty network settle under the control’s observation schedule. Collect the device state. Freeze the scored snapshot and record hashes of the native collection manifest and packet-processing observations.
4. **After freezing the snapshot**, independently confirm the changed behavior on the replica. For example, the supervisor can verify an HTTP request at both sides of the Gray Firewall. The separate confirmation keeps traffic generated by the experiment from marking the faulty rule with an otherwise distinctive packet counter in Astra’s input.
5. Restore the original configuration and check the healthy behavior again. Keep the before, fault-present, and restored observations, their times and hashes. If the network fails to settle, the intended effect is unobserved, or restoration fails, retain the trial record and mark the trial unqualified. [Collection and confirmation ordering](../tests/baselines/naive-agent/scale/observation_window.py)

## 4. Qualify exactly what Astra and TDN will receive

`scale/panel.py prepare` compares the candidate snapshots with the private registration and the paired controls. The program checks the recorded location, firewall placement, capture and confirmation order, independent observation, and restoration. The program records rejection reasons in `panel-preflight.json`. A missing registered location stays missing. The supervisor starts scoring after every required snapshot and control qualifies. [Candidate catalogue format and commands](../tests/baselines/naive-agent/scale/README.md)

Two Python programs prepare and serve the evidence that Astra receives.

- **`scale/blinding.py` prepares the file Astra can read.** Astra receives the device roles, independently assigned Red security levels, deployment authorizations, and recorded device output. The preparation program removes the expected link and interface lists and the collector’s computed health verdicts. Astra can reconstruct connectivity from the device readings. Every Inner gateway exposes its observed security levels in a list, including an empty list when no Red enclave attaches. The export omits firewall counters, IPsec session ages, and byte and packet counts reported by strongSwan and Linux. Configured lifetimes, security-association state, rule order and forwarding decisions remain visible. [Snapshot preparation](../tests/baselines/naive-agent/scale/blinding.py)
- **`snapshot_reader.py` serves the original PDF and prepared snapshot.** Its three operations read the document, list devices and search observations. The supervisor retains the original capture and separate confirmation records. TDN receives the original evidence and declared design. Both results refer to one frozen capture, with the documents and fields available to each method stated in the report. [Snapshot server](../tests/baselines/naive-agent/snapshot_reader.py)

The benchmark rejects any audit copy containing an IPv4 address from the three RFC 5737 documentation ranges. The benchmark also checks for known diagnostic services and test traffic-control filters. Linux traffic-control readings must account for every device and each installed ingress or egress hook. An unsupported or missing reading makes a candidate ineligible. The original recording stays available for inspection.

## 5. Run both methods and record time

Start a fresh Astra session for each anonymous snapshot. Mix fault-free and faulty sessions using the registered order. Use the same open-ended prompt throughout. Preserve Astra’s complete answer, operation log, input hash, model, reasoning setting, elapsed time and completion status. Count a completed audit only after confirming that Astra read both the PDF and saved observations using the authorized operations.

Run the same Lean proof files on the faulty snapshot and its assigned healthy control. Each prospective snapshot must supply a public key-manager record for every Inner and Outer gateway. Lean compares the records marked active. The firewall checks read the effective rule order, chain defaults and registered service policy. The PF-10 check runs when the deployment selects that IPv4 objective. Preserve the imported evidence, Lean source and hashes, diagnostics, failed declarations, and checking times. Astra’s time covers the whole audit, with a one-hour limit per session. TDN’s reported time sums the intervals inside Lean after loading the evidence. The separate twenty-minute process limit applies to each proof file and includes loading. Report incomplete timings explicitly. [Lean timing](../tests/baselines/naive-agent/measure.py) · [Proof applications](../tests/baselines/naive-agent/scale/verification.py)

## 6. Grade findings and publish the denominators

| Method or finding | How the supervisor grades the result |
| --- | --- |
| Astra identifies the planted fault | Credit the trial when the answer identifies the actual configuration or behavior on the affected device or connection. A unique address or an unambiguous device description is sufficient. Accept a different CSfC citation. Quote Astra’s diagnosis and match the diagnosis to the independent observation. |
| Astra reports another finding | Grade each distinct claim as an additional consequence, a different genuine issue, a confirmed false alarm, or unresolved. A symptom alone earns no planted-fault credit. A genuine emulation issue outside the ten target RGs can still be a valid finding against the full PDF. |
| TDN rejects the faulty snapshot | Credit a failed proof on previously imported evidence if the identical proof file passed on the matched control. Any registered proof obligation can supply the rejection. Record the exact Lean diagnostic. |
| TDN accepts or cannot finish | A completed check in which every proof passes is a miss. An import error, build failure or timeout alone earns no credit. Record every incomplete check. After a repair, retain the original result and replay the fixed checker on the same registered captures and controls. |

A rejection on either additional healthy configuration counts as a TDN false alarm when the same proof passes on the primary control. An import or tool failure counts as incomplete. The report gives the actual denominator for each healthy variant. Nine controls on three topologies still leave substantial uncertainty about false alarms on other networks.

Publish planted faults detected out of completed, qualified trials for each network. Count a fault type as detected across topologies only when the method detects that fault on **all three**. Report attempted, unqualified, incomplete and scored trial counts, so a missing result cannot silently improve a rate. Report confirmed false findings, unresolved findings and genuine additional findings separately. For controls, give both the fraction of sessions with any alert and the fraction with a confirmed false alarm. State how many different control snapshots were audited if several sessions used the same capture. Report runtimes with the number of complete timings. Keep scores from a replay on known faults separate from results on newly registered locations. [Scoring implementation](../tests/baselines/naive-agent/scale/review.py) · [Report generator](../tests/baselines/naive-agent/scale/report.py)

## Run the registered study

Run the following commands from `tests/baselines/naive-agent`. The supervisor supplies independently collected captures through `captures.json`. Each study directory contains private registration files, raw evidence references, restoration records, frozen answers and proof diagnostics. Keep study outputs under the ignored `runs/` directory.

```sh
python3 scale/panel.py register runs/registered-study
python3 scale/panel.py prepare runs/registered-study --candidates captures.json
python3 scale/panel.py tdn runs/registered-study --workers 3
python3 scale/panel.py astra runs/registered-study --workers 3
```

Use `scale/review.py` for each frozen Astra answer, including the healthy controls. Supply the answer hash, quoted claims, evidence and judgments in the review file. Once every answer has been graded, generate the report.

```sh
python3 scale/review.py runs/registered-study Base inner-mode --findings review.json
python3 scale/report.py runs/registered-study runs/registered-study/report.html
```
