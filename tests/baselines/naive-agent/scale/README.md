# Registered snapshot comparison

The benchmark measures whether Astra identifies a planted fault in one saved network and whether TDN rejects the same snapshot. Each Astra session receives the CSfC PDF and one snapshot. The supervisor keeps the intended fault, selected location, independent observations and restoration records outside Astra’s workspace. Sixty faulty sessions cover twenty fault types on three topologies. Nine additional sessions use independently confirmed healthy configurations, three per topology. [Experiment workflow](../../../../workflows/benchmark_baseline_agent.md)

## Select the cases before scoring

The three [stored Twinet specifications](../profiles/scale/) reproduce the original experiment. For the new study, print the 20 registered cases with `python3 scale/panel.py catalog`. Print a deployable healthy design with `python3 scale/profiles.py Base --control-topology healthy-control`. The other design names are `healthy-route-variant-a` and `healthy-route-variant-b`. Each preserves the subnet’s next hop and the set of authorized Gray Firewall peer pairs. The original topology generator remains available through `--topology`.

Run the commands from `tests/baselines/naive-agent`. In a new study directory, `scale/panel.py register` draws one eligible device and, where applicable, one security level per case. **Row 1 of every IPv4 and IPv6 filter chain must match the healthy control.** For a firewall-rule fault, the program divides the remaining positions, starting at row 2, into thirds. Each fault type keeps the same third across topologies. The private registration also assigns each fault type to a healthy configuration. The three configurations receive seven, seven and six fault types on each topology. The assignment for a fault type stays the same across topologies.

```sh
python3 scale/panel.py register runs/registered-study
```

On a dedicated replica, `python3 scale/provision.py up Base --control healthy-control` installs the registered routes and firewall order. Stop the current replica with the corresponding `down` command before changing variants. The provisioning program leaves row one in place and reorders only consecutive, side-effect-free permits in the IPv4 `INPUT` and `FORWARD` chains of the Inner gateways, Outer gateways and Outer Firewalls. Panel qualification checks the installed rule order. Run the command separately on the three designs of each topology. The collector freezes the snapshot before checking every intended Red delivery and the installed tunnels. Benchmark fault definitions describe which observation qualifies an independently supplied capture. The historical first-row and test-link fixtures are replay-only.

```sh
python3 scale/panel.py collect-control runs/registered-study --network Base --control healthy-control --output controls/Base/primary
python3 scale/panel.py prepare runs/registered-study --candidates captures.json
```

The input catalogue names previously observed, stable captures. Paths are relative to the catalogue. Each clean directory contains `capture.json` and `snapshot/`. Each faulty directory contains `cell.json`, `capture/`, `operator/` and `post-health.json`. The candidate entry and frozen capture receipt must both name the healthy configuration assigned in `placement-plan.json`. The operator record identifies where the fault occurred and records its effect independently of Astra and Lean.

```json
{
  "controls": {
    "Base": {"healthy-control": "controls/Base/primary", "healthy-route-variant-a": "controls/Base/variant-a", "healthy-route-variant-b": "controls/Base/variant-b"},
    "10xLevels": {"healthy-control": "controls/10xLevels/primary", "healthy-route-variant-a": "controls/10xLevels/variant-a", "healthy-route-variant-b": "controls/10xLevels/variant-b"},
    "10xDevices": {"healthy-control": "controls/10xDevices/primary", "healthy-route-variant-a": "controls/10xDevices/variant-a", "healthy-route-variant-b": "controls/10xDevices/variant-b"}
  },
  "trials": [{
    "network": "Base",
    "case": "inner-mode",
    "control_variant": "healthy-route-variant-b",
    "anchor": "XB_I_A1",
    "level": "S1",
    "trial": "captures/record-001",
    "location_evidence": "operator/held.json",
    "location_sha256": "<SHA-256 of the independent observation>"
  }]
}
```

Use a null level for a device-wide condition. Candidates for firewall cases can also specify `rule_depth_third` as 0, 1 or 2. For a seven-rule chain, the three groups contain rows 2–3, 4–5 and 6–7. A chain with just one rule has no eligible position. `scale/panel.py prepare` compares the actual first row across all devices and filter chains, including secondary changes for topology faults. The program rejects an individual candidate if any first row changes. Where multiple candidates match the registration, a fixed ordering selects the observation before scoring.

The control and its faulty network share an observation schedule. A targeted traffic test can increment one firewall counter or write to one log. The scored snapshot is frozen before the supervisor starts that test. The supervisor keeps the independent confirmation with its own hash. Use `freeze_then_confirm` with the capture and confirmation callbacks and the plan registered for the study. Each accepted record needs both timing receipts and the original capture hashes. [Default observation plan](observation-plan.json) · [Capture and confirmation ordering](observation_window.py)

Astra sees the PDF, a short inventory of roles and current security levels, the deployment’s own policy, and the recorded device outputs. Only the `raw`, `processing` and `deployment-policy` views are served. Every Inner gateway has a `levels` list derived from the Red enclave assignments. The audit copy omits firewall counters, IPsec session ages, and IPsec byte and packet counts in strongSwan and Linux output. All three RFC 5737 address ranges disqualify an audit copy, including addresses in command arguments and error messages. TDN uses the original capture. The operator keeps both hashes and the raw records. Known experimental endpoints, service ports, protocol matches and test-only traffic-control filters disqualify the capture. A legitimate configured lifetime or an unrelated kernel table number retains its value.

For the seven revised cases, the private confirmation JSON contains `case`, `anchor`, `readings` and `facts`. Each of `before`, `during` and `restored` in `readings` refers to a different observed file under `operator/` with its SHA-256 and a Boolean `violated`. Only the middle recording can establish the violation. The [per-case evidence checks](design.py) define the fields each case requires. For the key-context case, every healthy and faulty capture needs a public key-origin record from each Inner and Outer gateway. The collector can read an operator-supplied public attestation at `/run/tdn-public-key-context.json` with exactly `device`, `active`, `origin` and `key_context`. The two identifiers refer to key-manager records and contain no key bytes. The supervisor verifies that the key manager produced the records for the active associations. The benchmark checks the recorded identities and their agreement. Use the same instrumentation in healthy and faulty captures. Each gateway must report whether its key context is active. The healthy controls require active records at every gateway. On a faulty capture, Lean compares the active records across layers. A missing record or a layer with no active context yields an incomplete key check.


| Case | Independent confirmation | What Lean checks on each registered snapshot |
| --- | --- | --- |
| Outer outbound protection | The same Red payload entered on Gray and left on Black with only the Inner layer. | The forwarding proof requires the ordered Outer and Inner layers at Black egress for every modeled trace from Red. |
| Inner outbound protection | The Red payload left on Gray in plaintext. | The forwarding proof requires the Inner layer at Gray egress for every modeled trace from Red. |
| Shared layer key context | Active gateways at different layers report the same key-manager origin and context. | Lean compares the recorded origin and context together across layers. The key manager supplies the evidence behind each identifier. |
| Outer default admission | A packet outside the approved classes reached the end of the Gray rules and was accepted. | PF-20 evaluates the captured rules in order and applies the default to packets left over. An unconditional drop before an `ACCEPT` default blocks those packets. |
| Gray management interface | The Gray Firewall accepted a management session on a Gray data interface. | PF-27 checks that every Gray data interface blocks local access to each registered management service. The experiment registers TCP port 8443. |
| IPv4 options | The Outer VPN gateway accepted a packet whose IPv4 header exceeded five words. | When PF-10 is selected, Lean checks header lengths of six through fifteen words on the Outer gateway’s input, forwarding and output chains. |
| Source reachability on Gray | The Outer gateway accepted a source on a Gray interface that has no return route to that source. | PF-18 checks locally accepted and forwarded traffic against the source prefixes that the recorded routing tables reach through the incoming interface. |

The operator’s packet recordings establish what happened during the live trial. Lean independently uses the saved forwarding state, filter rules, and public key records. [Forwarding proofs](../SnapshotCompliance.lean) · [Ordered firewall checks](../ServicePolicyChecks.lean) · [Key-context check](../KeyContextChecks.lean)

For either firewall-placement case, the supervisor records the observed path as an ordered list of pairs of interface IDs in the confirmation’s `path` field. Consecutive pairs must join at the same device. Qualification checks both ends of every live link, the endpoint roles and the firewalls encountered. A Gray path may cross several routers or switches.

The qualification report counts accepted controls and faults separately. A new port above 32767 found on just one device is ineligible if the port is absent from the assigned healthy configuration. Kernel routing-table numbers, certificate expiry dates and configured IPsec lifetimes retain their original meanings.

Topology size changes the search only when it adds eligible locations. For example, increasing the number of levels creates more potential Inner gateways at both sites. Each site still has a single shared Outer gateway. Compare results for each fault with the number of devices or levels that could actually exhibit it. A completed study measures the registered mix of placements. Independently registered repetitions can measure how much the result varies from one placement to another. [Eligible locations and capture checks](panel.py)

## Run both detectors and review their answers

```sh
python3 scale/panel.py tdn runs/registered-study --workers 3
python3 scale/panel.py astra runs/registered-study --workers 3
python3 scale/review.py runs/registered-study Base inner-mode --findings review.json
python3 scale/report.py runs/registered-study report.html
```

The study presents the healthy controls and faulty captures in mixed order. Astra's prompt and read-only operations are identical in all sessions. Every review must include the answer's SHA-256, `complete: true`, and a list of findings. Quote each distinct claim and supply the evidence and reason for its classification. An empty list records a completed audit that raised no issue. Use the registered variant name when reviewing a healthy capture.

| Classification | When to use it |
| --- | --- |
| `target` | The answer identifies the actual fault at an affected device. Record `identified_fault` and `devices`. A name, a unique observed address, or a quoted description that identifies one device is sufficient. For a description, record `location_quotation` and the matching inventory fields under `device_description`. Any CSfC citation is acceptable. |
| `consequence` | The answer describes an effect of the change. Symptoms alone earn no detection credit. |
| `other_real` | The capture and document confirm a different finding. |
| `false_positive` | The capture or document contradicts the claimed issue. |
| `unresolved` | The evidence cannot settle the claim. |

TDN earns credit when an obligation fails after Lean has loaded the evidence and the identical proof program passes on the fault’s registered healthy configuration. The scorer accepts a failure in any registered obligation. An import failure is recorded separately and prompts repair and replay. The report lists false alarms, unresolved alerts and other genuine findings separately. It also counts how many independent controls drew a false alarm and how many drew any alert. [Grading](review.py) · [Report](report.py)

## Audit or replay an existing collection

```sh
python3 scale/audit_archive.py runs/original-study new-cue-audit.json
python3 scale/replay.py runs/original-study runs/proof-replay --workers 3
```

An archived run can validate a repair against known inputs. An archived candidate qualifies for a new placement study only when it matches the registered location and passes the same evidence checks as every other candidate. Keep the original results and the replay in separate directories.
