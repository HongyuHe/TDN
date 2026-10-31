# Evidence-driven CSfC construction

The run reconstructs the Lean development from the extracted specification and newly collected emulation evidence. Both agents were launched independently as GPT-6 Astra with Extra High reasoning. The run began on October 17, 2026 at 20:50 UTC.

**Status: converged on October 17, 2026 at 23:17 UTC.** Every target and representative case has an explicit outcome, and no actionable evidence request remains unanswered. Repository validation and the fresh-host deployment replay passed.

## Outcomes

The construction register retains all 76 original targets and 749 recorded source-clause entries. Nine encompassing propositions are encoded in Lean. The other 67 whole-target encodings remain open, alongside the stated evidence, interpretation and proof gaps. Supporting lemmas and partial clause results do not count as completed encompassing targets.

| Target disposition | Groups |
| --- | ---: |
| Established within listed model and snapshot scopes | 3 |
| Partial results | 25 |
| Conditional results | 1 |
| Demonstrated violations | 2 |
| Unavailable evidence | 27 |
| Unresolved interpretation | 13 |
| Unresolved proof construction as the primary disposition | 5 |
| **Total** | **76** |

The disposition table records each group's primary outcome. The separate count of 67 unencoded encompassing targets can overlap with partial results and unavailable evidence. Neither count is a claim of mathematical impossibility.

| Complete scoped target | Checked instances | What the instance establishes |
| --- | ---: | --- |
| RG-022 | 16 profiles | Every imported loaded VPN mode policy meets the stated IKEv2 and encryption-mode conditions |
| RG-034 | 6 profiles | The declared Public Internet topology satisfies Outer Firewall placement and the modeled internal/external connectivity conditions |
| RG-038 | 6 profiles | Every packet accepted by the modeled filter hooks satisfies the selected protocol, IPv4-header and multicast restrictions |

The scoped counts include five native FRR/OVS profiles and their individually identified historical counterparts. A historical Linux result is never relabeled as native. The final [Construction report](integration/CONSTRUCTION_REPORT.md) lists the scopes, premises and remaining clauses.

The case register accounts for all 57 representative cases: 45 covered, 11 partial and one unavailable. Coverage means that an example or alternative is represented by the recorded experiment. Coverage does not establish every requirement applying to that example. All 19 Construction evidence requests have supplied, partial or rejected outcomes, and the initial broad request is explicitly superseded.

## Scope and isolation

All 76 proposed theorem statements entered the construction register before proof work began. The Evidence Agent expanded the nine topology examples, seventeen configuration records and one protocol record into 57 representative cases. A case records a particular arrangement or alternative; a case count is not a count of independently deployed networks.

The original Lean tree, importer, supporting tests and entrypoints were preserved under `archive/v1/`. Both agents received fresh workspaces and specification-derived inputs. A sandbox wrapper denied access to the original TDN repository, archived proofs, prior reports, Codex memories and original Twinet checkouts. The agents could exchange explicit evidence requests through the coordinator. The wrapper restrictions and their enforcement limits are recorded in [session.json](session.json) and [coordination](coordination/). Tool capabilities outside the wrapper could not be removed at the application level, so the recorded isolation controls are not presented as a complete security boundary.

Management remains an optional separate profile. A missing management observation does not block a theorem about the management-free data path. Management requirements retain their own partial or unavailable outcomes.

## How the proof construction changed the emulations

The strongest correction came from checking topology paths rather than relying on successful traffic probes. The first shared-Outer experiment passed all 30 sampled Red-host probes, but its topology contained six cross-level Gray paths avoiding a Gray Firewall. One witness was `I_A1–G_A1–O_A1–G_A2–I_A2`. The revised shared and redundant profiles place the Gray Firewall inline between each Inner attachment and the shared Outer arrangement. The repaired graphs admit a local separator certificate, which a reusable Lean induction theorem lifts to every finite modeled path.

The authentication audit tightened the configuration without changing the credentials. The original public-key settings permitted broader authentication choices. The revised settings explicitly require `ecdsa-384-sha384` for local and remote authentication. A fresh-session trial selected SHA384. A negative trial signed with SHA256 and recorded the responder's policy rejection; restoring SHA384 restored the session and useful traffic. Broad responder capability advertisements remain separate from the effective peer policy.

The expanded topology cases required separate network identity and security-level fields. Figure 5 represents independent Red networks at the same full security level. Treating level equality as network identity would incorrectly expect communication between those networks. The new profiles preserve separate network identities and trust domains. The four-level variants also retain Top Secret, Secret US-only, Secret Coalition and Unclassified so that the extracted source cases remain represented.

The final reusable profiles run FRR routers and OVS switches with native CLI access. The initial clean-workspace handoff omitted the user's standing runtime requirement, and the first experiments used the legacy Linux/static-routing backend. The coordinator identified the omission and required five fresh native profiles. Historical captures keep their original backend labels and proof scopes. Native captures add FRR control-container namespace associations and OVS Bridge/Port/Interface UUID relationships, with raw interface identities and CLI output.

The mechanism experiments exposed several implementation and collection problems. Recovery initially reused unsuitable security-association state; the corrected IPsec harness installs fresh AES-GCM key material, while MACsec link recovery retains its association and packet number. Strict CRL authentication required authority-key identifiers in the generated CRLs. The objective IKEv2 exchange required a pinned experimental ML-DSA implementation and corrected message-fragment handling. Failed trials remain available alongside the repaired observations.

## How the models and proofs changed

The new library separates generic arguments from concrete evidence. `TDN/Semantics/Paths.lean` uses Mathlib's reflexive-transitive closure to prove a firewall-separator theorem. Concrete imported graphs supply finite local checks. `TDN/Semantics/Filter.lean` and `PacketPolicy.lean` prove properties of first-match filtering; imported ordered rules supply the corresponding guards. `TDN/Semantics/Boundary.lean` allows unsafe operations and requires a local safety certificate before deriving protection-layer preservation.

The importer became stricter as mismatches were diagnosed. It rejects unknown active interfaces, omitted memberships, inconsistent raw observations and unsupported rule syntax. It distinguishes a genuine no-reply ping from a timeout, invocation error or missing interface. It treats negotiated sessions separately from complete loaded policy inventories. It also distinguishes a TLS application result from ICMP packet counts, and an NTP reply from actual clock synchronization.

Several failed checks exposed construction errors rather than deployment faults. A direct-edge interpretation of Outer-to-Black connectivity was stronger than the source text and was removed. A later two-link limit on Gray connectivity was also replaced by explicit path witnesses. Protocol fragment records may arrive out of numerical order, so completeness is checked as a duplicate-free set. Captured IKE notifications are bound to exact peer address pairs because an Outer observer can also see Inner-addressed traffic.

The native importer checks the connection between device records and actual runtime observations. FRR control sidecars use a separate process namespace but share the forwarding device's network namespace. Either verified container may execute `vtysh`. OVS table rows are joined through UUID references and checked against raw Linux ifindices and MAC addresses. The topology graph conservatively connects the listed switch ports; the graph proof does not certify OpenFlow execution or the entire Linux packet-processing pipeline.

The native transport declaration also needed correction. Its first version classified every device with the general transport role as Black, including two Gray routers. The importer rejected the classification against the observed interfaces. The second declaration names only the Black router as Black transport and preserves the Gray router identities separately. Both declaration versions remain available, and their specification and snapshot hashes are unchanged.

The management profile exposed an importer omission rather than a failed network requirement. A TLS response rule used a source-port match that the translator did not support. The translator gained a separate source-port condition while preserving destination-port semantics. Management-specific assumptions and results remain separate from the management-free theorem scopes.

## Deployment replay

The packaged native baseline was rebuilt and deployed on `clnode163` after the five main profiles had been validated on `clnode176`. The fresh host initially lacked Docker and Go. The recorded gate verified the source and image archives, loaded the images, built Twinet, ran the MSC and documentation tests, deployed the baseline, checked it and collected a fresh snapshot and process inventory.

The complete second-host gate ran from 23:01:12 to 23:07:27 UTC. Image loading took about 77 seconds, compilation 45 seconds, deployment 86 seconds and the MSC check 61 seconds. The [replay instructions](agents/evidence/outputs/REPLAY.md) include an executable image-build recipe for use when the saved image archive is unavailable. Source rebuilds record their resulting package versions and image IDs; the saved archive reproduces the earlier image bytes.

The integrated Twinet changes are in the local `codex/msc-construction-v2` worktree at `/Users/hongyu/Projects/Twinet-construction-v2`. The run also preserves the complete [public Twinet source](agents/evidence/Twinet/) and a [changed-file manifest](agents/evidence/outputs/twinet-changed-files.json). The original Twinet checkouts and their unrelated local changes were preserved.

## Remaining limits

The outcome register separates a fully checked target within a named scope from partial clause results and conditional theorems. A configuration proof establishes a property of the captured configuration. A generic proof establishes its conclusion under explicit model premises. Neither result independently certifies the collector, the source interpretation, physical equipment or all future execution.

The current lab cannot supply product certification, manufacturer independence, physical-device separation, personnel authorization, approved organizational processes or missing external annexes. Some emulated arrangements therefore demonstrate a violation or remain partial even when their traffic works. Those outcomes remain visible for the affected requirement groups.

The negotiated MACsec experiments retain concrete limitations. EAP-TLS authentication succeeded in the recorded role arrangements, but successful EAP-derived protected delivery was not established. The tested PSK implementation also needs a separate delay-protection assessment: its required two-second hello interval does not automatically establish the required delay-protection behavior. A successful encrypted ping does not discharge those obligations.

## Where to inspect the evidence

- [Proof register](integration/theorem_register.json): every original target, current outcome, clause contribution, assumptions and evidence dependencies.
- [Representative-case register](agents/evidence/outputs/case_coverage.json): source cases, containment choices, snapshots and remaining gaps.
- [Proof evolution](agents/construction/outputs/EVOLUTION.md): modeling corrections, failed attempts and validation rounds.
- [Agent interactions](INTERACTIONS.md): exact public requests, responses and coordinator feedback.
- [Combined timeline](EVOLUTION.md): UTC-indexed changes with reasons and links to preserved records.
- [Portable input map](source_paths.json): repository-relative paths used by the validation runner.
- [Coordinator source review](validation/coordinator-semantic-sample.json): selected semantic checks with source hashes and explicit limits.

Each agent history contains source checkpoints, command results and hashes. Snapshots remain immutable under `artifacts/snapshots/`. Derived scope corrections retain their parent manifests and explain the change. Early commands that preceded complete checkpoint instrumentation retain their available logs, with that recording limitation stated explicitly.

## Final validation

The repository's [complete validation](integration/integration-final-native-validation.json) passed all 76 commands and 136 Python tests. The commands regenerate evidence, compile Lean, check every registered theorem reference, exercise semantic examples, audit selected theorem axioms and run importer mutation tests. The independent Construction workspace had passed the same workflow with 92 proof/importer tests; the repository run also includes the existing preprocessing tests.

The Twinet full Go suite passed, and the second-host replay repeated the MSC and documentation checks against the packaged source. The coordinator verified that all 561 archived files retain their original hashes. [The closing checks](validation/final-coordinator-checks.json) and [workflow bookkeeping](validation/workflow-bookkeeping.json) record those results and the remaining limits. No third-party reviewer PASS is claimed for this run.

The changes and records are saved locally. No commit or push was performed. The runtime image archive is retained locally with its hash and excluded from Git; the public source and image-build recipe provide a rebuild path.
