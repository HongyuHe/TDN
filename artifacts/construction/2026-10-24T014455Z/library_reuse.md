# Library reuse assessment

## Tested versions

The baseline pins Lean 4.34.1 and Mathlib d13f23b723b8a846827a245b89c10fc7d3f11612. The official CSLib checkout at 6ff325e870ed89f86be10515f0e7297fa5a32845 requires Lean 4.36.0-rc1. Its official toolchain history identifies 990e65a685bed413f43b139db900a36ad5322a10 as the latest revision before the 4.35 series. That revision targets 4.34.0.

The isolated experiments/cslib uses the baseline Lean and Mathlib with that pinned CSLib. `lake update` and `lake build Compat` succeeded; build.log records 658 successful jobs. Compat.lean proves preservation of a numerical state invariant via `mtrInv_of_trInv` and an actual simulation. No baseline toolchain change was required. The active dependency is now pinned to the tested revision.

## Candidate declarations and decisions

All paths below refer to the pinned official CSLib checkout in references/cslib.

| Candidate | Assumptions and model connection | Decision |
|---|---|---|
| Foundations/Semantics/LTS/Basic.lean: LTS | State and action types; ternary transition relation. Supports explicit route, filter, encrypt, decrypt, switch and delivery actions without finite-state restrictions. | Adopt for new packet execution. |
| LTS.MTr | Finite list of labels; reflexive empty trace and stepL constructor. Keeps operation order visible. | Adopt for finite protected-payload executions. |
| LTS.mtrInv_of_trInv | Each actual permitted step preserves the predicate. Does not prove network-specific preservation. | Adopt to lift checked local packet-processing lemmas. |
| Foundations/Semantics/LTS/Simulation.lean: LTS.IsSimulation | Both systems share labels; each detailed step must match one abstract step. | Use only with explicit abstract stuttering steps for route/filter events. Plain existing Network.Step cannot match those events. |
| LTS.IsSimulation.sim_trace | Simulation and related initial states yield matching full finite traces with related endpoints. | Adopt where the connecting simulation is proved; never count assumed simulation as snapshot compliance. |
| LTS.HasTau and saturate | Internal labels are explicit and saturate permits internal multistep matching. | Evaluated; straightforward explicit stuttering suffices for first packet model. Preserve option for later protocol abstraction. |
| Mathlib.Logic.Relation.ReflTransGen | Unlabelled finite reachability and induction. Current Paths/Temporal arguments are short and independent of operation labels. | Retain for topology and existing temporal proofs; replacing those arguments supplies no additional obligation coverage. |
| Mathlib.Data.Finset.Basic and List membership | Finite inventory quantification and decidable checks. | Retain to check complete imported sets and per-record constraints. |

The assessment does not claim completion of packet semantics. Actual use declarations and final validation are updated as implementation progresses.

## Event admission and record coverage continuation

TDN/Semantics/Admission.lean directly reuses the pinned CSLib LTS, MTr and mtrInv_of_trInv declarations. A step records an event only when its matching predecessor exists in the prior history. The preserved predicate then covers every event in every finite admitted history. Administration and Provisioning instantiate the relation for authentication, patch testing, and key-generation/CSR/signing/installation order. These events use explicit causal order fields; physical deadlines use separate UTC-second fields. Mathlib/Lean list membership and map/flatMap lemmas establish finite inventory coverage in RecordCoverage, Governance, Testing and SIEM. No second execution closure was introduced. Successful module builds are retained in experiments/administration-auditing-v4-build.log, incidents-v2-build.log, governance-v1-build.log, management-v1-build.log and provisioning-siem-v1-build.log.

## Route-aware hooks, trace accounting, encapsulation and sequence freshness
The pinned CSLib LTS.MTr and mtrInv_of_trInv remain the basis for packet preservation. RoutedFrame retains an actual SelectedRoute until the hook, and FiniteRoutedExecution adds that route's destination interval to local rule checks. The original stronger finite checks still instantiate the same general theorem. The all-IPv6 application and positive trace compile; seven other cases exposed configuration failures rather than a library limitation.
TraceAccounting reuses MTr induction for a generic credit/debit conservation identity. ExecutionHistory instantiates it with actual envelope pushes and pops. Encapsulation reuses the same transition foundation for unchanged opaque bodies and endpoint-restricted unwrapping.
SequenceFreshness reuses Admission, whose prior-event theorem was already derived with CSLib invariant preservation. Its arithmetic receive-age lemma uses Lean omega on sequence thresholds and millisecond timestamps. No additional trace framework is introduced. LinkProtection models one local data-port operation and proves universal emission confidentiality directly by cases; an LTS wrapper would not simplify that one-step result. Its composition with network execution remains an actionable task.

## 2026-10-24: finite fragments and event occurrences

Fragmentation.lean directly constructs CSLib LTS.IsSimulation from the local StepProjection relation and calls IsSimulation.sim_trace. Internal fragment/reassembly actions map to stuttering steps. The concrete carrier now holds any finite list of fragments; valid pieces have equal descriptors, contiguous offsets and exactly the original byte sequence. SegmentedStep preserves those facts. The simulation then transfers the previously proved packet invariant. The implementation connection is an explicit separate obligation under C-FRAGMENT-001.

TraceEvents.lean uses CSLib MTr induction to find a concrete predicate-changing step with its actual prefix and suffix. ExecutionEvents.lean applies that general result to actual encryption/decryption and proves Inner-before-Outer order. The identical theorem is applied to the shared and baseline native cases and all eight family cases in FreshNativeLayerOrder. These uses reuse the pinned CSLib dependency described above, rather than introducing an independent trace relation.

## 2026-10-24 13:59 UTC: minimal exposure and packet alignment

Mathlib.Order.Minimal defines Minimal for the subset order and proves Set.minimal_iff_forall_sdiff_singleton at lines 348–352 of the pinned source. The theorem requires upward preservation of feasibility, then reduces minimality to feasibility plus failure after each single removal. Components.minimal_exposure_from_necessary_permissions directly reuses that theorem. The encompassing source specification uses Minimal and does not require the supporting monotonicity assumption universally. PacketLength reuses Nat.div_le_div_right and order monotonicity to bound all aligned encodings by the maximum. CSLib is unnecessary for those static set/arithmetic arguments; it remains the foundation for execution and state preservation.

The 14:17 UTC PF extension uses CSLib LTS.mtrInv_of_trInv to preserve an empty connection-state cache through arbitrary finite packet/expiration histories. List.Sublist models expiration without inventing state. Filter.denying_prefix_blocks then combines finite source/interface rule coverage with an arbitrary remote destination and packet history.

### Gregorian calendar reuse, 2026-10-24 15:10 UTC
Reviewed the pinned Lean 4.34.1 standard library Std.Time.PlainDateTime.ofWallTime, addMonthsClip and toWallTime, plus WallTime.ofSeconds/toSeconds and the Year/Month offset types. Adopted those pure conversions in TDN.Semantics.CalendarTime. They compute actual Gregorian month anniversaries while preserving UTC time of day. The existing RecordCoverage.not_deleted_during_retention theorem supplies the deletion-history-to-current-presence argument. No networking-specific calendar implementation or new axiom is introduced. CalendarRetention.lean checks leap-day arithmetic and rejects early deletion, arbitrary distant registration expiry, prepublication registration and cross-solution registration.

### 2026-10-24: fragment byte-origin histories

ReassemblyOrigins uses the already pinned CSLib LTS.MTr and mtrInv_of_trInv. A local receive rule checks a fragment against an input/interface/association guard; discard and clear cannot introduce bytes. The generic proof preserves a predicate on every byte across all buffer histories. Mathlib List.mem_flatten and List.mem_map connect assembled bytes to admitted pieces. No new simulation or induction framework was introduced. The exact-packet Fragmentation simulation remains a separate conditional result and does not infer payload identity from an ordinary fragment key. The recorded fragment-origin-mixing-local-invariant build and mixed-origin-assembly-regressions validate the new declarations.

## 2026-10-24: arbitrary mixed inbound boundaries

MultiProtocolAuthentication reuses TraceEvents.changing_predicate and the existing CSLib finite-trace relation. The proof follows a region condition through every non-decryption transition. A trace that reaches the protected side must leave that condition through a real local receiving operation. RestrictedExecution projects the component-local trace into the original transition system. FiniteMultiProtocolAuthentication connects the remaining carrier INPUT condition to the ordered local filter rules. The construction does not assume an already protected incoming body. The existing pinned CSLib revision and compatibility assessment continue to apply.

Twenty-eight applications reuse the same theorem across six mixed-protocol pairings and the bridged opaque-Ethernet case. Every application has a positive inward segment and nonempty observed attachments. Local configuration and cryptographic implementation contracts remain distinct from the Lean trace proof.

## 2026-10-24: response history and scheduled cover

HistoricalResponses and UniformResponseRegions reuse CSLib finite executions and invariant preservation. Saved safe packet contexts permit delayed error handling without assuming that the current ESP bytes are the quoted plaintext. The concrete family444-v13 proof checks every observed device owner and retains a positive execution.

CoverTraffic uses the same pinned CSLib preservation theorem for FIFO arrivals and scheduled sends. Mathlib list membership and map results establish padding/queue preservation and equal size observations under equal schedules. Construction independently reviewed the coordinator contribution and mapped its bounded conclusions to RG032. Exact source/runtime and timing qualifications are in transec-cover-review.md.

## Clock correction measurements and final MACsec parameter applications
Reviewed 2026-10-24. ClockSamples.successful_sample_improves_displaced_clock uses integer magnitude and Lean Omega to combine the checked final bound with the initial displacement. A transition-system library would not add behavior to these three finite observations. TimeSynchronization.trusted_time_from_component_assignments assembles the source-specific assignment obligations without assuming source trust from an NTP response.

FinalMACsecProtection reuses macsec_protection_from_local_checks and LinkProtection.every_emitted_frame_is_encrypted. The separate SequenceFreshness.accepted_transmission_is_recent theorem remains the candidate for a physical freshness conclusion. Its authenticated counter/sample and age conditions have not been replaced by successful finite delay probes.

## Strict responses, received fragment paths and key-server priority
Reviewed 2026-10-24. StrictResponseProjection reuses CSLib MTr.stepR and the existing OUTPUT-confinement invariant to recover an underlying network execution. Existing full-label delivery theorems therefore apply unchanged to the extended gateway response behavior.

ReassembledDelivery derives the local byte-domain guard from actual source-interface and network-path checks. ReassemblyOrigins then reuses CSLib preservation for arbitrary fragment buffer histories, without equal source-packet identities. The backend mapping from received fragments to those paths is explicit; the next construction extends the model to allow intermediate plaintext reassembly followed by continued forwarding.

The coordinator's MACsecKeyServer argument uses finite natural-number priority comparisons. A new transition framework is unnecessary for the configured choice. Distributed election scheduling remains outside that arithmetic result.

## ByteFlows and intermediate plaintext assembly
The new finite-packet machine reuses CSLib LTS.MTr, MTr.stepL, MTr.comp and mtrInv_of_trInv. Mathlib's list membership, flattening and map facts connect each split or assembled byte to an earlier carrier. Local injection, forwarding and assembly preservation replace a global same-packet assumption. PlaintextAssembly proves that changing an assembled packet header at the same receiving interface preserves the existing domain invariant. The unchanged native finite route/filter/SA checks instantiate the result for shared four-domain and baseline two-domain inventories.

The positive regression follows the actual shared trace, splits and assembles at the Inner Red ingress, then continues through both encryption layers and delivery. Byte values are illustrative. The separate regression combines different packet identifiers without adding an equality guard.

The reviewed MD15 model also uses CSLib mtrInv_of_trInv. Its creation/removal argument records key origin and allows arbitrarily many renewed EAP participants. Complete public configurations and pinned source entry points supply the local disabled-pre-shared guard.

## Combined byte and gateway-response execution
ResponseByteFlows composes the existing generic ByteFlows and KernelResponses machines. CSLib preserves the per-byte property across the combined transition relation. The existing strict OUTPUT proof excludes external reply emissions without a quote-body restriction. The native applications reuse the already checked domain and gateway rules. Ordinary useful traces remain admitted; a separate byte-flow trace splits and rejoins at the Inner ingress before continuing through both encryption layers.

## Uniform component replies and saved byte contexts
The component-response extension directly reuses KernelResponses.local_reply_checks_preserve_network_safety and the pinned CSLib LTS.mtrInv_of_trInv through ByteFlows. UniformDomainResponses derives its local reply condition from absence of inbound associations, equal interface layouts, route-owner equality and per-domain allowed-port closure. The proof never assumes the desired final delivery claim.

Mathlib List.Sublist.subset proves removal preservation. List membership proves explicit copied-prefix preservation. The prior List.Perm.mem_iff argument handles arbitrary interleavings. These local lemmas extend the existing ByteFlows theorem without introducing a new reachability infrastructure.

## Individual byte paths and operation order
ByteLineage reuses ByteFlows.all_executions_preserve_byte_properties with a source-path predicate. CSLib MTr.stepR extends the byte path through packet and assembly steps. TraceEvents.changing_predicate_has_event finds the actual tag-adding operation, and the existing Execution missing-tag lemma identifies encryption. The document-specific order theorem then uses local domain conditions and finite Outer-region layouts. No new global compliance premise or packet-ID uniqueness assumption is introduced.


## Fragment header completion

FragmentHeaders uses ordered Filter.evaluate induction and List.all facts to prove inclusion for every missing transport-field completion. CSLib remains the execution foundation; no new transition framework was introduced. The local filter inclusion can support the existing CSLib invariant composition once authenticated reassembly is connected. The source and concrete-check limits are recorded in fragment-header-nft-review.md.

## Mixed byte protection and authenticated assembly

MixedByteFlows directly reuses ByteFlows, ByteLineage, CSLib.LTS.mtrInv_of_trInv and TraceEvents. The existing mixed local-condition proof supplies the network steps; a short plaintext-assembly lemma supplies the added step. The same theorem is applied to seven configurations and eighteen useful paths. AuthenticatedAssembly also reuses CSLib invariant lifting. Its authenticity contract concerns actual plaintext and prior publications; it does not authenticate ghost annotations. See authenticated-assembly-review.md for the remaining concrete connection.

## Final partial-clause library decisions — 2026-10-24

PlacementClauses directly uses Mathlib List.relationReflTransGen_of_exists_isChain_cons from Mathlib/Data/List/Chain.lean, lines 400–403. A finite checked branch becomes the existing relation closure. The Red egress and redundant firewall applications reuse TDN.Paths.no_firewall_free_crossing unchanged. The new import contains eight independent branch checks and four redundant Outer checks, without a new path framework.

PeerInteroperability reuses MultiProtocolExecution.all_executions_preserve_original_ethernet, which uses CSLib LTS.mtrInv_of_trInv. The concrete forward and reverse 30-step deliveries discharge the trace premises. Mathlib list-to-finset membership and subset reasoning supplies complete peer issuer coverage. VPN certificate uniqueness uses Mathlib List.inj_on_of_nodup_map.

RecordedOperations uses Mathlib.Logic.Relation ReflTransGen refl/tail and closure induction at the pinned d13f23b723b8a846827a245b89c10fc7d3f11612 revision, lines 388–390. The coordinator also inspected CSLib LTS.Basic mtrInv_of_trInv at 990e65a685bed413f43b139db900a36ad5322a10, lines 193–196. The power clause needs an unlabeled finite observed-state relation. Mathlib's existing closure fits directly; adding action labels would add no supported scope. Packet and authentication lifecycle proofs continue to use CSLib.

## Auditor rotation source correction

AuditRotation uses Mathlib list flattening, append associativity, List.prefix_append and List.IsPrefix.trans. The claim is a single observed storage operation followed by append-only activity. A new transition system or CSLib action layer would add no evidence-supported behavior. The generic result preserves exact order and multiplicity and can start from any archive/active inventory. Its observed-prefix form permits an independent earlier read without claiming the complete pre-rotation file was captured.

The former RG069 method/path permission theorem remains useful access-control support. It is no longer used to count the component-access or log-review duties. The replacement application targets the actual log-management operation in p054:u014.s001.
