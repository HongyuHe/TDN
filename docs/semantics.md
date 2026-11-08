# Reusable network models and proofs in `TDN/Semantics`

`TDN/Semantics` provides network models and general proofs that can be applied to different configurations and snapshots. The modules describe packet processing, topology, filtering, encryption layers, authentication, fragmentation, generated replies, authenticated operations and cover traffic. A caller supplies the relevant configuration and proves the theorem's premises for that configuration.

The catalog covers all 111 active Lean files in `TDN/Semantics`. It indexes 1064 explicitly named declarations and 79 explicit instances. Each index links to the current source line. Constructors, structure-field projections, and automatically derived declarations are represented by their parent types.

Each module section explains its purpose, principal results, and conditions for reuse. The expandable declaration index in each section links every named declaration to its source line. The source links are relative to the repository so they remain usable in another checkout and on GitHub.

## How to read the library

A **model** describes the states and operations considered by a proof. For example, `Execution.Step` describes one packet-processing operation. An **invariant** is a condition that remains true after every permitted step when it is true initially. A **trace** is a finite sequence of permitted steps. A theorem about every trace can cover arbitrarily long finite executions without enumerating them.

A **predicate** is a condition on a value, such as whether a node is a firewall. A **contract** is an explicitly required guarantee from another model or implementation. A **soundness theorem** proves that passing a check is sufficient for the condition claimed by that check. An **induction proof** establishes an initial case and proves that one more permitted step preserves the result. The same argument then covers any finite number of steps.

An **assumption** or **premise** is a condition that must be supplied when applying a theorem. For example, a link may be required to connect interfaces with the same expected encryption stack. A **witness** is concrete supporting information, such as a path demonstrating connectivity. A **local check** verifies one of the required conditions from the supplied data. Local checks can compare several devices or inspect an entire finite rule list.

Lean declarations serve the following roles:

| Lean construct | Meaning in the library |
| --- | --- |
| `structure` | A record with named fields, such as a route or device. A structure ending in `: Prop` packages logical conditions that need proofs. |
| `inductive` | A type or relation defined by its permitted cases. The constructors of `Execution.Step` specify which packet-processing steps exist. |
| `def` | A named computation or expression. A definition returning `Prop` states a condition, such as a required relationship between interfaces. |
| `abbrev` | A short name for another expression or type. |
| `lemma` | A checked supporting result, such as preservation by one step, a finite record check, or the assembly of local assumptions. |
| `theorem` | A checked principal result offered by the module, such as a reusable execution guarantee, a requirement result, or its application to a snapshot. |
| `Decidable P` | A method that determines whether proposition `P` holds and supplies a proof of the outcome. The finite-check modules provide instances for their supported conditions. |
| `by decide` | Ask Lean to use the available decision method to prove a concrete proposition. It operates on Lean values that have already been imported or defined. |
| `∀ x, ...` | The condition holds for every `x` of the stated type. |
| `∃ x, ...` | Some `x` satisfies the condition. Applying the result may reveal that witness. |
| `P → Q` | Given a proof of `P`, the result supplies a proof of `Q`. |
| `P ∧ Q` | Both conditions hold. |
| `P ∨ Q` | At least one of the conditions holds. |
| `system.Tr before action after` | One permitted step connects the two states with that action. |
| `system.MTr before actions after` | A finite trace connects the two states with the listed actions. |
| `system.TrInv property` | Every permitted step preserves `property`. |
| `Relation.ReflTransGen edge a b` | A path of zero or more edges connects `a` to `b`. |

A principal theorem retains that role when another theorem uses it. For example, `execution_preserves_stack_invariant` is a reusable result supported by the lemma `step_preserves_stack_invariant`. Concrete evidence uses lemmas for edge checks, initial states, and local conditions, then theorems for the resulting network property. The choice of keyword depends on the result's role; a proof using `by decide` can establish either a supporting fact or a final result. Lean checks both kinds of proof in the same way.

The word **stack** means the ordered list of encryption-layer tags in a modeled packet. The first tag is the outermost layer. For example, `[2, 11]` describes Outer layer `2` surrounding Inner layer `11`. The tags identify protection layers in the proof. Actual addresses, protocol fields, and SPIs have separate fields.

An **interface** is a modeled connection point identified by a natural number. The configuration maps interfaces to their devices and interface names. The **expected encapsulation stack** assigns an expected protection-layer list to each interface: `expectedEncapStack : Nat → List Nat`. An interface might expect `[]` on Red, `[11]` on Gray, or `[2, 11]` on Black. The `expectedEncapStack` function supplies proof annotations whose consistency must be proved against the operational configuration. `TDN.Execution.data_plane_ignores_encap_stack_annotations` establishes that changing only the stored stack annotations leaves the modeled operational configuration unchanged.

A **projection** maps a detailed state to the information retained by a simpler model. For example, a fragmented-packet state contains both a logical packet state and its pieces; a projection can retain only the logical state. A proof relating the models checks each detailed step and then transfers properties across complete traces. Some detailed steps can leave the projected state unchanged, as splitting a packet can leave its logical identity unchanged.

The naming choices and their networking meanings are recorded in [Network terminology and model refinement](network_terminology.md).

## Organization and dependencies

The modules separate general arguments from the finite data used to apply them. None of the 111 modules imports a snapshot, an instance module, or a document-specific target. Every direct project import stays within `TDN.Semantics`. Some modules describe broadly reusable mathematics; others describe a specific supported network mechanism or configuration pattern, such as authenticated fragment assembly.

| Topic | Starting modules | What a caller supplies |
| --- | --- | --- |
| [Topology and packet policy](#topology-and-packet-policy) | `Waypointing`, `Addressing`, `Filter`, `PacketPolicy` | Edges, labels, ranges, ordered rules, and coverage of relevant connections. |
| [IP packet execution](#ip-packet-execution) | `Execution`, `ExecutionInvariant`, `FiniteExecution` | Devices, interfaces, routes, rules, policies, installed associations, links, and checked expected encapsulation stacks. |
| [MACsec and mixed-protocol execution](#macsec-and-mixed-protocol-execution) | `LinkProtection`, `LayeredFrame`, `MultiProtocolExecution` | MACsec settings, associations, logical/physical interfaces, carriers, and their connection to IP processing. |
| [Generated replies](#generated-replies) | `KernelResponses`, `SourceResponseGuards`, `GuardedResponseNetwork` | Reply-generation scope, source/output rules, route choices, and safety of allowed emissions. |
| [Fragments, copied bytes, and reassembly](#fragments-copied-bytes-and-reassembly) | `Fragmentation`, `ByteFlows`, `AuthenticatedAssembly` | Byte origins, assembly rules, encodings, and any authentication contract. |
| [Trust and access](#trust-and-access) | `Trust`, `IKEContexts`, `KeySources`, `AccessControl` | Authority/key ownership, reciprocal peer observations, permitted key sources, and role permissions. |
| [Events and general trace arguments](#events-and-general-trace-arguments) | `Admission`, `TraceEvents`, `TraceAccounting` | Event meanings, timestamps, prerequisites, step invariants, or per-step arithmetic equations. |
| [Packet sizes and cover traffic](#packet-sizes-and-cover-traffic) | `PacketLength`, `CoverTraffic` | Size budgets and the cover-traffic sender model. |

The packet-stack proof follows the dependency chain shown below. Each arrow means that the lower result uses the information or proof above it.

```mermaid
flowchart TD
    records["Imported devices, ifaces, routes, policies, and links"]
    checks["Finite checks, proved for the supplied records"]
    local["LocalStackConditions for the resulting configuration"]
    step["step_preserves_stack_invariant"]
    trace["execution_preserves_stack_invariant"]
    result["transmitted_stack and document-specific consequences"]
    records --> checks
    checks -->|"local_stack_conditions_of_finite_checks"| local
    local --> step
    step -->|"CSLib: mtrInv_of_trInv"| trace
    trace --> result
```

The finite checks and their soundness theorems avoid enumerating all possible packets. They inspect records such as rule atoms and address intervals, then prove that every packet matching those records has the required behavior. The graph and trace induction proofs extend those conditions to paths and executions of arbitrary finite length.

## Example: a finite edge check supports an arbitrary-path theorem

A four-node graph illustrates the complete proof structure. Nodes `0` and `1` connect to firewall `2`, which connects to node `3`. The graph has a real path from `0` to `3`. The property to prove is that every such path must visit the firewall.

```lean
import TDN.Semantics.Waypointing

namespace SemanticsGuide

def edge (a b : Fin 4) : Prop :=
  (a = 0 ∧ b = 1) ∨ (a = 1 ∧ b = 2) ∨ (a = 2 ∧ b = 3)

def firewall (node : Fin 4) : Prop := node = 2

def side (node : Fin 4) : Nat := if node = 3 then 1 else 0

lemma checked_edges : ∀ a b : Fin 4,
    edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by
  unfold edge firewall
  decide

theorem no_bypass :
    ¬ Relation.ReflTransGen (TDN.Waypointing.Avoiding edge firewall) 0 3 := by
  exact TDN.Waypointing.waypointing_of_edge_invariant edge firewall side checked_edges
    (by unfold firewall; decide) (by decide)

end SemanticsGuide
```

`Fin 4` gives Lean exactly four possible nodes. `checked_edges` checks all endpoint pairs and proves that every edge whose endpoints are both outside the firewall preserves the side label. In the example, the remaining edge `0 → 1` preserves label `0`. The edges touching firewall `2` are excluded by the hypotheses.

`no_bypass` applies the existing general theorem. Its first supplied proof is `checked_edges`. `unfold edge firewall` exposes the definitions to the decision procedure. The two smaller proofs establish that node `0` is outside the firewall and that nodes `0` and `3` have different side labels. The library's induction argument then excludes every finite firewall-avoiding path between the endpoints. A different graph changes the data and edge checks while retaining that general argument.

## Example: checked local processing determines the transmitted stack

The packet theorem states exactly which conditions connect local processing to a two-layer result. In the following example, `checks` is a proof of all `LocalStackConditions` for configuration `c` and expected stacks `expectedEncapStack`. A snapshot application can obtain that proof using the finite-check modules.

```lean
import TDN.Semantics.ExecutionInvariant

open TDN.Execution

example (env : Environment) (expectedEncapStack : Nat → List Nat)
    (checks : LocalStackConditions env expectedEncapStack)
    (inner outer : Nat) (initialState finalState : State) (actions : List Action)
    (run : (lts env).MTr initialState actions finalState)
    (initial : StackInvariant env expectedEncapStack initialState)
    (ready : finalState.datapathStage = .ready)
    (blackIface : expectedEncapStack finalState.iface = [outer, inner]) :
    finalState.frame.tags = [outer, inner] := by
  have stack := transmitted_stack env expectedEncapStack checks run initial ready
  exact stack.trans blackIface
```

The premises identify a permitted finite execution, a valid starting state, a final state ready for transmission, and a final interface assigned the two-layer expected stack. `transmitted_stack` proves that the final frame's tags equal the expected stack at that interface. `stack.trans blackIface` combines the two equalities to obtain `[outer, inner]`.

`LocalStackConditions` is where the network-specific proof work enters the argument. Its fields require evidence about route ownership, links, switching, accepted forwarding and local output, and routing after encryption. `ExecutionEvents.nested_stack_requires_ordered_encryptions` can additionally identify the Inner and Outer encryption events in order when its placement and initial-stack premises hold.

## Applying the modules to another network

A new network application starts by choosing the behavior needed for its requirement. A topology requirement can use `Waypointing`; a packet-protection requirement needs an execution model that includes the relevant forwarding, encryption, switching, and delivery steps. Generated replies, fragment movement, and mixed protocols require the corresponding extensions when they can affect the claim.

1. Import the relevant modules and state the desired property for a configuration parameter.
2. Populate the supported device, interface, policy, route, and observation records from the new network. Preserve every choice covered by the model, including equally selected policies or routes.
3. Supply supporting information such as expected interface encapsulation stacks, domain membership, graph labels, or concrete paths. Keep the meaning of those values explicit.
4. Prove the required checks over the records. Use `by decide` for supported concrete finite propositions. If a check fails, inspect the configuration, translation, and chosen sufficient conditions before changing any general theorem.
5. Apply the appropriate soundness theorem to obtain the general local premises. Apply the path or execution theorem to derive the required consequence.
6. When the requirement includes useful communication, provide a separate accepted packet or delivery trace. A safety theorem can also hold for a configuration that drops all traffic.

The proof applies to the behavior represented by the model and its supplied premises. Deployment claims also require faithful collection, correct translation, and a justified relationship between actual processing and modeled steps. A snapshot supplies fixed-state observations; claims about changing configuration, protocol convergence, or real-time scheduling need models and evidence for those changes.

## External Lean libraries used

The implementation uses Lean 4.34.1 and the dependency revisions recorded in [lakefile.toml](../lakefile.toml) and [lean-toolchain](../lean-toolchain). The module import lists show exactly which libraries each source file uses.

| Library | Used capabilities | Pinned revision or version |
| --- | --- | --- |
| CSLib | `LTS`, one-step relations, finite traces, invariant lifting through `mtrInv_of_trInv`, and simulation between transition systems. | `990e65a685bed413f43b139db900a36ad5322a10` |
| Mathlib | Reflexive/transitive graph paths, list reasoning, bounded natural numbers, arithmetic support, and monotonicity. | `d13f23b723b8a846827a245b89c10fc7d3f11612` |
| Lean and Std | Core types, decidability, and the `omega` arithmetic tactic. | Lean `v4.34.1` |

`Semantics` defines network behavior and the premises connecting its records. CSLib supplies general trace reasoning, and Mathlib supplies general mathematical facts. For example, `ExecutionInvariant` first proves preservation for each network step, then calls `Cslib.LTS.mtrInv_of_trInv` to extend preservation to every finite trace.

## Complete module catalog

The catalog groups all modules by their primary purpose. Namespaces are listed separately because several files extend a shared namespace. For example, declarations from `FiniteExecution.lean` are named `TDN.Execution.*` even though their import path is `TDN.Semantics.FiniteExecution`.

## Topology and packet policy

[Waypointing](#waypointing), [Addressing](#addressing), [InternetAddresses](#internetaddresses), [Filter](#filter), [PacketPolicy](#packetpolicy), [HeaderPolicy](#headerpolicy)

### Waypointing

Source: [Waypointing.lean](../TDN/Semantics/Waypointing.lean). Namespace: `TDN.Waypointing`.

`Waypointing` turns an edge-level check into a statement about every finite path. You supply the graph, a predicate identifying the acceptable waypoints, and a `region` label for each node. Firewalls are one application of that waypoint set. [`Avoiding`](../TDN/Semantics/Waypointing.lean#L5) permits an edge only when its destination is outside the waypoint set; the theorems separately require a starting node outside that set.

[`waypoint_free_path_preserves_region`](../TDN/Semantics/Waypointing.lean#L8) proves that a path avoiding the waypoints preserves its starting label when every edge outside the waypoint set does so. [`waypointing_of_edge_invariant`](../TDN/Semantics/Waypointing.lean#L17) then excludes waypoint-free paths between differently labeled endpoints. [`path_avoids_absent_waypoints`](../TDN/Semantics/Waypointing.lean#L25) establishes that every graph path avoids the waypoint set when that set is empty. A requirement proof can combine that result with an existing connection to show that a mandatory waypoint must exist.

A new topology supplies new edges and labels. The proofs stay unchanged. The graph must include every connection relevant to the claimed path property.

Direct imports: `Mathlib.Logic.Relation`.

<details>
<summary>All 4 named declarations in Waypointing</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Avoiding`](../TDN/Semantics/Waypointing.lean#L5) |
| `theorem` | [`waypoint_free_path_preserves_region`](../TDN/Semantics/Waypointing.lean#L8) |
| `theorem` | [`waypointing_of_edge_invariant`](../TDN/Semantics/Waypointing.lean#L17) |
| `lemma` | [`path_avoids_absent_waypoints`](../TDN/Semantics/Waypointing.lean#L25) |

</details>

### Addressing

Source: [Addressing.lean](../TDN/Semantics/Addressing.lean). Namespace: `TDN.Addressing`.

`Addressing` associates inclusive numeric address ranges with arbitrary labels. [`Range`](../TDN/Semantics/Addressing.lean#L6) stores `low`, `high`, and `label`; [`Contains`](../TDN/Semantics/Addressing.lean#L12) tests membership, and [`Owns`](../TDN/Semantics/Addressing.lean#L15) connects an address to the label of a containing range.

[`Separated`](../TDN/Semantics/Addressing.lean#L18) requires ranges with different labels to be disjoint. [`separated_ranges_unique_label`](../TDN/Semantics/Addressing.lean#L21) proves that an address cannot belong to two different labels under that condition. A network can use security levels or tenant identifiers as labels. The importer must supply the ranges and their intended labels; the library proves the relationship between those supplied records.

Direct imports: `Mathlib.Data.List.Basic`, `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 5 named declarations in Addressing</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Range`](../TDN/Semantics/Addressing.lean#L6) |
| `def` | [`Contains`](../TDN/Semantics/Addressing.lean#L12) |
| `def` | [`Owns`](../TDN/Semantics/Addressing.lean#L15) |
| `def` | [`Separated`](../TDN/Semantics/Addressing.lean#L18) |
| `theorem` | [`separated_ranges_unique_label`](../TDN/Semantics/Addressing.lean#L21) |

</details>

### InternetAddresses

Source: [InternetAddresses.lean](../TDN/Semantics/InternetAddresses.lean). Namespace: `TDN.InternetAddresses`.

`InternetAddresses` gives IPv4 and IPv6 addresses distinct numeric representations. [`encode4`](../TDN/Semantics/InternetAddresses.lean#L6) uses the value of a bounded 32-bit address. [`encode6`](../TDN/Semantics/InternetAddresses.lean#L7) adds `2^128` to a bounded 128-bit address. The three encoding theorems prove that each encoding preserves address identity and that the two families never collide.

[`headerWords`](../TDN/Semantics/InternetAddresses.lean#L24) returns five for an IPv4 key and zero for other keys. [`ipv6_has_no_ipv4_ihl`](../TDN/Semantics/InternetAddresses.lean#L26) verifies the IPv6 case. The function supplies the modeled base-header length when creating an outer header. It does not parse arbitrary IPv4 options or IPv6 extension headers.

Direct imports: `Mathlib.Data.Fin.Basic`, `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 7 named declarations in InternetAddresses</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`encode4`](../TDN/Semantics/InternetAddresses.lean#L6) |
| `def` | [`encode6`](../TDN/Semantics/InternetAddresses.lean#L7) |
| `theorem` | [`families_have_disjoint_keys`](../TDN/Semantics/InternetAddresses.lean#L9) |
| `theorem` | [`ipv4_encoding_injective`](../TDN/Semantics/InternetAddresses.lean#L15) |
| `theorem` | [`ipv6_encoding_injective`](../TDN/Semantics/InternetAddresses.lean#L18) |
| `def` | [`headerWords`](../TDN/Semantics/InternetAddresses.lean#L24) |
| `theorem` | [`ipv6_has_no_ipv4_ihl`](../TDN/Semantics/InternetAddresses.lean#L26) |

</details>

### Filter

Source: [Filter.lean](../TDN/Semantics/Filter.lean). Namespace: `TDN.Filter`.

`Filter` evaluates an ordered list of rules. Each [`Rule`](../TDN/Semantics/Filter.lean#L9) contains a Boolean match function and an allow-or-deny [`Verdict`](../TDN/Semantics/Filter.lean#L5). [`evaluate`](../TDN/Semantics/Filter.lean#L13) returns the verdict of the first matching rule, or the supplied fallback when every rule misses.

[`default_deny_sound`](../TDN/Semantics/Filter.lean#L31) proves that every accepted packet has a desired property when the fallback denies traffic and every allow rule guarantees that property. [`rejects_outside_allowlist`](../TDN/Semantics/Filter.lean#L38) gives the corresponding rejection result. [`accepts_at_first_matching_rule`](../TDN/Semantics/Filter.lean#L61) proves positive acceptance after checking that earlier rules miss. [`denying_prefix_blocks`](../TDN/Semantics/Filter.lean#L69) proves rejection when an initial sequence of deny rules contains a match. [`HasUsefulTraffic`](../TDN/Semantics/Filter.lean#L46) states that at least one useful packet is accepted; a caller must supply that witness.

The packet type and match functions are parameters, so the results apply to several policy models.

Direct imports: `Mathlib.Data.List.Basic`.

<details>
<summary>All 10 named declarations in Filter</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`Verdict`](../TDN/Semantics/Filter.lean#L5) |
| `structure` | [`Rule`](../TDN/Semantics/Filter.lean#L9) |
| `def` | [`evaluate`](../TDN/Semantics/Filter.lean#L13) |
| `lemma` | [`allowed_has_matching_allow`](../TDN/Semantics/Filter.lean#L18) |
| `theorem` | [`default_deny_sound`](../TDN/Semantics/Filter.lean#L31) |
| `theorem` | [`rejects_outside_allowlist`](../TDN/Semantics/Filter.lean#L38) |
| `def` | [`HasUsefulTraffic`](../TDN/Semantics/Filter.lean#L46) |
| `lemma` | [`evaluate_skips_nonmatching_prefix`](../TDN/Semantics/Filter.lean#L50) |
| `theorem` | [`accepts_at_first_matching_rule`](../TDN/Semantics/Filter.lean#L61) |
| `theorem` | [`denying_prefix_blocks`](../TDN/Semantics/Filter.lean#L69) |

</details>

### PacketPolicy

Source: [PacketPolicy.lean](../TDN/Semantics/PacketPolicy.lean). Namespace: `TDN.PacketPolicy`.

`PacketPolicy` supplies the concrete packet fields and rule conditions used by the execution models. [`Packet`](../TDN/Semantics/PacketPolicy.lean#L5) includes addresses, protocol, interfaces, transport ports, header fields, connection state, and inbound/outbound IPsec-policy identifiers. [`Atom`](../TDN/Semantics/PacketPolicy.lean#L98) describes one condition on those fields. A [`Rule`](../TDN/Semantics/PacketPolicy.lean#L159) matches only when every atom holds.

[`Rule.toFilter`](../TDN/Semantics/PacketPolicy.lean#L164) connects those records to the ordered evaluator in `Filter`. [`matching_atom`](../TDN/Semantics/PacketPolicy.lean#L167) recovers any atom's condition from a successful match. [`Guarded`](../TDN/Semantics/PacketPolicy.lean#L181) requires the appropriate interface direction and an inbound or outbound policy condition. [`forwarding_policy_protects`](../TDN/Semantics/PacketPolicy.lean#L211) proves that every accepted packet has one of those guarded directions when every allow rule is guarded and the fallback denies traffic.

The result concerns policy metadata on the modeled packet. The execution modules connect outbound policy selection to an encryption operation and installed state.

The boundary proofs also inspect packet contents. `IKEHeader` checks the represented IKE version and message length. The UDP framing conditions distinguish IKE and encapsulated ESP, account for IPv4 header options, and handle reply ports explicitly. `MKAFraming` checks the supported Ethernet control-frame layout and actor identity. Size and byte-field atoms let ordered filter rules impose the same conditions. These checks establish the listed packet-format conditions; authentication depends on the separate protocol and credential models.

Direct imports: [Filter](#filter).

<details>
<summary>All 19 named declarations in PacketPolicy</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Packet`](../TDN/Semantics/PacketPolicy.lean#L5) |
| `def` | [`IKEHeader`](../TDN/Semantics/PacketPolicy.lean#L28) |
| `def` | [`Packet.IPv4FragmentOffsetDecoded`](../TDN/Semantics/PacketPolicy.lean#L38) |
| `def` | [`Packet.IPsecUDPFraming`](../TDN/Semantics/PacketPolicy.lean#L43) |
| `def` | [`Packet.IPsecUDPFramingWithOptions`](../TDN/Semantics/PacketPolicy.lean#L58) |
| `def` | [`Packet.IPsecUDPReplyFramingWithOptions`](../TDN/Semantics/PacketPolicy.lean#L74) |
| `def` | [`byteField`](../TDN/Semantics/PacketPolicy.lean#L84) |
| `def` | [`Packet.MKAFraming`](../TDN/Semantics/PacketPolicy.lean#L87) |
| `inductive` | [`Atom`](../TDN/Semantics/PacketPolicy.lean#L98) |
| `def` | [`Atom.holds`](../TDN/Semantics/PacketPolicy.lean#L126) |
| `structure` | [`Rule`](../TDN/Semantics/PacketPolicy.lean#L159) |
| `def` | [`Rule.toFilter`](../TDN/Semantics/PacketPolicy.lean#L164) |
| `lemma` | [`matching_atom`](../TDN/Semantics/PacketPolicy.lean#L167) |
| `def` | [`OutboundGuard`](../TDN/Semantics/PacketPolicy.lean#L173) |
| `def` | [`InboundGuard`](../TDN/Semantics/PacketPolicy.lean#L177) |
| `def` | [`Guarded`](../TDN/Semantics/PacketPolicy.lean#L181) |
| `def` | [`ProtectedForward`](../TDN/Semantics/PacketPolicy.lean#L192) |
| `lemma` | [`guarded_rule_protects`](../TDN/Semantics/PacketPolicy.lean#L196) |
| `theorem` | [`forwarding_policy_protects`](../TDN/Semantics/PacketPolicy.lean#L211) |

Explicit instances:

- [Instance at line 34](../TDN/Semantics/PacketPolicy.lean#L34)
- [Instance at line 54](../TDN/Semantics/PacketPolicy.lean#L54)
- [Instance at line 69](../TDN/Semantics/PacketPolicy.lean#L69)
- [Instance at line 79](../TDN/Semantics/PacketPolicy.lean#L79)
- [Instance at line 94](../TDN/Semantics/PacketPolicy.lean#L94)
- [Instance at line 156](../TDN/Semantics/PacketPolicy.lean#L156)
- [Instance at line 184](../TDN/Semantics/PacketPolicy.lean#L184)

</details>

### HeaderPolicy

Source: [HeaderPolicy.lean](../TDN/Semantics/HeaderPolicy.lean). Namespace: `TDN.PacketPolicy`.

`HeaderPolicy` derives header restrictions from the atoms in every allow rule. [`ProtocolGuard`](../TDN/Semantics/HeaderPolicy.lean#L5) selects an allowed protocol. [`ImmediateHeaderGuard`](../TDN/Semantics/HeaderPolicy.lean#L40) restricts the immediate IPv6 next-header field. [`UnicastGuard`](../TDN/Semantics/HeaderPolicy.lean#L12) either excludes the external interface or excludes a specified destination interval.

[`accepted_protocol`](../TDN/Semantics/HeaderPolicy.lean#L30), [`accepted_immediate_header`](../TDN/Semantics/HeaderPolicy.lean#L47), and [`accepted_header_words`](../TDN/Semantics/HeaderPolicy.lean#L56) prove the corresponding restriction for any accepted packet. [`accepted_external_unicast`](../TDN/Semantics/HeaderPolicy.lean#L64) excludes the supplied destination interval for traffic entering through the external interface. A caller supplies the interval to exclude, such as a multicast range. All four results use default-deny evaluation and checks over the complete allow-rule list.

Direct imports: [PacketPolicy](#packetpolicy).

<details>
<summary>All 8 named declarations in HeaderPolicy</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ProtocolGuard`](../TDN/Semantics/HeaderPolicy.lean#L5) |
| `def` | [`UnicastGuard`](../TDN/Semantics/HeaderPolicy.lean#L12) |
| `abbrev` | [`Accepts`](../TDN/Semantics/HeaderPolicy.lean#L27) |
| `theorem` | [`accepted_protocol`](../TDN/Semantics/HeaderPolicy.lean#L30) |
| `def` | [`ImmediateHeaderGuard`](../TDN/Semantics/HeaderPolicy.lean#L40) |
| `theorem` | [`accepted_immediate_header`](../TDN/Semantics/HeaderPolicy.lean#L47) |
| `theorem` | [`accepted_header_words`](../TDN/Semantics/HeaderPolicy.lean#L56) |
| `theorem` | [`accepted_external_unicast`](../TDN/Semantics/HeaderPolicy.lean#L64) |

Explicit instances:

- [Instance at line 8](../TDN/Semantics/HeaderPolicy.lean#L8)
- [Instance at line 18](../TDN/Semantics/HeaderPolicy.lean#L18)
- [Instance at line 43](../TDN/Semantics/HeaderPolicy.lean#L43)

</details>

## IP packet execution

[Execution](#execution), [ExecutionInvariant](#executioninvariant), [ExecutionChecks](#executionchecks), [FiniteExecution](#finiteexecution), [FiniteRoutedExecution](#finiteroutedexecution), [ExecutionDomains](#executiondomains), [FiniteDomains](#finitedomains), [ExecutionProvenance](#executionprovenance), [AuthenticationSelectors](#authenticationselectors), [ExecutionAuthentication](#executionauthentication), [ExecutionHistory](#executionhistory), [ExecutionEvents](#executionevents), [CiphertextTransit](#ciphertexttransit)

### Execution

Source: [Execution.lean](../TDN/Semantics/Execution.lean). Namespace: `TDN.Execution`.

`Execution` defines the packet-processing steps shared by the IPsec proofs. A [`State`](../TDN/Semantics/Execution.lean#L44) contains an interface, a processing phase, a [`Frame`](../TDN/Semantics/Execution.lean#L18), and the policy identifiers authenticated at ingress. The frame stores the current header, payload identity, origin domain, saved encryption envelopes, and the entry interface. Each [`Envelope`](../TDN/Semantics/Execution.lean#L14) preserves the preceding header so that decryption can restore it.

[`Environment`](../TDN/Semantics/Execution.lean#L110) supplies routes, INPUT/FORWARD/OUTPUT rules and fallback verdicts, IPsec policies, installed security associations, interface names, device ownership, links, switching, local addresses, and Red payload origins. [`Association`](../TDN/Semantics/Execution.lean#L50) represents a policy and its selectors. [`SecurityAssociation`](../TDN/Semantics/Execution.lean#L63) represents installed state. [`StateBindsPolicy`](../TDN/Semantics/Execution.lean#L70) checks the local request identifier, endpoints, and any required SPI. [`selectedAssociations`](../TDN/Semantics/Execution.lean#L82) retains all equally best matching policies.

[`SelectedRoute`](../TDN/Semantics/Execution.lean#L104) chooses among matching routes for the same ingress: lowest table priority first, then longest prefix, then lowest metric. Equal choices remain possible. [`Step`](../TDN/Semantics/Execution.lean#L155) describes receipt, route selection, filtering, encryption, decryption, transmission, switching, local delivery, and dropping. Encryption requires both a selected policy and matching installed state. Plain transmission after filtering requires that no outbound policy was selected.

The preservation theorems retain payload identity, origin domain, and original addresses across every finite execution. The policy-atom results connect a matched outbound-policy condition to a configured operation and exclude the plain-transmission case. [`matched_execution`](../TDN/Semantics/Execution.lean#L320) transfers an execution to another model when the caller proves that each detailed step maps to an allowed step in that model. The route and policy records remain fixed throughout each execution.

Direct imports: `Cslib.Foundations.Semantics.LTS.Simulation`, [PacketPolicy](#packetpolicy), [InternetAddresses](#internetaddresses).

<details>
<summary>All 34 named declarations in Execution</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Seal`](../TDN/Semantics/Execution.lean#L7) |
| `structure` | [`Envelope`](../TDN/Semantics/Execution.lean#L14) |
| `structure` | [`Frame`](../TDN/Semantics/Execution.lean#L18) |
| `def` | [`payloadAddresses`](../TDN/Semantics/Execution.lean#L25) |
| `def` | [`Frame.addresses`](../TDN/Semantics/Execution.lean#L29) |
| `lemma` | [`payload_addresses_ignore_metadata`](../TDN/Semantics/Execution.lean#L32) |
| `inductive` | [`DatapathStage`](../TDN/Semantics/Execution.lean#L39) |
| `structure` | [`State`](../TDN/Semantics/Execution.lean#L44) |
| `structure` | [`Association`](../TDN/Semantics/Execution.lean#L50) |
| `structure` | [`SecurityAssociation`](../TDN/Semantics/Execution.lean#L63) |
| `def` | [`StateBindsPolicy`](../TDN/Semantics/Execution.lean#L70) |
| `def` | [`Association.seal`](../TDN/Semantics/Execution.lean#L75) |
| `def` | [`Association.matches`](../TDN/Semantics/Execution.lean#L78) |
| `def` | [`selectedAssociations`](../TDN/Semantics/Execution.lean#L82) |
| `inductive` | [`Action`](../TDN/Semantics/Execution.lean#L87) |
| `structure` | [`Route`](../TDN/Semantics/Execution.lean#L91) |
| `def` | [`Route.matches`](../TDN/Semantics/Execution.lean#L101) |
| `def` | [`SelectedRoute`](../TDN/Semantics/Execution.lean#L104) |
| `structure` | [`Environment`](../TDN/Semantics/Execution.lean#L110) |
| `def` | [`policyPacket`](../TDN/Semantics/Execution.lean#L130) |
| `def` | [`accepts`](../TDN/Semantics/Execution.lean#L137) |
| `def` | [`encrypt`](../TDN/Semantics/Execution.lean#L141) |
| `inductive` | [`Step`](../TDN/Semantics/Execution.lean#L155) |
| `def` | [`lts`](../TDN/Semantics/Execution.lean#L226) |
| `lemma` | [`step_preserves_payload`](../TDN/Semantics/Execution.lean#L228) |
| `lemma` | [`step_preserves_original_addresses`](../TDN/Semantics/Execution.lean#L233) |
| `theorem` | [`execution_preserves_original_addresses`](../TDN/Semantics/Execution.lean#L254) |
| `theorem` | [`plaintext_delivery_retains_addresses`](../TDN/Semantics/Execution.lean#L262) |
| `theorem` | [`execution_preserves_payload`](../TDN/Semantics/Execution.lean#L271) |
| `lemma` | [`matched_policy_is_configured`](../TDN/Semantics/Execution.lean#L282) |
| `theorem` | [`outbound_policy_atom_selects_operation`](../TDN/Semantics/Execution.lean#L290) |
| `lemma` | [`outbound_policy_atom_excludes_plain`](../TDN/Semantics/Execution.lean#L301) |
| `lemma` | [`simulation_of_step_map`](../TDN/Semantics/Execution.lean#L311) |
| `theorem` | [`matched_execution`](../TDN/Semantics/Execution.lean#L320) |

</details>

### ExecutionInvariant

Source: [ExecutionInvariant.lean](../TDN/Semantics/ExecutionInvariant.lean). Namespace: `TDN.Execution`.

`ExecutionInvariant` assigns an expected list of encryption-layer tags to each interface through `expectedEncapStack : Nat → List Nat`. [`Frame.tags`](../TDN/Semantics/ExecutionInvariant.lean#L5) reads the actual tags in the modeled envelopes. [`encapStackAfterIngress`](../TDN/Semantics/ExecutionInvariant.lean#L8) accounts for a successful inbound decryption by removing the first expected tag. [`StackInvariant`](../TDN/Semantics/ExecutionInvariant.lean#L61) states the appropriate relationship for each processing phase.

[`LocalStackConditions`](../TDN/Semantics/ExecutionInvariant.lean#L32) packages six kinds of premises: routes stay within a device; links preserve the expected stack; switching preserves the processing stack; accepted forwarding rules produce the expected output stack; locally generated output does the same; and routing after encryption preserves the resulting stack. The conditions cover every selected policy, including ties.

[`step_preserves_stack_invariant`](../TDN/Semantics/ExecutionInvariant.lean#L91) checks every constructor of `Execution.Step`. [`execution_preserves_stack_invariant`](../TDN/Semantics/ExecutionInvariant.lean#L143) applies CSLib's general induction result to any finite execution. [`transmitted_stack`](../TDN/Semantics/ExecutionInvariant.lean#L152) concludes that a state ready for transmission has exactly the stack assigned to its interface. A new network supplies a configuration, expected encapsulation stacks, and proofs of the local conditions.

Direct imports: [Execution](#execution).

<details>
<summary>All 12 named declarations in ExecutionInvariant</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Frame.tags`](../TDN/Semantics/ExecutionInvariant.lean#L5) |
| `def` | [`encapStackAfterIngress`](../TDN/Semantics/ExecutionInvariant.lean#L8) |
| `def` | [`LocalAuthentication`](../TDN/Semantics/ExecutionInvariant.lean#L12) |
| `def` | [`ProcessingInvariant`](../TDN/Semantics/ExecutionInvariant.lean#L16) |
| `def` | [`AcceptedHook`](../TDN/Semantics/ExecutionInvariant.lean#L22) |
| `def` | [`RoutedFrame`](../TDN/Semantics/ExecutionInvariant.lean#L28) |
| `structure` | [`LocalStackConditions`](../TDN/Semantics/ExecutionInvariant.lean#L32) |
| `def` | [`StackInvariant`](../TDN/Semantics/ExecutionInvariant.lean#L61) |
| `lemma` | [`accepted_hook_stack_effect`](../TDN/Semantics/ExecutionInvariant.lean#L79) |
| `lemma` | [`step_preserves_stack_invariant`](../TDN/Semantics/ExecutionInvariant.lean#L91) |
| `theorem` | [`execution_preserves_stack_invariant`](../TDN/Semantics/ExecutionInvariant.lean#L143) |
| `theorem` | [`transmitted_stack`](../TDN/Semantics/ExecutionInvariant.lean#L152) |

</details>

### ExecutionChecks

Source: [ExecutionChecks.lean](../TDN/Semantics/ExecutionChecks.lean). Namespace: `TDN.Execution`.

`ExecutionChecks` reduces a packet-dependent stack obligation to checks on rule records. [`IfaceCompatible`](../TDN/Semantics/ExecutionChecks.lean#L6) checks interface constraints. [`ImpossibleAuthentication`](../TDN/Semantics/ExecutionChecks.lean#L12) finds an inbound-policy requirement absent from the known authentication list. [`ExcludesSelector`](../TDN/Semantics/ExecutionChecks.lean#L22) finds address ranges that cannot match a policy. [`HasOutboundGuard`](../TDN/Semantics/ExecutionChecks.lean#L17) identifies a required outbound policy.

[`RuleStackCheck`](../TDN/Semantics/ExecutionChecks.lean#L82) combines those tests: either the rule cannot apply, or plain and encrypted forwarding produce the required stack. [`checked_rule_stack_effect`](../TDN/Semantics/ExecutionChecks.lean#L90) proves that conclusion for a matching rule. [`checked_hook_stack_effect`](../TDN/Semantics/ExecutionChecks.lean#L121) extends the argument to an accepted packet under a default-deny rule list. The checks are sufficient conditions; a failure can require a more precise argument about why a rule is unreachable.

Direct imports: [ExecutionInvariant](#executioninvariant), `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 10 named declarations in ExecutionChecks</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`IfaceCompatible`](../TDN/Semantics/ExecutionChecks.lean#L6) |
| `def` | [`ImpossibleAuthentication`](../TDN/Semantics/ExecutionChecks.lean#L12) |
| `def` | [`HasOutboundGuard`](../TDN/Semantics/ExecutionChecks.lean#L17) |
| `def` | [`ExcludesSelector`](../TDN/Semantics/ExecutionChecks.lean#L22) |
| `lemma` | [`matched_ifaces_compatible`](../TDN/Semantics/ExecutionChecks.lean#L56) |
| `lemma` | [`matching_authentication_possible`](../TDN/Semantics/ExecutionChecks.lean#L63) |
| `lemma` | [`excluded_selector_cannot_match`](../TDN/Semantics/ExecutionChecks.lean#L70) |
| `def` | [`RuleStackCheck`](../TDN/Semantics/ExecutionChecks.lean#L82) |
| `lemma` | [`checked_rule_stack_effect`](../TDN/Semantics/ExecutionChecks.lean#L90) |
| `theorem` | [`checked_hook_stack_effect`](../TDN/Semantics/ExecutionChecks.lean#L121) |

Explicit instances:

- [Instance at line 29](../TDN/Semantics/ExecutionChecks.lean#L29)
- [Instance at line 35](../TDN/Semantics/ExecutionChecks.lean#L35)
- [Instance at line 42](../TDN/Semantics/ExecutionChecks.lean#L42)
- [Instance at line 48](../TDN/Semantics/ExecutionChecks.lean#L48)

</details>

### FiniteExecution

Source: [FiniteExecution.lean](../TDN/Semantics/FiniteExecution.lean). Namespace: `TDN.Execution`.

`FiniteExecution` builds `Execution.Environment` from finite lists of devices, interfaces, routes, links, and switch connections. [`DeviceData`](../TDN/Semantics/FiniteExecution.lean#L5) holds policies, rules, installed state, local addresses, and a recipient domain. [`IfaceData`](../TDN/Semantics/FiniteExecution.lean#L18) holds its owner, interface name, expected stack, and whether it originates payload traffic. [`deviceAt`](../TDN/Semantics/FiniteExecution.lean#L25) and [`ifaceAt`](../TDN/Semantics/FiniteExecution.lean#L28) return default records for indices outside their lists.

[`possibleAuthentications`](../TDN/Semantics/FiniteExecution.lean#L64) enumerates the empty authentication list and the singleton lists allowed by the inbound policies and interface stack. [`FiniteForwardChecks`](../TDN/Semantics/FiniteExecution.lean#L94), [`FiniteOutputChecks`](../TDN/Semantics/FiniteExecution.lean#L135), and [`FiniteOuterRoutes`](../TDN/Semantics/FiniteExecution.lean#L168) state checks over finite records. The soundness theorems prove that those checks imply the corresponding obligations for arbitrary modeled packets. [`local_stack_conditions_of_finite_checks`](../TDN/Semantics/FiniteExecution.lean#L202) assembles the results into [`LocalStackConditions`](../TDN/Semantics/ExecutionInvariant.lean#L32).

The checks include default records because the general configuration accepts any natural-number interface index. Snapshot applications can prove the finite propositions with `by decide`, then reuse the general soundness theorems.

Direct imports: [ExecutionChecks](#executionchecks).

<details>
<summary>All 18 named declarations in FiniteExecution</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`DeviceData`](../TDN/Semantics/FiniteExecution.lean#L5) |
| `structure` | [`IfaceData`](../TDN/Semantics/FiniteExecution.lean#L18) |
| `def` | [`deviceAt`](../TDN/Semantics/FiniteExecution.lean#L25) |
| `def` | [`ifaceAt`](../TDN/Semantics/FiniteExecution.lean#L28) |
| `def` | [`dataPlaneConfigFromRecords`](../TDN/Semantics/FiniteExecution.lean#L31) |
| `def` | [`expectedEncapStackFromRecords`](../TDN/Semantics/FiniteExecution.lean#L52) |
| `lemma` | [`iface_at_member_or_default`](../TDN/Semantics/FiniteExecution.lean#L55) |
| `def` | [`possibleAuthentications`](../TDN/Semantics/FiniteExecution.lean#L64) |
| `lemma` | [`valid_authentication_in_finite_list`](../TDN/Semantics/FiniteExecution.lean#L67) |
| `def` | [`RecordRuleCheck`](../TDN/Semantics/FiniteExecution.lean#L82) |
| `def` | [`FiniteForwardChecks`](../TDN/Semantics/FiniteExecution.lean#L94) |
| `theorem` | [`finite_forward_checks_sound`](../TDN/Semantics/FiniteExecution.lean#L104) |
| `def` | [`FiniteOutputChecks`](../TDN/Semantics/FiniteExecution.lean#L135) |
| `theorem` | [`finite_output_checks_sound`](../TDN/Semantics/FiniteExecution.lean#L143) |
| `def` | [`FiniteOuterRoutes`](../TDN/Semantics/FiniteExecution.lean#L168) |
| `theorem` | [`finite_outer_routes_sound`](../TDN/Semantics/FiniteExecution.lean#L178) |
| `lemma` | [`device_at_member_or_default`](../TDN/Semantics/FiniteExecution.lean#L193) |
| `theorem` | [`local_stack_conditions_of_finite_checks`](../TDN/Semantics/FiniteExecution.lean#L202) |

Explicit instances:

- [Instance at line 91](../TDN/Semantics/FiniteExecution.lean#L91)
- [Instance at line 101](../TDN/Semantics/FiniteExecution.lean#L101)
- [Instance at line 140](../TDN/Semantics/FiniteExecution.lean#L140)
- [Instance at line 175](../TDN/Semantics/FiniteExecution.lean#L175)

</details>

### FiniteRoutedExecution

Source: [FiniteRoutedExecution.lean](../TDN/Semantics/FiniteRoutedExecution.lean). Namespace: `TDN.Execution`.

`FiniteRoutedExecution` uses the selected route to narrow the forwarding-rule check. [`ExcludesRoute`](../TDN/Semantics/FiniteRoutedExecution.lean#L5) detects a rule whose destination range cannot intersect a route. [`withRoute`](../TDN/Semantics/FiniteRoutedExecution.lean#L27) adds the route's destination range to the rule's conditions for the proof.

[`FiniteRoutedForwardChecks`](../TDN/Semantics/FiniteRoutedExecution.lean#L38) examines route, authentication, and allow-rule combinations. Each combination must be impossible or satisfy the stack check with the route restriction included. [`finite_routed_forward_checks_sound`](../TDN/Semantics/FiniteRoutedExecution.lean#L53) proves the packet-level conclusion. [`local_stack_conditions_of_routed_finite_checks`](../TDN/Semantics/FiniteRoutedExecution.lean#L86) combines those checks with link, switch, output, route-ownership, and post-encryption-route checks. The imported operational rules remain unchanged; the added range is supporting information for the proof.

Direct imports: [FiniteExecution](#finiteexecution).

<details>
<summary>All 7 named declarations in FiniteRoutedExecution</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ExcludesRoute`](../TDN/Semantics/FiniteRoutedExecution.lean#L5) |
| `lemma` | [`matching_route_not_excluded`](../TDN/Semantics/FiniteRoutedExecution.lean#L17) |
| `def` | [`withRoute`](../TDN/Semantics/FiniteRoutedExecution.lean#L27) |
| `lemma` | [`matches_with_route`](../TDN/Semantics/FiniteRoutedExecution.lean#L30) |
| `def` | [`FiniteRoutedForwardChecks`](../TDN/Semantics/FiniteRoutedExecution.lean#L38) |
| `theorem` | [`finite_routed_forward_checks_sound`](../TDN/Semantics/FiniteRoutedExecution.lean#L53) |
| `theorem` | [`local_stack_conditions_of_routed_finite_checks`](../TDN/Semantics/FiniteRoutedExecution.lean#L86) |

Explicit instances:

- [Instance at line 10](../TDN/Semantics/FiniteRoutedExecution.lean#L10)
- [Instance at line 48](../TDN/Semantics/FiniteRoutedExecution.lean#L48)

</details>

### ExecutionDomains

Source: [ExecutionDomains.lean](../TDN/Semantics/ExecutionDomains.lean). Namespace: `TDN.Execution`.

`ExecutionDomains` tracks whether processing stays within a chosen set of allowed interfaces. The caller defines that set as `allowed : Nat → Prop`. [`DomainProcessing`](../TDN/Semantics/ExecutionDomains.lean#L5) and [`DomainInvariant`](../TDN/Semantics/ExecutionDomains.lean#L38) combine membership in the set with the encryption-stack conditions.

[`LocalDomainConditions`](../TDN/Semantics/ExecutionDomains.lean#L9) requires links, switches, accepted forwarding, local output, and post-encryption routing to preserve both the expected stack and the allowed set. [`execution_preserves_domain_invariant`](../TDN/Semantics/ExecutionDomains.lean#L125) lifts those local premises to every finite execution. [`delivered_iface_is_allowed`](../TDN/Semantics/ExecutionDomains.lean#L134) applies the invariant to a delivered state.

A caller can instantiate the allowed set for one security domain and exclude recipients in another. The library itself leaves the meaning of a domain and the membership of each interface to the caller.

Direct imports: [ExecutionProvenance](#executionprovenance).

<details>
<summary>All 7 named declarations in ExecutionDomains</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`DomainProcessing`](../TDN/Semantics/ExecutionDomains.lean#L5) |
| `structure` | [`LocalDomainConditions`](../TDN/Semantics/ExecutionDomains.lean#L9) |
| `def` | [`DomainInvariant`](../TDN/Semantics/ExecutionDomains.lean#L38) |
| `lemma` | [`accepted_hook_domain_effect`](../TDN/Semantics/ExecutionDomains.lean#L52) |
| `lemma` | [`step_preserves_domain_invariant`](../TDN/Semantics/ExecutionDomains.lean#L67) |
| `theorem` | [`execution_preserves_domain_invariant`](../TDN/Semantics/ExecutionDomains.lean#L125) |
| `theorem` | [`delivered_iface_is_allowed`](../TDN/Semantics/ExecutionDomains.lean#L134) |

</details>

### FiniteDomains

Source: [FiniteDomains.lean](../TDN/Semantics/FiniteDomains.lean). Namespace: `TDN.Execution`.

`FiniteDomains` supplies finite checks for the allowed-interface argument. [`RecordDomainCheck`](../TDN/Semantics/FiniteDomains.lean#L5) extends the per-rule stack check with permission for the output interface. The forwarding, local-output, and outer-route predicates check the finite device and interface records. [`local_domain_conditions_of_finite_checks`](../TDN/Semantics/FiniteDomains.lean#L112) turns the results into [`LocalDomainConditions`](../TDN/Semantics/ExecutionDomains.lean#L9) for all modeled packets.

[`withEncapStackAnnotations`](../TDN/Semantics/FiniteDomains.lean#L159) changes the proof's expected-stack annotations. [`data_plane_ignores_encap_stack_annotations`](../TDN/Semantics/FiniteDomains.lean#L170) proves that changing only those annotations leaves `dataPlaneConfigFromRecords` unchanged. A network can therefore support several domain-specific stack annotations while retaining the same operational configuration. Every chosen stack annotation still needs its own checked local premises.

Direct imports: [ExecutionDomains](#executiondomains).

<details>
<summary>All 11 named declarations in FiniteDomains</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`RecordDomainCheck`](../TDN/Semantics/FiniteDomains.lean#L5) |
| `lemma` | [`domain_check_implies_stack_check`](../TDN/Semantics/FiniteDomains.lean#L19) |
| `lemma` | [`matched_domain_check_allows_output`](../TDN/Semantics/FiniteDomains.lean#L28) |
| `def` | [`FiniteDomainForwardChecks`](../TDN/Semantics/FiniteDomains.lean#L40) |
| `theorem` | [`finite_domain_forward_checks_sound`](../TDN/Semantics/FiniteDomains.lean#L53) |
| `def` | [`FiniteDomainOutputChecks`](../TDN/Semantics/FiniteDomains.lean#L86) |
| `def` | [`FiniteDomainOuterRoutes`](../TDN/Semantics/FiniteDomains.lean#L98) |
| `theorem` | [`local_domain_conditions_of_finite_checks`](../TDN/Semantics/FiniteDomains.lean#L112) |
| `def` | [`withEncapStackAnnotations`](../TDN/Semantics/FiniteDomains.lean#L159) |
| `lemma` | [`encap_stack_update_preserves_data_plane_fields`](../TDN/Semantics/FiniteDomains.lean#L162) |
| `theorem` | [`data_plane_ignores_encap_stack_annotations`](../TDN/Semantics/FiniteDomains.lean#L170) |

Explicit instances:

- [Instance at line 15](../TDN/Semantics/FiniteDomains.lean#L15)
- [Instance at line 48](../TDN/Semantics/FiniteDomains.lean#L48)
- [Instance at line 93](../TDN/Semantics/FiniteDomains.lean#L93)
- [Instance at line 107](../TDN/Semantics/FiniteDomains.lean#L107)

</details>

### ExecutionProvenance

Source: [ExecutionProvenance.lean](../TDN/Semantics/ExecutionProvenance.lean). Namespace: `TDN.Execution`.

`ExecutionProvenance` connects each modeled encryption envelope to a configured outbound policy and installed state. [`ProducedSeal`](../TDN/Semantics/ExecutionProvenance.lean#L5) expresses that connection, and [`ProducedEnvelopes`](../TDN/Semantics/ExecutionProvenance.lean#L10) requires it for every envelope. [`execution_envelopes_have_configured_provenance`](../TDN/Semantics/ExecutionProvenance.lean#L42) proves the property for executions that start without envelopes.

[`SameWireAssociation`](../TDN/Semantics/ExecutionProvenance.lean#L51) compares SPI and endpoints. [`PeerTagAgreement`](../TDN/Semantics/ExecutionProvenance.lean#L54) requires matching sender and receiver wire records to use the same proof tag. [`wire_match_determines_annotated_seal`](../TDN/Semantics/ExecutionProvenance.lean#L65) uses that agreement to recover the complete annotated seal from a wire match. [`FinitePeerTagAgreement`](../TDN/Semantics/ExecutionProvenance.lean#L82) and its soundness theorem make the agreement check finite. The caller must retain every relevant peer record and justify the interpretation of its installed state.

Direct imports: [FiniteExecution](#finiteexecution).

<details>
<summary>All 10 named declarations in ExecutionProvenance</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ProducedSeal`](../TDN/Semantics/ExecutionProvenance.lean#L5) |
| `def` | [`ProducedEnvelopes`](../TDN/Semantics/ExecutionProvenance.lean#L10) |
| `lemma` | [`step_preserves_envelope_provenance`](../TDN/Semantics/ExecutionProvenance.lean#L13) |
| `theorem` | [`execution_envelopes_have_configured_provenance`](../TDN/Semantics/ExecutionProvenance.lean#L42) |
| `def` | [`SameWireAssociation`](../TDN/Semantics/ExecutionProvenance.lean#L51) |
| `def` | [`PeerTagAgreement`](../TDN/Semantics/ExecutionProvenance.lean#L54) |
| `def` | [`WireMatchesSeal`](../TDN/Semantics/ExecutionProvenance.lean#L62) |
| `theorem` | [`wire_match_determines_annotated_seal`](../TDN/Semantics/ExecutionProvenance.lean#L65) |
| `def` | [`FinitePeerTagAgreement`](../TDN/Semantics/ExecutionProvenance.lean#L82) |
| `theorem` | [`finite_peer_tag_agreement_sound`](../TDN/Semantics/ExecutionProvenance.lean#L93) |

Explicit instances:

- [Instance at line 89](../TDN/Semantics/ExecutionProvenance.lean#L89)

</details>

### AuthenticationSelectors

Source: [AuthenticationSelectors.lean](../TDN/Semantics/AuthenticationSelectors.lean). Namespace: `TDN.Execution`.

`AuthenticationSelectors` records why an inbound policy identifier appears in a state's authentication list. [`AuthenticationMatches`](../TDN/Semantics/AuthenticationSelectors.lean#L5) requires a matching configured inbound policy whose address selectors accept the current packet. [`ProcessingAuthenticationMatches`](../TDN/Semantics/AuthenticationSelectors.lean#L9) applies the condition in the phases that use that metadata.

The step lemma and [`execution_preserves_authentication_selectors`](../TDN/Semantics/AuthenticationSelectors.lean#L31) prove that the relationship survives every finite execution from an initially valid state. The result lets later response checks use an authenticated packet's address range when reasoning about a reply to its source.

Direct imports: [ExecutionInvariant](#executioninvariant).

<details>
<summary>All 4 named declarations in AuthenticationSelectors</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`AuthenticationMatches`](../TDN/Semantics/AuthenticationSelectors.lean#L5) |
| `def` | [`ProcessingAuthenticationMatches`](../TDN/Semantics/AuthenticationSelectors.lean#L9) |
| `lemma` | [`step_preserves_authentication_selectors`](../TDN/Semantics/AuthenticationSelectors.lean#L14) |
| `theorem` | [`execution_preserves_authentication_selectors`](../TDN/Semantics/AuthenticationSelectors.lean#L31) |

</details>

### ExecutionAuthentication

Source: [ExecutionAuthentication.lean](../TDN/Semantics/ExecutionAuthentication.lean). Namespace: `TDN.Execution`.

`ExecutionAuthentication` proves that crossing a component's protected boundary requires a decryption step inside that component. [`UndecryptedRegion`](../TDN/Semantics/ExecutionAuthentication.lean#L10) describes states that remain on the protected side while their authentication list is empty.

[`undecrypted_step_retains_region`](../TDN/Semantics/ExecutionAuthentication.lean#L25) proves that every non-decryption step preserves the condition under [`LocalStackConditions`](../TDN/Semantics/ExecutionInvariant.lean#L32). [`inbound_crossing_requires_local_decryption`](../TDN/Semantics/ExecutionAuthentication.lean#L95) then identifies an actual decryption event in a finite execution confined to one component. The execution must begin received and unauthenticated at an interface whose expected stack includes the tag, and finish ready at an interface whose expected stack excludes it. The component's inbound policies must all use the specified tag. The event also retains the original payload identity.

Direct imports: [ExecutionEvents](#executionevents), [RestrictedExecution](#restrictedexecution).

<details>
<summary>All 4 named declarations in ExecutionAuthentication</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`IngressMetadata`](../TDN/Semantics/ExecutionAuthentication.lean#L6) |
| `def` | [`UndecryptedRegion`](../TDN/Semantics/ExecutionAuthentication.lean#L10) |
| `lemma` | [`undecrypted_step_retains_region`](../TDN/Semantics/ExecutionAuthentication.lean#L25) |
| `theorem` | [`inbound_crossing_requires_local_decryption`](../TDN/Semantics/ExecutionAuthentication.lean#L95) |

</details>

### ExecutionHistory

Source: [ExecutionHistory.lean](../TDN/Semantics/ExecutionHistory.lean). Namespace: `TDN.Execution`.

`ExecutionHistory` counts encryption and decryption operations across a finite execution. [`encryptionCredit`](../TDN/Semantics/ExecutionHistory.lean#L6) assigns one to encryption; [`decryptionDebit`](../TDN/Semantics/ExecutionHistory.lean#L7) assigns one to decryption. The step lemma relates those counts to the change in envelope depth.

[`execution_envelope_balance`](../TDN/Semantics/ExecutionHistory.lean#L15) proves that final depth plus decryptions equals initial depth plus encryptions. [`stack_growth_requires_encryptions`](../TDN/Semantics/ExecutionHistory.lean#L22) and [`stack_removal_requires_decryptions`](../TDN/Semantics/ExecutionHistory.lean#L29) derive lower bounds on the number of operations. Those counts follow directly from `Execution.Step`; identifying particular Inner and Outer operations in order uses `ExecutionEvents`.

Direct imports: [Execution](#execution), [TraceAccounting](#traceaccounting).

<details>
<summary>All 6 named declarations in ExecutionHistory</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`encryptionCredit`](../TDN/Semantics/ExecutionHistory.lean#L6) |
| `def` | [`decryptionDebit`](../TDN/Semantics/ExecutionHistory.lean#L7) |
| `lemma` | [`step_envelope_balance`](../TDN/Semantics/ExecutionHistory.lean#L9) |
| `theorem` | [`execution_envelope_balance`](../TDN/Semantics/ExecutionHistory.lean#L15) |
| `theorem` | [`stack_growth_requires_encryptions`](../TDN/Semantics/ExecutionHistory.lean#L22) |
| `theorem` | [`stack_removal_requires_decryptions`](../TDN/Semantics/ExecutionHistory.lean#L29) |

</details>

### ExecutionEvents

Source: [ExecutionEvents.lean](../TDN/Semantics/ExecutionEvents.lean). Namespace: `TDN.Execution`.

`ExecutionEvents` finds specific encryption or decryption steps within an execution. The one-step lemmas show that adding a previously absent tag requires encryption and removing a present tag requires decryption. The boundary theorems locate those events and preserve the payload identity.

[`OrderedEncryptions`](../TDN/Semantics/ExecutionEvents.lean#L95) states that an Inner encryption event occurs before a particular Outer encryption event. [`nested_stack_requires_ordered_encryptions`](../TDN/Semantics/ExecutionEvents.lean#L107) proves that order when the execution starts with an empty stack, ends with the Outer tag present, satisfies [`LocalStackConditions`](../TDN/Semantics/ExecutionInvariant.lean#L32), and every interface headed by the Outer tag expects exactly `[outerTag, innerTag]`. The theorem supplies event witnesses within the modeled execution.

Direct imports: [ExecutionInvariant](#executioninvariant), [TraceEvents](#traceevents).

<details>
<summary>All 8 named declarations in ExecutionEvents</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`missing_tag_added_only_by_encryption`](../TDN/Semantics/ExecutionEvents.lean#L6) |
| `lemma` | [`present_tag_removed_only_by_decryption`](../TDN/Semantics/ExecutionEvents.lean#L22) |
| `lemma` | [`execution_payload_identity`](../TDN/Semantics/ExecutionEvents.lean#L37) |
| `theorem` | [`boundary_layer_removal_has_decryption`](../TDN/Semantics/ExecutionEvents.lean#L45) |
| `theorem` | [`boundary_layer_addition_has_encryption`](../TDN/Semantics/ExecutionEvents.lean#L59) |
| `lemma` | [`outer_encryption_has_inner_stack`](../TDN/Semantics/ExecutionEvents.lean#L74) |
| `def` | [`OrderedEncryptions`](../TDN/Semantics/ExecutionEvents.lean#L95) |
| `theorem` | [`nested_stack_requires_ordered_encryptions`](../TDN/Semantics/ExecutionEvents.lean#L107) |

</details>

### CiphertextTransit

Source: [CiphertextTransit.lean](../TDN/Semantics/CiphertextTransit.lean). Namespace: `TDN.Execution`.

`CiphertextTransit` isolates execution steps that do not encrypt, decrypt, or deliver payloads. [`withHiddenContent`](../TDN/Semantics/CiphertextTransit.lean#L15) replaces the payload identifier, origin domain, and saved envelopes while preserving the visible packet and processing state.

[`transit_step_ignores_hidden_content`](../TDN/Semantics/CiphertextTransit.lean#L22) and [`transit_path_ignores_hidden_content`](../TDN/Semantics/CiphertextTransit.lean#L45) prove that the same transit steps remain possible after the replacement. [`recovered_content_follows_checked_transit`](../TDN/Semantics/CiphertextTransit.lean#L56) combines that fact with the allowed-domain invariant. Reuse requires the selected steps to inspect only the fields retained by the replacement. The theorem describes the modeled processing behavior; a cryptographic secrecy claim needs an attacker and cryptographic security assumptions.

Direct imports: [ExecutionDomains](#executiondomains).

<details>
<summary>All 6 named declarations in CiphertextTransit</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`TransitAction`](../TDN/Semantics/CiphertextTransit.lean#L5) |
| `def` | [`transit`](../TDN/Semantics/CiphertextTransit.lean#L12) |
| `def` | [`withHiddenContent`](../TDN/Semantics/CiphertextTransit.lean#L15) |
| `lemma` | [`transit_step_ignores_hidden_content`](../TDN/Semantics/CiphertextTransit.lean#L22) |
| `theorem` | [`transit_path_ignores_hidden_content`](../TDN/Semantics/CiphertextTransit.lean#L45) |
| `theorem` | [`recovered_content_follows_checked_transit`](../TDN/Semantics/CiphertextTransit.lean#L56) |

Explicit instances:

- [Instance at line 8](../TDN/Semantics/CiphertextTransit.lean#L8)

</details>

## MACsec and mixed-protocol execution

[LinkProtection](#linkprotection), [LayeredFrame](#layeredframe), [MultiProtocolExecution](#multiprotocolexecution), [MultiProtocolInvariant](#multiprotocolinvariant), [FiniteMultiProtocol](#finitemultiprotocol), [MultiProtocolProvenance](#multiprotocolprovenance), [MultiProtocolEvents](#multiprotocolevents), [MultiProtocolAuthentication](#multiprotocolauthentication), [FiniteMultiProtocolAuthentication](#finitemultiprotocolauthentication)

### LinkProtection

Source: [LinkProtection.lean](../TDN/Semantics/LinkProtection.lean). Namespace: `TDN.LinkProtection`.

`LinkProtection` models the effect of MACsec protection settings on one transmission. [`Config`](../TDN/Semantics/LinkProtection.lean#L3) records whether the controlled port is enabled, whether frames are protected and encrypted, and the confidentiality offset. [`transmit`](../TDN/Semantics/LinkProtection.lean#L16) returns no frame, a plain frame, an integrity-only frame, or an encrypted frame according to the settings and active association.

[`every_emitted_frame_is_encrypted`](../TDN/Semantics/LinkProtection.lean#L30) proves full encryption when protection and encryption are enabled and the offset is zero. [`absent_sa_blocks_data`](../TDN/Semantics/LinkProtection.lean#L40) proves that protected traffic cannot transmit without an association. [`enabled_sa_emits_encryption`](../TDN/Semantics/LinkProtection.lean#L45) supplies the positive transmission result. The wrapper records the operation symbolically; the function does not compute ciphertext bytes.

Direct imports: .

<details>
<summary>All 7 named declarations in LinkProtection</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Config`](../TDN/Semantics/LinkProtection.lean#L3) |
| `inductive` | [`WireFrame`](../TDN/Semantics/LinkProtection.lean#L10) |
| `def` | [`transmit`](../TDN/Semantics/LinkProtection.lean#L16) |
| `def` | [`FullyEncrypted`](../TDN/Semantics/LinkProtection.lean#L26) |
| `theorem` | [`every_emitted_frame_is_encrypted`](../TDN/Semantics/LinkProtection.lean#L30) |
| `theorem` | [`absent_sa_blocks_data`](../TDN/Semantics/LinkProtection.lean#L40) |
| `theorem` | [`enabled_sa_emits_encryption`](../TDN/Semantics/LinkProtection.lean#L45) |

</details>

### LayeredFrame

Source: [LayeredFrame.lean](../TDN/Semantics/LayeredFrame.lean). Namespace: `TDN.LayeredFrame`.

`LayeredFrame` represents nested IPsec, MACsec, and carrier encapsulation. [`Body`](../TDN/Semantics/LayeredFrame.lean#L38) can contain an IP datagram, an Ethernet frame, or another body wrapped in one of those three mechanisms. `visibleHeader` returns the currently routable IP header. `protectionLayers` collects only the IPsec and MACsec tags; a carrier wrapper preserves that list.

[`MACsecAssociation`](../TDN/Semantics/LayeredFrame.lean#L6) records a tag, SCI, association number, and a local key-generation identifier. [`SameMACWireIdentity`](../TDN/Semantics/LayeredFrame.lean#L14) compares SCI and association number. [`Carrier`](../TDN/Semantics/LayeredFrame.lean#L21) records addresses, ports, and the peer session. [`unwrapCarrier`](../TDN/Semantics/LayeredFrame.lean#L97) checks the receiving address, remote address, ports, and local session before removing the wrapper.

The lemmas establish the expected header visibility and layer order. [`successful_carrier_unwrap_preserves_layers`](../TDN/Semantics/LayeredFrame.lean#L108) proves that successful removal of a carrier changes no encryption layers. Cryptographic operations remain represented by typed wrappers.

Direct imports: [Execution](#execution), [LinkProtection](#linkprotection).

<details>
<summary>All 27 named declarations in LayeredFrame</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`MACsecAssociation`](../TDN/Semantics/LayeredFrame.lean#L6) |
| `def` | [`SameMACWireIdentity`](../TDN/Semantics/LayeredFrame.lean#L14) |
| `structure` | [`Carrier`](../TDN/Semantics/LayeredFrame.lean#L21) |
| `structure` | [`EthernetHeader`](../TDN/Semantics/LayeredFrame.lean#L31) |
| `inductive` | [`Body`](../TDN/Semantics/LayeredFrame.lean#L38) |
| `structure` | [`Frame`](../TDN/Semantics/LayeredFrame.lean#L45) |
| `def` | [`outerHeader`](../TDN/Semantics/LayeredFrame.lean#L52) |
| `def` | [`Body.visibleHeader`](../TDN/Semantics/LayeredFrame.lean#L59) |
| `def` | [`Body.protectionLayers`](../TDN/Semantics/LayeredFrame.lean#L67) |
| `def` | [`Body.originalHeader`](../TDN/Semantics/LayeredFrame.lean#L73) |
| `def` | [`Body.originalEthernet`](../TDN/Semantics/LayeredFrame.lean#L78) |
| `def` | [`Body.isEthernetCiphertext`](../TDN/Semantics/LayeredFrame.lean#L83) |
| `lemma` | [`macsec_has_no_routable_inner_header`](../TDN/Semantics/LayeredFrame.lean#L87) |
| `lemma` | [`carrier_preserves_protection_layers`](../TDN/Semantics/LayeredFrame.lean#L90) |
| `lemma` | [`nested_outer_inner_order`](../TDN/Semantics/LayeredFrame.lean#L93) |
| `def` | [`unwrapCarrier`](../TDN/Semantics/LayeredFrame.lean#L97) |
| `theorem` | [`successful_carrier_unwrap_preserves_layers`](../TDN/Semantics/LayeredFrame.lean#L108) |
| `def` | [`Frame.visibleHeader`](../TDN/Semantics/LayeredFrame.lean#L123) |
| `def` | [`Frame.pushHeader`](../TDN/Semantics/LayeredFrame.lean#L128) |
| `def` | [`Frame.popHeader`](../TDN/Semantics/LayeredFrame.lean#L133) |
| `def` | [`Frame.forwarded`](../TDN/Semantics/LayeredFrame.lean#L138) |
| `lemma` | [`Frame.forwarded_payload`](../TDN/Semantics/LayeredFrame.lean#L147) |
| `lemma` | [`Frame.forwarded_origin`](../TDN/Semantics/LayeredFrame.lean#L151) |
| `def` | [`HeaderIdentity`](../TDN/Semantics/LayeredFrame.lean#L160) |
| `def` | [`Body.HeadersCoherent`](../TDN/Semantics/LayeredFrame.lean#L163) |
| `def` | [`Frame.HeadersCoherent`](../TDN/Semantics/LayeredFrame.lean#L182) |
| `lemma` | [`Frame.forwarded_body`](../TDN/Semantics/LayeredFrame.lean#L189) |

Explicit instances:

- [Instance at line 17](../TDN/Semantics/LayeredFrame.lean#L17)

</details>

### MultiProtocolExecution

Source: [MultiProtocolExecution.lean](../TDN/Semantics/MultiProtocolExecution.lean). Namespace: `TDN.MultiProtocolExecution`.

`MultiProtocolExecution` combines IP processing with MACsec interfaces, carrier endpoints, bridges, and physical links. `Config.ip` reuses `Execution.Environment`. [`MACIface`](../TDN/Semantics/MultiProtocolExecution.lean#L7) links logical and physical interfaces to transmit/receive associations and protection settings. [`CarrierIface`](../TDN/Semantics/MultiProtocolExecution.lean#L16) links a virtual interface to a routing interface and session information.

[`Step`](../TDN/Semantics/MultiProtocolExecution.lean#L101) models IPsec encryption/decryption, MACsec encryption/decryption, carrier encapsulation/decapsulation, IP filtering and routing, bridging, delivery, and dropping. It also includes unprotected MACsec transmission and unchecked reception when their settings permit those behaviors. [`fullMACsecTransmit`](../TDN/Semantics/MultiProtocolExecution.lean#L96) identifies successful full-frame encryption. [`all_executions_preserve_payload`](../TDN/Semantics/MultiProtocolExecution.lean#L217) preserves payload identity and origin domain across all modeled steps.

Applications supply the device records and topology. The stronger security results require the settings and local conditions checked in the next modules.

Direct imports: [LayeredFrame](#layeredframe).

<details>
<summary>All 30 named declarations in MultiProtocolExecution</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`MACIface`](../TDN/Semantics/MultiProtocolExecution.lean#L7) |
| `structure` | [`CarrierIface`](../TDN/Semantics/MultiProtocolExecution.lean#L16) |
| `structure` | [`HeaderProcessing`](../TDN/Semantics/MultiProtocolExecution.lean#L23) |
| `structure` | [`Config`](../TDN/Semantics/MultiProtocolExecution.lean#L27) |
| `def` | [`Config.forwardedFrame`](../TDN/Semantics/MultiProtocolExecution.lean#L39) |
| `def` | [`Config.ipsecFrame`](../TDN/Semantics/MultiProtocolExecution.lean#L44) |
| `def` | [`Config.macsecFrame`](../TDN/Semantics/MultiProtocolExecution.lean#L53) |
| `def` | [`Config.carrierFrame`](../TDN/Semantics/MultiProtocolExecution.lean#L59) |
| `def` | [`Config.restoredFrame`](../TDN/Semantics/MultiProtocolExecution.lean#L68) |
| `def` | [`Config.visibleHeader`](../TDN/Semantics/MultiProtocolExecution.lean#L73) |
| `structure` | [`State`](../TDN/Semantics/MultiProtocolExecution.lean#L78) |
| `inductive` | [`Action`](../TDN/Semantics/MultiProtocolExecution.lean#L87) |
| `def` | [`policyHeader`](../TDN/Semantics/MultiProtocolExecution.lean#L93) |
| `def` | [`fullMACsecTransmit`](../TDN/Semantics/MultiProtocolExecution.lean#L96) |
| `inductive` | [`Step`](../TDN/Semantics/MultiProtocolExecution.lean#L101) |
| `def` | [`lts`](../TDN/Semantics/MultiProtocolExecution.lean#L207) |
| `lemma` | [`step_preserves_payload`](../TDN/Semantics/MultiProtocolExecution.lean#L209) |
| `theorem` | [`all_executions_preserve_payload`](../TDN/Semantics/MultiProtocolExecution.lean#L217) |
| `def` | [`Config.LinkPath`](../TDN/Semantics/MultiProtocolExecution.lean#L235) |
| `def` | [`Config.LinkAdmitted`](../TDN/Semantics/MultiProtocolExecution.lean#L240) |
| `def` | [`Config.LinkStepAdmitted`](../TDN/Semantics/MultiProtocolExecution.lean#L247) |
| `def` | [`Config.ForwardableHeader`](../TDN/Semantics/MultiProtocolExecution.lean#L265) |
| `def` | [`Config.HeaderStepAdmitted`](../TDN/Semantics/MultiProtocolExecution.lean#L268) |
| `def` | [`Config.HeaderGenerationKnown`](../TDN/Semantics/MultiProtocolExecution.lean#L272) |
| `def` | [`Config.LinkEncodingComplete`](../TDN/Semantics/MultiProtocolExecution.lean#L278) |
| `lemma` | [`Config.forwardedFrame_body`](../TDN/Semantics/MultiProtocolExecution.lean#L288) |
| `lemma` | [`Config.ipsecFrame_body`](../TDN/Semantics/MultiProtocolExecution.lean#L292) |
| `lemma` | [`Config.macsecFrame_body`](../TDN/Semantics/MultiProtocolExecution.lean#L298) |
| `lemma` | [`Config.carrierFrame_body`](../TDN/Semantics/MultiProtocolExecution.lean#L304) |
| `lemma` | [`Config.restoredFrame_body`](../TDN/Semantics/MultiProtocolExecution.lean#L310) |

</details>

### MultiProtocolInvariant

Source: [MultiProtocolInvariant.lean](../TDN/Semantics/MultiProtocolInvariant.lean). Namespace: `TDN.MultiProtocolExecution`.

`MultiProtocolInvariant` extends expected-stack reasoning to nested IPsec, MACsec, and carrier bodies. [`CarrierBodies`](../TDN/Semantics/MultiProtocolInvariant.lean#L31) records how a body relates to configured transmitters and carrier endpoints. [`CarrierPeers`](../TDN/Semantics/MultiProtocolInvariant.lean#L40) checks reciprocal addresses, ports, and directional session matching. [`StackInvariant`](../TDN/Semantics/MultiProtocolInvariant.lean#L78) combines those relationships with the conditions for each processing phase.

[`LocalConditions`](../TDN/Semantics/MultiProtocolInvariant.lean#L49) includes the IP stack conditions, stack-preserving links and bridges, MACsec transmit/receive tag placement, peer-tag agreement, protection/encryption enabled with zero confidentiality offset, strict receive validation, and carrier route/peer conditions. [`all_executions_preserve_stack`](../TDN/Semantics/MultiProtocolInvariant.lean#L343) proves preservation across any finite mixed-protocol execution once those premises and the initial invariant hold.

The constructor-by-constructor proof excludes insecure MACsec steps through the required settings. A new protocol wrapper needs its own behavior and preservation argument.

Direct imports: [MultiProtocolExecution](#multiprotocolexecution), [ExecutionInvariant](#executioninvariant).

<details>
<summary>All 16 named declarations in MultiProtocolInvariant</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Processing`](../TDN/Semantics/MultiProtocolInvariant.lean#L7) |
| `def` | [`Routed`](../TDN/Semantics/MultiProtocolInvariant.lean#L12) |
| `def` | [`carrierHeader`](../TDN/Semantics/MultiProtocolInvariant.lean#L16) |
| `def` | [`LocalHeader`](../TDN/Semantics/MultiProtocolInvariant.lean#L20) |
| `def` | [`AcceptedHook`](../TDN/Semantics/MultiProtocolInvariant.lean#L24) |
| `def` | [`CarrierBodies`](../TDN/Semantics/MultiProtocolInvariant.lean#L31) |
| `def` | [`CarrierPeers`](../TDN/Semantics/MultiProtocolInvariant.lean#L40) |
| `structure` | [`LocalConditions`](../TDN/Semantics/MultiProtocolInvariant.lean#L49) |
| `def` | [`StackInvariant`](../TDN/Semantics/MultiProtocolInvariant.lean#L78) |
| `def` | [`ipFrame`](../TDN/Semantics/MultiProtocolInvariant.lean#L98) |
| `lemma` | [`selected_route_metadata`](../TDN/Semantics/MultiProtocolInvariant.lean#L103) |
| `lemma` | [`hook_stack_effect_from_metadata`](../TDN/Semantics/MultiProtocolInvariant.lean#L108) |
| `lemma` | [`hook_stack_effect`](../TDN/Semantics/MultiProtocolInvariant.lean#L140) |
| `lemma` | [`unwrap_carrier_preserves_record`](../TDN/Semantics/MultiProtocolInvariant.lean#L150) |
| `lemma` | [`step_preserves_stack`](../TDN/Semantics/MultiProtocolInvariant.lean#L168) |
| `theorem` | [`all_executions_preserve_stack`](../TDN/Semantics/MultiProtocolInvariant.lean#L343) |

</details>

### FiniteMultiProtocol

Source: [FiniteMultiProtocol.lean](../TDN/Semantics/FiniteMultiProtocol.lean). Namespace: `TDN.MultiProtocolExecution`.

`FiniteMultiProtocol` constructs the mixed-protocol configuration from finite device, interface, route, link, bridge, MACsec, and carrier lists. [`MACTransmitCheck`](../TDN/Semantics/FiniteMultiProtocol.lean#L14) checks tag placement for a configured transmit association. [`CarrierRouteChecks`](../TDN/Semantics/FiniteMultiProtocol.lean#L21) checks the stack effect of selected IPsec policies on each carrier header's route.

[`local_conditions_from_finite_checks`](../TDN/Semantics/FiniteMultiProtocol.lean#L49) assembles those checks, MACsec receive/tag/security checks, carrier-peer checks, and existing IP conditions into `MultiProtocolExecution.LocalConditions`. The resulting general execution theorem can then be applied without changing its proof. Missing transmit associations can satisfy the placement check, so a separate delivery witness is needed when the requirement includes successful communication.

Direct imports: [MultiProtocolInvariant](#multiprotocolinvariant), [FiniteRoutedExecution](#finiteroutedexecution).

<details>
<summary>All 4 named declarations in FiniteMultiProtocol</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`dataPlaneConfigFromRecords`](../TDN/Semantics/FiniteMultiProtocol.lean#L7) |
| `def` | [`MACTransmitCheck`](../TDN/Semantics/FiniteMultiProtocol.lean#L14) |
| `def` | [`CarrierRouteChecks`](../TDN/Semantics/FiniteMultiProtocol.lean#L21) |
| `theorem` | [`local_conditions_from_finite_checks`](../TDN/Semantics/FiniteMultiProtocol.lean#L49) |

Explicit instances:

- [Instance at line 34](../TDN/Semantics/FiniteMultiProtocol.lean#L34)
- [Instance at line 39](../TDN/Semantics/FiniteMultiProtocol.lean#L39)
- [Instance at line 45](../TDN/Semantics/FiniteMultiProtocol.lean#L45)

</details>

### MultiProtocolProvenance

Source: [MultiProtocolProvenance.lean](../TDN/Semantics/MultiProtocolProvenance.lean). Namespace: `TDN.MultiProtocolExecution`.

`MultiProtocolProvenance` tracks configured IPsec origins inside bodies that may also contain MACsec or carrier wrappers. [`ProducedIPBodies`](../TDN/Semantics/MultiProtocolProvenance.lean#L7) recursively requires every IPsec seal to come from a configured policy and installed state.

[`all_executions_preserve_ip_provenance`](../TDN/Semantics/MultiProtocolProvenance.lean#L41) preserves that property. [`wire_matching_ipsec_decryption_is_admitted`](../TDN/Semantics/MultiProtocolProvenance.lean#L48) proves that a receiving IPsec decryption step is available when the wire identity matches, sender/receiver tag agreement holds, the inbound policy and state are installed and bound, and the recovered header satisfies the selectors. The theorem concerns the IPsec portion of the mixed model; MACsec settings and tag relationships have their own premises.

Direct imports: [MultiProtocolExecution](#multiprotocolexecution), [ExecutionProvenance](#executionprovenance).

<details>
<summary>All 5 named declarations in MultiProtocolProvenance</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ProducedIPBodies`](../TDN/Semantics/MultiProtocolProvenance.lean#L7) |
| `lemma` | [`unwrap_preserves_ip_provenance`](../TDN/Semantics/MultiProtocolProvenance.lean#L12) |
| `lemma` | [`step_preserves_ip_provenance`](../TDN/Semantics/MultiProtocolProvenance.lean#L24) |
| `theorem` | [`all_executions_preserve_ip_provenance`](../TDN/Semantics/MultiProtocolProvenance.lean#L41) |
| `theorem` | [`wire_matching_ipsec_decryption_is_admitted`](../TDN/Semantics/MultiProtocolProvenance.lean#L48) |

</details>

### MultiProtocolEvents

Source: [MultiProtocolEvents.lean](../TDN/Semantics/MultiProtocolEvents.lean). Namespace: `TDN.MultiProtocolExecution`.

`MultiProtocolEvents` proves operation-order facts across IPsec and MACsec. [`IsEncryption`](../TDN/Semantics/MultiProtocolEvents.lean#L35) and [`IsDecryption`](../TDN/Semantics/MultiProtocolEvents.lean#L38) each include both protocols. The step lemmas classify layer changes, and the boundary theorems locate the operation that added or removed a tag.

[`nested_stack_requires_ordered_encryptions`](../TDN/Semantics/MultiProtocolEvents.lean#L136) establishes Inner-before-Outer encryption under the mixed-protocol local conditions and the two-layer placement condition. The original-Ethernet lemmas and theorem also preserve the innermost Ethernet header through all modeled steps. Carrier encapsulation preserves the encryption-layer list, so a carrier operation cannot supply an encryption event.

Direct imports: [MultiProtocolInvariant](#multiprotocolinvariant), [TraceEvents](#traceevents).

<details>
<summary>All 13 named declarations in MultiProtocolEvents</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`unwrap_preserves_original_ethernet`](../TDN/Semantics/MultiProtocolEvents.lean#L7) |
| `lemma` | [`step_preserves_original_ethernet`](../TDN/Semantics/MultiProtocolEvents.lean#L18) |
| `theorem` | [`all_executions_preserve_original_ethernet`](../TDN/Semantics/MultiProtocolEvents.lean#L26) |
| `def` | [`IsEncryption`](../TDN/Semantics/MultiProtocolEvents.lean#L35) |
| `def` | [`IsDecryption`](../TDN/Semantics/MultiProtocolEvents.lean#L38) |
| `lemma` | [`step_layer_effect`](../TDN/Semantics/MultiProtocolEvents.lean#L41) |
| `lemma` | [`missing_layer_requires_encryption`](../TDN/Semantics/MultiProtocolEvents.lean#L54) |
| `lemma` | [`removed_layer_requires_decryption`](../TDN/Semantics/MultiProtocolEvents.lean#L68) |
| `theorem` | [`boundary_addition_has_actual_encryption`](../TDN/Semantics/MultiProtocolEvents.lean#L82) |
| `theorem` | [`boundary_removal_has_actual_decryption`](../TDN/Semantics/MultiProtocolEvents.lean#L97) |
| `lemma` | [`encryption_output_layout`](../TDN/Semantics/MultiProtocolEvents.lean#L112) |
| `def` | [`OrderedEncryptions`](../TDN/Semantics/MultiProtocolEvents.lean#L122) |
| `theorem` | [`nested_stack_requires_ordered_encryptions`](../TDN/Semantics/MultiProtocolEvents.lean#L136) |

</details>

### MultiProtocolAuthentication

Source: [MultiProtocolAuthentication.lean](../TDN/Semantics/MultiProtocolAuthentication.lean). Namespace: `TDN.MultiProtocolExecution`.

`MultiProtocolAuthentication` proves required boundary decryption when a component may use IPsec, MACsec, and carriers. [`CarrierInputCheck`](../TDN/Semantics/MultiProtocolAuthentication.lean#L20) prevents accepted carrier input from removing a required boundary tag merely by moving to a virtual interface. [`UndecryptedRegion`](../TDN/Semantics/MultiProtocolAuthentication.lean#L41) tracks the corresponding condition through processing phases.

[`inbound_crossing_has_actual_boundary_decryption`](../TDN/Semantics/MultiProtocolAuthentication.lean#L230) locates an IPsec or MACsec decryption inside the chosen component. Its premises include the mixed local conditions, the carrier input check, policy/tag restrictions for the component, and an execution confined to that component from a protected-side received state to an unprotected-side ready state. [`BoundaryDecryption`](../TDN/Semantics/MultiProtocolAuthentication.lean#L220) records the relevant policy or MACsec association and the layer removal.

Direct imports: [MultiProtocolEvents](#multiprotocolevents), [RestrictedExecution](#restrictedexecution).

<details>
<summary>All 8 named declarations in MultiProtocolAuthentication</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`carrierReceiveHeader`](../TDN/Semantics/MultiProtocolAuthentication.lean#L7) |
| `def` | [`carrierInputPacket`](../TDN/Semantics/MultiProtocolAuthentication.lean#L11) |
| `def` | [`CarrierInputCheck`](../TDN/Semantics/MultiProtocolAuthentication.lean#L20) |
| `lemma` | [`successful_unwrap_has_receiving_header`](../TDN/Semantics/MultiProtocolAuthentication.lean#L28) |
| `def` | [`UndecryptedRegion`](../TDN/Semantics/MultiProtocolAuthentication.lean#L41) |
| `lemma` | [`nondecryption_preserves_region`](../TDN/Semantics/MultiProtocolAuthentication.lean#L69) |
| `def` | [`BoundaryDecryption`](../TDN/Semantics/MultiProtocolAuthentication.lean#L220) |
| `theorem` | [`inbound_crossing_has_actual_boundary_decryption`](../TDN/Semantics/MultiProtocolAuthentication.lean#L230) |

</details>

### FiniteMultiProtocolAuthentication

Source: [FiniteMultiProtocolAuthentication.lean](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean). Namespace: `TDN.MultiProtocolExecution`.

`FiniteMultiProtocolAuthentication` makes carrier-input checking finite. [`carrierRecordPacket`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L16) builds the packet fields seen at a recorded ingress. [`FiniteCarrierInputChecks`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L25) requires the virtual interface to retain the tag, or default-deny INPUT rules to reject the carrier independently of connection-tracking state.

[`ignoresTracking`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L7) identifies atoms that do not inspect that state. [`finite_carrier_input_checks_sound`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L43) proves the general [`CarrierInputCheck`](../TDN/Semantics/MultiProtocolAuthentication.lean#L20) from the finite records. The condition covers arbitrary tracking strings by using a rejecting atom whose result cannot change with the string.

Direct imports: [MultiProtocolAuthentication](#multiprotocolauthentication), [FiniteMultiProtocol](#finitemultiprotocol).

<details>
<summary>All 5 named declarations in FiniteMultiProtocolAuthentication</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ignoresTracking`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L7) |
| `lemma` | [`atom_holds_ignores_tracking`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L11) |
| `def` | [`carrierRecordPacket`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L16) |
| `def` | [`FiniteCarrierInputChecks`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L25) |
| `theorem` | [`finite_carrier_input_checks_sound`](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L43) |

Explicit instances:

- [Instance at line 37](../TDN/Semantics/FiniteMultiProtocolAuthentication.lean#L37)

</details>

## Generated replies

[KernelResponses](#kernelresponses), [SourceResponseGuards](#sourceresponseguards), [GuardedResponseNetwork](#guardedresponsenetwork), [EncryptedResponseGuards](#encryptedresponseguards), [UniformResponseRegions](#uniformresponseregions), [UniformDomainResponses](#uniformdomainresponses), [StrictResponseProjection](#strictresponseprojection), [HistoricalResponses](#historicalresponses)

### KernelResponses

Source: [KernelResponses.lean](../TDN/Semantics/KernelResponses.lean). Namespace: `TDN.KernelResponses`.

`KernelResponses` adds generated ICMP or ICMPv6 traffic to an arbitrary network model. Its states track normal processing, a generated reply, a routed reply, and a consumed packet. [`Config`](../TDN/Semantics/KernelResponses.lean#L54) supplies when replies can be generated, how they are routed and filtered, and the state created on emission.

[`SafeResponseRule`](../TDN/Semantics/KernelResponses.lean#L17) allows a response only on loopback or excludes response protocols. The strict output-guard theorems preserve a network invariant by preventing external reply emission. [`local_reply_checks_preserve_network_safety`](../TDN/Semantics/KernelResponses.lean#L137) and [`copied_response_executions_remain_safe`](../TDN/Semantics/KernelResponses.lean#L156) support permitted replies when the caller proves that every allowed emission preserves the property. [`ProvenanceInvariant`](../TDN/Semantics/KernelResponses.lean#L128) retains the source state's safety while the reply is generated and routed.

The reply-generation relation is deliberately broad. Applications must justify the chosen generation scope and emission function for the behavior they claim to cover.

Direct imports: [PacketPolicy](#packetpolicy), `Cslib.Foundations.Semantics.LTS.Basic`.

<details>
<summary>All 16 named declarations in KernelResponses</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`Kind`](../TDN/Semantics/KernelResponses.lean#L6) |
| `def` | [`ResponseProtocol`](../TDN/Semantics/KernelResponses.lean#L10) |
| `def` | [`SafeResponseRule`](../TDN/Semantics/KernelResponses.lean#L17) |
| `theorem` | [`accepted_response_is_loopback`](../TDN/Semantics/KernelResponses.lean#L30) |
| `inductive` | [`State`](../TDN/Semantics/KernelResponses.lean#L44) |
| `inductive` | [`Action`](../TDN/Semantics/KernelResponses.lean#L50) |
| `structure` | [`Config`](../TDN/Semantics/KernelResponses.lean#L54) |
| `def` | [`outputPacket`](../TDN/Semantics/KernelResponses.lean#L62) |
| `inductive` | [`Step`](../TDN/Semantics/KernelResponses.lean#L66) |
| `def` | [`lts`](../TDN/Semantics/KernelResponses.lean#L85) |
| `def` | [`Invariant`](../TDN/Semantics/KernelResponses.lean#L88) |
| `lemma` | [`response_output_guards_preserve_network_invariant`](../TDN/Semantics/KernelResponses.lean#L94) |
| `theorem` | [`network_observations_remain_safe_with_kernel_responses`](../TDN/Semantics/KernelResponses.lean#L114) |
| `def` | [`ProvenanceInvariant`](../TDN/Semantics/KernelResponses.lean#L128) |
| `lemma` | [`local_reply_checks_preserve_network_safety`](../TDN/Semantics/KernelResponses.lean#L137) |
| `theorem` | [`copied_response_executions_remain_safe`](../TDN/Semantics/KernelResponses.lean#L156) |

Explicit instances:

- [Instance at line 13](../TDN/Semantics/KernelResponses.lean#L13)
- [Instance at line 23](../TDN/Semantics/KernelResponses.lean#L23)

</details>

### SourceResponseGuards

Source: [SourceResponseGuards.lean](../TDN/Semantics/SourceResponseGuards.lean). Namespace: `TDN.SourceResponseGuards`.

`SourceResponseGuards` compares the rules that admitted a source packet with the OUTPUT rules that could admit its reply. [`PairCheck`](../TDN/Semantics/SourceResponseGuards.lean#L72) requires equal protection stacks or identifies a reason the source/reply pair cannot match: interface mismatch, impossible authentication, non-response protocol, or disjoint source/reply address ranges.

[`AuthenticationReplyConflict`](../TDN/Semantics/SourceResponseGuards.lean#L155) adds exclusions derived from the packet's authenticated inbound policy. [`FiniteReplyChecks`](../TDN/Semantics/SourceResponseGuards.lean#L183) evaluates the cases over recorded interfaces, policies, and rules. Its soundness theorem proves equal source and output stacks for an accepted reply to the original source address.

[`FiniteGuardCoverage`](../TDN/Semantics/SourceResponseGuards.lean#L273) ensures that source-guard rules cover both encoded address families. [`finite_guard_coverage_excludes_fallback`](../TDN/Semantics/SourceResponseGuards.lean#L284) supplies an actual matching rule, so a permissive source fallback cannot silently justify an unchecked reply. The rule-pair conditions and coverage checks must both hold.

Direct imports: [KernelResponses](#kernelresponses), [FiniteExecution](#finiteexecution), [AuthenticationSelectors](#authenticationselectors).

<details>
<summary>All 18 named declarations in SourceResponseGuards</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`fallback_irrelevant`](../TDN/Semantics/SourceResponseGuards.lean#L7) |
| `def` | [`WrongIngress`](../TDN/Semantics/SourceResponseGuards.lean#L24) |
| `def` | [`WrongEgress`](../TDN/Semantics/SourceResponseGuards.lean#L29) |
| `def` | [`NonResponseProtocol`](../TDN/Semantics/SourceResponseGuards.lean#L34) |
| `def` | [`DisjointReplyAddress`](../TDN/Semantics/SourceResponseGuards.lean#L39) |
| `def` | [`PairCheck`](../TDN/Semantics/SourceResponseGuards.lean#L72) |
| `lemma` | [`checked_pair_preserves_layers`](../TDN/Semantics/SourceResponseGuards.lean#L84) |
| `theorem` | [`ordered_reply_checks_preserve_layers`](../TDN/Semantics/SourceResponseGuards.lean#L113) |
| `def` | [`ReplyExcludesSelector`](../TDN/Semantics/SourceResponseGuards.lean#L142) |
| `def` | [`AuthenticationReplyConflict`](../TDN/Semantics/SourceResponseGuards.lean#L155) |
| `lemma` | [`authenticated_reply_cannot_match`](../TDN/Semantics/SourceResponseGuards.lean#L165) |
| `def` | [`FiniteReplyChecks`](../TDN/Semantics/SourceResponseGuards.lean#L183) |
| `theorem` | [`finite_reply_checks_preserve_layers`](../TDN/Semantics/SourceResponseGuards.lean#L200) |
| `def` | [`CoverageRule`](../TDN/Semantics/SourceResponseGuards.lean#L242) |
| `lemma` | [`coverage_rule_matches`](../TDN/Semantics/SourceResponseGuards.lean#L257) |
| `def` | [`ValidSourceAddress`](../TDN/Semantics/SourceResponseGuards.lean#L270) |
| `def` | [`FiniteGuardCoverage`](../TDN/Semantics/SourceResponseGuards.lean#L273) |
| `theorem` | [`finite_guard_coverage_excludes_fallback`](../TDN/Semantics/SourceResponseGuards.lean#L284) |

Explicit instances:

- [Instance at line 45](../TDN/Semantics/SourceResponseGuards.lean#L45)
- [Instance at line 51](../TDN/Semantics/SourceResponseGuards.lean#L51)
- [Instance at line 57](../TDN/Semantics/SourceResponseGuards.lean#L57)
- [Instance at line 64](../TDN/Semantics/SourceResponseGuards.lean#L64)
- [Instance at line 78](../TDN/Semantics/SourceResponseGuards.lean#L78)
- [Instance at line 147](../TDN/Semantics/SourceResponseGuards.lean#L147)
- [Instance at line 160](../TDN/Semantics/SourceResponseGuards.lean#L160)
- [Instance at line 194](../TDN/Semantics/SourceResponseGuards.lean#L194)
- [Instance at line 248](../TDN/Semantics/SourceResponseGuards.lean#L248)
- [Instance at line 279](../TDN/Semantics/SourceResponseGuards.lean#L279)

</details>

### GuardedResponseNetwork

Source: [GuardedResponseNetwork.lean](../TDN/Semantics/GuardedResponseNetwork.lean). Namespace: `TDN.GuardedResponseNetwork`.

`GuardedResponseNetwork` combines finite IP execution data with per-device source guards. [`Guarded`](../TDN/Semantics/GuardedResponseNetwork.lean#L29) requires active processing states to pass those guards. [`network`](../TDN/Semantics/GuardedResponseNetwork.lean#L38) adds that condition to each underlying execution step. [`Safe`](../TDN/Semantics/GuardedResponseNetwork.lean#L41) combines the stack invariant, authentication-selector consistency, and source guards.

[`responseConfig`](../TDN/Semantics/GuardedResponseNetwork.lean#L45) generates replies for eligible non-loopback ingress records and routes them back to the source address. [`reply_emission_preserves_safe`](../TDN/Semantics/GuardedResponseNetwork.lean#L80) proves safety from finite source/reply checks, source-rule coverage, default-deny output, and local stack conditions. [`all_guarded_response_executions_preserve_stack`](../TDN/Semantics/GuardedResponseNetwork.lean#L130) extends the result to complete finite runs.

A deployment application must account for the added source guards. Restricting the modeled steps is justified only when the real processing under consideration enforces those restrictions.

Direct imports: [SourceResponseGuards](#sourceresponseguards).

<details>
<summary>All 14 named declarations in GuardedResponseNetwork</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ActivePhase`](../TDN/Semantics/GuardedResponseNetwork.lean#L6) |
| `structure` | [`Data`](../TDN/Semantics/GuardedResponseNetwork.lean#L13) |
| `def` | [`Data.config`](../TDN/Semantics/GuardedResponseNetwork.lean#L21) |
| `def` | [`Data.expectedEncapStack`](../TDN/Semantics/GuardedResponseNetwork.lean#L24) |
| `def` | [`sourcePacket`](../TDN/Semantics/GuardedResponseNetwork.lean#L26) |
| `def` | [`Guarded`](../TDN/Semantics/GuardedResponseNetwork.lean#L29) |
| `def` | [`network`](../TDN/Semantics/GuardedResponseNetwork.lean#L38) |
| `def` | [`Safe`](../TDN/Semantics/GuardedResponseNetwork.lean#L41) |
| `def` | [`responseConfig`](../TDN/Semantics/GuardedResponseNetwork.lean#L45) |
| `lemma` | [`processing_of_active`](../TDN/Semantics/GuardedResponseNetwork.lean#L62) |
| `lemma` | [`selectors_of_active`](../TDN/Semantics/GuardedResponseNetwork.lean#L67) |
| `lemma` | [`network_preserves_safe`](../TDN/Semantics/GuardedResponseNetwork.lean#L73) |
| `lemma` | [`reply_emission_preserves_safe`](../TDN/Semantics/GuardedResponseNetwork.lean#L80) |
| `theorem` | [`all_guarded_response_executions_preserve_stack`](../TDN/Semantics/GuardedResponseNetwork.lean#L130) |

Explicit instances:

- [Instance at line 9](../TDN/Semantics/GuardedResponseNetwork.lean#L9)
- [Instance at line 34](../TDN/Semantics/GuardedResponseNetwork.lean#L34)

</details>

### EncryptedResponseGuards

Source: [EncryptedResponseGuards.lean](../TDN/Semantics/EncryptedResponseGuards.lean). Namespace: `TDN.EncryptedResponseGuards`.

`EncryptedResponseGuards` handles replies associated with locally encrypted frames. [`LocallyEncrypted`](../TDN/Semantics/EncryptedResponseGuards.lean#L6) identifies frames produced by an outbound policy on the same device. [`LocalDeny`](../TDN/Semantics/EncryptedResponseGuards.lean#L35) requires output rules to reject external responses to the encrypted frame's source, either through protocol/loopback restrictions or destination exclusion.

[`encrypted_error_cannot_leave_component`](../TDN/Semantics/EncryptedResponseGuards.lean#L42) proves that such an external response cannot be accepted. [`FiniteDeny`](../TDN/Semantics/EncryptedResponseGuards.lean#L67) and [`finite_deny_sound`](../TDN/Semantics/EncryptedResponseGuards.lean#L76) connect the obligation to device records. [`combinedConfig`](../TDN/Semantics/EncryptedResponseGuards.lean#L91) includes both guarded ordinary sources and locally encrypted sources; [`combined_executions_preserve_stack`](../TDN/Semantics/EncryptedResponseGuards.lean#L125) proves the resulting stack property. [`network_trace_in_response_system`](../TDN/Semantics/EncryptedResponseGuards.lean#L150) embeds an ordinary execution in the response model.

Direct imports: [GuardedResponseNetwork](#guardedresponsenetwork).

<details>
<summary>All 12 named declarations in EncryptedResponseGuards</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`LocallyEncrypted`](../TDN/Semantics/EncryptedResponseGuards.lean#L6) |
| `def` | [`ExcludesWireSource`](../TDN/Semantics/EncryptedResponseGuards.lean#L11) |
| `lemma` | [`matching_destination_not_excluded`](../TDN/Semantics/EncryptedResponseGuards.lean#L24) |
| `def` | [`LocalDeny`](../TDN/Semantics/EncryptedResponseGuards.lean#L35) |
| `theorem` | [`encrypted_error_cannot_leave_component`](../TDN/Semantics/EncryptedResponseGuards.lean#L42) |
| `def` | [`FiniteDeny`](../TDN/Semantics/EncryptedResponseGuards.lean#L67) |
| `theorem` | [`finite_deny_sound`](../TDN/Semantics/EncryptedResponseGuards.lean#L76) |
| `def` | [`combinedConfig`](../TDN/Semantics/EncryptedResponseGuards.lean#L91) |
| `lemma` | [`combined_reply_preserves_safe`](../TDN/Semantics/EncryptedResponseGuards.lean#L97) |
| `theorem` | [`combined_executions_preserve_stack`](../TDN/Semantics/EncryptedResponseGuards.lean#L125) |
| `lemma` | [`encryption_step_is_local`](../TDN/Semantics/EncryptedResponseGuards.lean#L144) |
| `lemma` | [`network_trace_in_response_system`](../TDN/Semantics/EncryptedResponseGuards.lean#L150) |

Explicit instances:

- [Instance at line 16](../TDN/Semantics/EncryptedResponseGuards.lean#L16)
- [Instance at line 72](../TDN/Semantics/EncryptedResponseGuards.lean#L72)

</details>

### UniformResponseRegions

Source: [UniformResponseRegions.lean](../TDN/Semantics/UniformResponseRegions.lean). Namespace: `TDN.UniformResponseRegions`.

`UniformResponseRegions` handles devices whose interfaces all require the same protection stack and that have no inbound decryption policies. [`Uniform`](../TDN/Semantics/UniformResponseRegions.lean#L6) states those two conditions. [`all_active_phases_have_uniform_stack`](../TDN/Semantics/UniformResponseRegions.lean#L26) proves that every non-dropped state satisfying the stack invariant has the stack assigned to its current interface.

[`FiniteUniform`](../TDN/Semantics/UniformResponseRegions.lean#L44) checks the condition over device and interface records. The response configuration extends the previous model to those devices, and [`all_component_response_executions_preserve_stack`](../TDN/Semantics/UniformResponseRegions.lean#L109) combines uniform-device checks with the source-guard and encrypted-response checks. A device that crosses encryption boundaries needs the stronger checks from the other response modules.

Direct imports: [EncryptedResponseGuards](#encryptedresponseguards).

<details>
<summary>All 8 named declarations in UniformResponseRegions</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Uniform`](../TDN/Semantics/UniformResponseRegions.lean#L6) |
| `lemma` | [`processing_stack_at_iface`](../TDN/Semantics/UniformResponseRegions.lean#L11) |
| `theorem` | [`all_active_phases_have_uniform_stack`](../TDN/Semantics/UniformResponseRegions.lean#L26) |
| `def` | [`FiniteUniform`](../TDN/Semantics/UniformResponseRegions.lean#L44) |
| `theorem` | [`finite_uniform_sound`](../TDN/Semantics/UniformResponseRegions.lean#L54) |
| `def` | [`responseConfig`](../TDN/Semantics/UniformResponseRegions.lean#L67) |
| `lemma` | [`reply_preserves_safe`](../TDN/Semantics/UniformResponseRegions.lean#L74) |
| `theorem` | [`all_component_response_executions_preserve_stack`](../TDN/Semantics/UniformResponseRegions.lean#L109) |

Explicit instances:

- [Instance at line 49](../TDN/Semantics/UniformResponseRegions.lean#L49)

</details>

### UniformDomainResponses

Source: [UniformDomainResponses.lean](../TDN/Semantics/UniformDomainResponses.lean). Namespace: `TDN.UniformDomainResponses`.

`UniformDomainResponses` extends uniform-device reasoning with membership in an allowed set of interfaces. [`Uniform`](../TDN/Semantics/UniformDomainResponses.lean#L7) requires both uniform stacks and preservation of allowed membership between interfaces on the device.

[`responseConfig`](../TDN/Semantics/UniformDomainResponses.lean#L39) covers two declared device sets: devices whose output rules strictly block external responses, and devices satisfying the uniform conditions. [`reply_preserves_domain`](../TDN/Semantics/UniformDomainResponses.lean#L51) proves that permitted emissions preserve [`DomainInvariant`](../TDN/Semantics/ExecutionDomains.lean#L38). [`FiniteUniform`](../TDN/Semantics/UniformDomainResponses.lean#L85) and its soundness theorem reduce the uniform premise to recorded interfaces and devices. The sets of response-generating devices and their premises are explicit application inputs.

Direct imports: [UniformResponseRegions](#uniformresponseregions), [ExecutionDomains](#executiondomains).

<details>
<summary>All 7 named declarations in UniformDomainResponses</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Uniform`](../TDN/Semantics/UniformDomainResponses.lean#L7) |
| `lemma` | [`processing_at_iface`](../TDN/Semantics/UniformDomainResponses.lean#L13) |
| `lemma` | [`active_domain_at_iface`](../TDN/Semantics/UniformDomainResponses.lean#L21) |
| `def` | [`responseConfig`](../TDN/Semantics/UniformDomainResponses.lean#L39) |
| `lemma` | [`reply_preserves_domain`](../TDN/Semantics/UniformDomainResponses.lean#L51) |
| `def` | [`FiniteUniform`](../TDN/Semantics/UniformDomainResponses.lean#L85) |
| `theorem` | [`finite_uniform_sound`](../TDN/Semantics/UniformDomainResponses.lean#L98) |

Explicit instances:

- [Instance at line 92](../TDN/Semantics/UniformDomainResponses.lean#L92)

</details>

### StrictResponseProjection

Source: [StrictResponseProjection.lean](../TDN/Semantics/StrictResponseProjection.lean). Namespace: `TDN.KernelResponses`.

`StrictResponseProjection` proves that a completed network-to-network run in the strict response model has a corresponding run in the original network model. [`strict_response_result_has_network_execution`](../TDN/Semantics/StrictResponseProjection.lean#L5) requires default-deny output and [`SafeResponseRule`](../TDN/Semantics/KernelResponses.lean#L17) for every allowed rule at every enabled reply source.

The proof removes response-processing branches that cannot emit externally and recovers a list of original network actions. The theorem provides a useful connection when applying existing path or execution results to a model that includes blocked generated responses.

Direct imports: [KernelResponses](#kernelresponses).

<details>
<summary>All 1 named declarations in StrictResponseProjection</summary>

| Kind | Declaration |
| --- | --- |
| `theorem` | [`strict_response_result_has_network_execution`](../TDN/Semantics/StrictResponseProjection.lean#L5) |

</details>

### HistoricalResponses

Source: [HistoricalResponses.lean](../TDN/Semantics/HistoricalResponses.lean). Namespace: `TDN.HistoricalResponses`.

`HistoricalResponses` retains earlier network states so that later processing can refer to them. Its [`State`](../TDN/Semantics/HistoricalResponses.lean#L5) holds the current state and a list of retained states. Ordinary network steps retain the previous state; a selection step makes a retained state current again.

[`Safe`](../TDN/Semantics/HistoricalResponses.lean#L24) requires the property for every retained state as well as the current one. [`network_preserves_retained_safety`](../TDN/Semantics/HistoricalResponses.lean#L27) and [`all_historical_responses_preserve_safety`](../TDN/Semantics/HistoricalResponses.lean#L50) preserve that condition, including generated replies when their local emission check holds. [`lift_network_trace`](../TDN/Semantics/HistoricalResponses.lean#L74) embeds an ordinary trace. The model supports delayed processing of saved packet states; it supplies no wall-clock scheduling guarantee.

Direct imports: [KernelResponses](#kernelresponses).

<details>
<summary>All 9 named declarations in HistoricalResponses</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`State`](../TDN/Semantics/HistoricalResponses.lean#L5) |
| `inductive` | [`Action`](../TDN/Semantics/HistoricalResponses.lean#L9) |
| `inductive` | [`Step`](../TDN/Semantics/HistoricalResponses.lean#L13) |
| `def` | [`lts`](../TDN/Semantics/HistoricalResponses.lean#L21) |
| `def` | [`Safe`](../TDN/Semantics/HistoricalResponses.lean#L24) |
| `lemma` | [`network_preserves_retained_safety`](../TDN/Semantics/HistoricalResponses.lean#L27) |
| `def` | [`responseConfig`](../TDN/Semantics/HistoricalResponses.lean#L40) |
| `theorem` | [`all_historical_responses_preserve_safety`](../TDN/Semantics/HistoricalResponses.lean#L50) |
| `theorem` | [`lift_network_trace`](../TDN/Semantics/HistoricalResponses.lean#L74) |

</details>

## Fragments, copied bytes, and reassembly

[Fragmentation](#fragmentation), [DistributedFragments](#distributedfragments), [ExecutionFragments](#executionfragments), [FragmentHeaders](#fragmentheaders), [ReassemblyOrigins](#reassemblyorigins), [AuthenticatedAssembly](#authenticatedassembly), [ByteFlows](#byteflows), [ByteLineage](#bytelineage), [PlaintextAssembly](#plaintextassembly), [ResponseByteFlows](#responsebyteflows), [ByteProtectionEvents](#byteprotectionevents), [MixedByteFlows](#mixedbyteflows)

### Fragmentation

Source: [Fragmentation.lean](../TDN/Semantics/Fragmentation.lean). Namespace: `TDN.Fragmentation`.

`Fragmentation` represents a datagram as a header and a byte list, and a fragment as a header, offset, and byte list. [`split`](../TDN/Semantics/Fragmentation.lean#L15) produces two pieces; [`join`](../TDN/Semantics/Fragmentation.lean#L20) accepts matching headers and contiguous offsets. The first theorems prove header preservation and exact reassembly for those operations.

[`ValidPieces`](../TDN/Semantics/Fragmentation.lean#L91) generalizes the argument to any nonempty partition with common headers, contiguous offsets, and bytes that reconstruct the original. [`SegmentedState`](../TDN/Semantics/Fragmentation.lean#L127) retains a logical state plus optional fragments. Its steps split, reassemble, or move pieces through an underlying logical step that preserves their encoded header and bytes. The consistency theorems preserve that relationship.

[`StepProjection`](../TDN/Semantics/Fragmentation.lean#L41) requires each detailed step to correspond to an abstract step or leave the abstract state unchanged. [`fragmented_execution_preserves_invariant`](../TDN/Semantics/Fragmentation.lean#L63) transfers an abstract invariant through that connection. The concrete fragmented-system constructors establish the projection for the defined model. A deployment still needs a justified mapping from its fragmentation behavior to those constructors.

Direct imports: `Cslib.Foundations.Semantics.LTS.Simulation`, `Mathlib.Data.List.Basic`.

<details>
<summary>All 24 named declarations in Fragmentation</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Datagram`](../TDN/Semantics/Fragmentation.lean#L6) |
| `structure` | [`Fragment`](../TDN/Semantics/Fragmentation.lean#L10) |
| `def` | [`split`](../TDN/Semantics/Fragmentation.lean#L15) |
| `def` | [`join`](../TDN/Semantics/Fragmentation.lean#L20) |
| `theorem` | [`split_preserves_header`](../TDN/Semantics/Fragmentation.lean#L25) |
| `theorem` | [`reassembly_restores_bytes`](../TDN/Semantics/Fragmentation.lean#L29) |
| `def` | [`stuttering`](../TDN/Semantics/Fragmentation.lean#L35) |
| `def` | [`StepProjection`](../TDN/Semantics/Fragmentation.lean#L41) |
| `theorem` | [`projection_is_simulation`](../TDN/Semantics/Fragmentation.lean#L47) |
| `lemma` | [`stuttering_preserves_invariant`](../TDN/Semantics/Fragmentation.lean#L55) |
| `theorem` | [`fragmented_execution_preserves_invariant`](../TDN/Semantics/Fragmentation.lean#L63) |
| `def` | [`Contiguous`](../TDN/Semantics/Fragmentation.lean#L77) |
| `def` | [`ValidPieces`](../TDN/Semantics/Fragmentation.lean#L91) |
| `def` | [`makePieces`](../TDN/Semantics/Fragmentation.lean#L96) |
| `lemma` | [`made_pieces_metadata`](../TDN/Semantics/Fragmentation.lean#L101) |
| `theorem` | [`arbitrary_partition_is_valid`](../TDN/Semantics/Fragmentation.lean#L118) |
| `structure` | [`SegmentedState`](../TDN/Semantics/Fragmentation.lean#L127) |
| `inductive` | [`SegmentedStep`](../TDN/Semantics/Fragmentation.lean#L131) |
| `def` | [`segmented`](../TDN/Semantics/Fragmentation.lean#L147) |
| `theorem` | [`segmented_projection_checked`](../TDN/Semantics/Fragmentation.lean#L152) |
| `def` | [`PiecesConsistent`](../TDN/Semantics/Fragmentation.lean#L162) |
| `lemma` | [`segmented_preserves_piece_consistency`](../TDN/Semantics/Fragmentation.lean#L166) |
| `theorem` | [`execution_preserves_piece_consistency`](../TDN/Semantics/Fragmentation.lean#L181) |
| `theorem` | [`arbitrary_partition_reassembles`](../TDN/Semantics/Fragmentation.lean#L189) |

Explicit instances:

- [Instance at line 82](../TDN/Semantics/Fragmentation.lean#L82)

</details>

### DistributedFragments

Source: [DistributedFragments.lean](../TDN/Semantics/DistributedFragments.lean). Namespace: `TDN.Fragmentation`.

`DistributedFragments` allows fragments to occupy different logical states while they travel. [`DistributedState`](../TDN/Semantics/DistributedFragments.lean#L5) contains either a whole packet or a list of located pieces. `movePiece` advances one piece while preserving its encoded header and bytes. Reassembly requires the pieces to meet at the same logical state and satisfy [`ValidPieces`](../TDN/Semantics/Fragmentation.lean#L91).

[`DistributedInvariant`](../TDN/Semantics/DistributedFragments.lean#L33) requires each located piece to satisfy the underlying invariant and carry the header of its logical state. [`distributed_step_preserves`](../TDN/Semantics/DistributedFragments.lean#L40) and [`distributed_execution_preserves`](../TDN/Semantics/DistributedFragments.lean#L64) lift any locally preserved invariant to that model. The argument covers the allowed movement and reassembly steps; it does not require all fragments to move together.

Direct imports: [Fragmentation](#fragmentation).

<details>
<summary>All 6 named declarations in DistributedFragments</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`DistributedState`](../TDN/Semantics/DistributedFragments.lean#L5) |
| `inductive` | [`DistributedStep`](../TDN/Semantics/DistributedFragments.lean#L9) |
| `def` | [`distributed`](../TDN/Semantics/DistributedFragments.lean#L28) |
| `def` | [`DistributedInvariant`](../TDN/Semantics/DistributedFragments.lean#L33) |
| `lemma` | [`distributed_step_preserves`](../TDN/Semantics/DistributedFragments.lean#L40) |
| `theorem` | [`distributed_execution_preserves`](../TDN/Semantics/DistributedFragments.lean#L64) |

</details>

### ExecutionFragments

Source: [ExecutionFragments.lean](../TDN/Semantics/ExecutionFragments.lean). Namespace: `TDN.Execution`.

`ExecutionFragments` connects IP packet execution to the generic fragmentation model. [`FragmentDescriptor`](../TDN/Semantics/ExecutionFragments.lean#L6) records payload identity, origin domain, visible source/destination addresses, and protection tags. [`encodeForFragmentation`](../TDN/Semantics/ExecutionFragments.lean#L18) pairs that descriptor with bytes supplied by the caller's encoding function.

[`execution_fragment_descriptors_match`](../TDN/Semantics/ExecutionFragments.lean#L22) proves that every retained fragment has the descriptor of the current logical execution state when the run starts whole. The encoding function and the admissible fragment movements determine what implementation behavior the result covers.

Direct imports: [ExecutionInvariant](#executioninvariant), [Fragmentation](#fragmentation).

<details>
<summary>All 4 named declarations in ExecutionFragments</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`FragmentDescriptor`](../TDN/Semantics/ExecutionFragments.lean#L6) |
| `def` | [`fragmentDescriptor`](../TDN/Semantics/ExecutionFragments.lean#L14) |
| `def` | [`encodeForFragmentation`](../TDN/Semantics/ExecutionFragments.lean#L18) |
| `theorem` | [`execution_fragment_descriptors_match`](../TDN/Semantics/ExecutionFragments.lean#L22) |

</details>

### FragmentHeaders

Source: [FragmentHeaders.lean](../TDN/Semantics/FragmentHeaders.lean). Namespace: `TDN.FragmentHeaders`.

`FragmentHeaders` models rule evaluation when a fragment lacks transport-header fields. [`availableWithoutTransport`](../TDN/Semantics/FragmentHeaders.lean#L6) excludes transport-port and ICMP type/code atoms. A fragment rule matches only when all its atoms are available and hold. [`completeTransport`](../TDN/Semantics/FragmentHeaders.lean#L46) supplies arbitrary values for the missing fields.

[`every_transport_completion_covers_accepted_fragment`](../TDN/Semantics/FragmentHeaders.lean#L65) proves that acceptance extends to every such completion for an allow-only rule list. [`fragment_forwarding_inherits_packet_policy`](../TDN/Semantics/FragmentHeaders.lean#L37) derives guarded forwarding under default deny. The route and policy-selection lemmas prove independence from the missing fields because the modeled selectors use addresses.

The allow-only premise is essential to the supplied argument. More general ordered mixtures of allow and deny rules need additional reasoning about how missing fields affect earlier rules.

Direct imports: [Execution](#execution).

<details>
<summary>All 10 named declarations in FragmentHeaders</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`availableWithoutTransport`](../TDN/Semantics/FragmentHeaders.lean#L6) |
| `def` | [`rule`](../TDN/Semantics/FragmentHeaders.lean#L10) |
| `lemma` | [`fragment_match_implies_completed_match`](../TDN/Semantics/FragmentHeaders.lean#L14) |
| `theorem` | [`allow_only_rules_cover_noninitial_fragments`](../TDN/Semantics/FragmentHeaders.lean#L20) |
| `theorem` | [`fragment_forwarding_inherits_packet_policy`](../TDN/Semantics/FragmentHeaders.lean#L37) |
| `def` | [`completeTransport`](../TDN/Semantics/FragmentHeaders.lean#L46) |
| `lemma` | [`fragment_rule_ignores_unavailable_transport`](../TDN/Semantics/FragmentHeaders.lean#L53) |
| `theorem` | [`every_transport_completion_covers_accepted_fragment`](../TDN/Semantics/FragmentHeaders.lean#L65) |
| `lemma` | [`route_selection_ignores_unavailable_transport`](../TDN/Semantics/FragmentHeaders.lean#L83) |
| `lemma` | [`policy_selection_ignores_unavailable_transport`](../TDN/Semantics/FragmentHeaders.lean#L89) |

</details>

### ReassemblyOrigins

Source: [ReassemblyOrigins.lean](../TDN/Semantics/ReassemblyOrigins.lean). Namespace: `TDN.ReassemblyOrigins`.

`ReassemblyOrigins` proves properties of the bytes admitted into a reassembly buffer. [`ByteOrigin`](../TDN/Semantics/ReassemblyOrigins.lean#L5) can annotate each byte with its domain and source packet. [`assemble`](../TDN/Semantics/ReassemblyOrigins.lean#L10) checks nonempty pieces, matching headers, and contiguous offsets before concatenating their bytes.

[`PieceSafe`](../TDN/Semantics/ReassemblyOrigins.lean#L18) and [`BufferSafe`](../TDN/Semantics/ReassemblyOrigins.lean#L22) require a chosen property for every byte. The buffer steps admit pieces, discard pieces, or clear the buffer. [`every_reassembly_history_preserves_byte_safety`](../TDN/Semantics/ReassemblyOrigins.lean#L83) proves the property for every assembled byte when each admitted piece satisfies it. [`reassembled_bytes_stay_in_admitted_domain`](../TDN/Semantics/ReassemblyOrigins.lean#L98) specializes the property to one domain. The caller must prove the piece-admission rule, including how source annotations correspond to actual received data.

Direct imports: [Fragmentation](#fragmentation).

<details>
<summary>All 12 named declarations in ReassemblyOrigins</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`ByteOrigin`](../TDN/Semantics/ReassemblyOrigins.lean#L5) |
| `def` | [`assemble`](../TDN/Semantics/ReassemblyOrigins.lean#L10) |
| `def` | [`PieceSafe`](../TDN/Semantics/ReassemblyOrigins.lean#L18) |
| `def` | [`BufferSafe`](../TDN/Semantics/ReassemblyOrigins.lean#L22) |
| `lemma` | [`flattened_bytes_safe`](../TDN/Semantics/ReassemblyOrigins.lean#L26) |
| `theorem` | [`assembled_bytes_inherit_piece_safety`](../TDN/Semantics/ReassemblyOrigins.lean#L36) |
| `inductive` | [`Action`](../TDN/Semantics/ReassemblyOrigins.lean#L48) |
| `inductive` | [`Step`](../TDN/Semantics/ReassemblyOrigins.lean#L52) |
| `def` | [`system`](../TDN/Semantics/ReassemblyOrigins.lean#L62) |
| `lemma` | [`admission_preserves_byte_safety`](../TDN/Semantics/ReassemblyOrigins.lean#L67) |
| `theorem` | [`every_reassembly_history_preserves_byte_safety`](../TDN/Semantics/ReassemblyOrigins.lean#L83) |
| `theorem` | [`reassembled_bytes_stay_in_admitted_domain`](../TDN/Semantics/ReassemblyOrigins.lean#L98) |

</details>

### AuthenticatedAssembly

Source: [AuthenticatedAssembly.lean](../TDN/Semantics/AuthenticatedAssembly.lean). Namespace: `TDN.AuthenticatedAssembly`.

`AuthenticatedAssembly` connects accepted reassembled ciphertext to messages previously produced under compatible authentication contexts. [`Context`](../TDN/Semantics/AuthenticatedAssembly.lean#L5) includes secret identity, receiver, protocol domain, direction, and key-use epoch. [`Compatible`](../TDN/Semantics/AuthenticatedAssembly.lean#L13) checks those fields and a caller-supplied epoch-acceptance relation. A [`Message`](../TDN/Semantics/AuthenticatedAssembly.lean#L20) retains producer annotations; a [`Decoded`](../TDN/Semantics/AuthenticatedAssembly.lean#L27) value contains the context, wire bytes, and recovered plaintext.

[`AuthenticationSound`](../TDN/Semantics/AuthenticatedAssembly.lean#L47) requires every accepted decoding to match a prior publication. It is an explicit cryptographic premise. [`all_accepted_messages_inherit_publication_property`](../TDN/Semantics/AuthenticatedAssembly.lean#L128) proves that accepted messages inherit a property imposed on every published message. [`accepted_messages_from_seeded_history`](../TDN/Semantics/AuthenticatedAssembly.lean#L151) handles a nonempty initial history, and [`published_messages_were_produced`](../TDN/Semantics/AuthenticatedAssembly.lean#L172) establishes production for histories starting empty.

The application must include every producer capable of authenticating under the receiving context and justify key, direction, epoch, and no-forgery assumptions. The property applies to all matching publications, which matters when identical plaintext could have several producers.

Direct imports: [ReassemblyOrigins](#reassemblyorigins).

<details>
<summary>All 15 named declarations in AuthenticatedAssembly</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Context`](../TDN/Semantics/AuthenticatedAssembly.lean#L5) |
| `def` | [`Compatible`](../TDN/Semantics/AuthenticatedAssembly.lean#L13) |
| `structure` | [`Message`](../TDN/Semantics/AuthenticatedAssembly.lean#L20) |
| `structure` | [`Decoded`](../TDN/Semantics/AuthenticatedAssembly.lean#L27) |
| `def` | [`Matches`](../TDN/Semantics/AuthenticatedAssembly.lean#L33) |
| `structure` | [`State`](../TDN/Semantics/AuthenticatedAssembly.lean#L39) |
| `inductive` | [`Action`](../TDN/Semantics/AuthenticatedAssembly.lean#L44) |
| `def` | [`AuthenticationSound`](../TDN/Semantics/AuthenticatedAssembly.lean#L47) |
| `inductive` | [`Step`](../TDN/Semantics/AuthenticatedAssembly.lean#L54) |
| `def` | [`system`](../TDN/Semantics/AuthenticatedAssembly.lean#L77) |
| `def` | [`Safe`](../TDN/Semantics/AuthenticatedAssembly.lean#L84) |
| `lemma` | [`local_publication_preserves`](../TDN/Semantics/AuthenticatedAssembly.lean#L92) |
| `theorem` | [`all_accepted_messages_inherit_publication_property`](../TDN/Semantics/AuthenticatedAssembly.lean#L128) |
| `theorem` | [`accepted_messages_from_seeded_history`](../TDN/Semantics/AuthenticatedAssembly.lean#L151) |
| `theorem` | [`published_messages_were_produced`](../TDN/Semantics/AuthenticatedAssembly.lean#L172) |

</details>

### ByteFlows

Source: [ByteFlows.lean](../TDN/Semantics/ByteFlows.lean). Namespace: `TDN.ByteFlows`.

`ByteFlows` lifts a packet-state model to a collection of packets carrying explicit byte lists. [`Carrier`](../TDN/Semantics/ByteFlows.lean#L6) pairs a network state with its bytes. The steps inject packets, advance one packet, split, assemble, copy selected bytes, discard packets, or reorder the collection.

[`all_executions_preserve_byte_properties`](../TDN/Semantics/ByteFlows.lean#L108) proves a property for every byte in every resulting carrier. The caller supplies three premises: valid origins satisfy the property; network steps preserve it; and permitted assembly preserves it. [`network_trace_on_one_carrier`](../TDN/Semantics/ByteFlows.lean#L122) embeds an ordinary network trace into the collection model. Copying is based on membership in a source byte list, so applications should use origin-bearing byte identities when equal byte values could otherwise hide distinct sources.

Direct imports: `Cslib.Foundations.Semantics.LTS.Basic`, `Mathlib.Data.List.Basic`.

<details>
<summary>All 8 named declarations in ByteFlows</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Carrier`](../TDN/Semantics/ByteFlows.lean#L6) |
| `inductive` | [`Action`](../TDN/Semantics/ByteFlows.lean#L10) |
| `inductive` | [`Step`](../TDN/Semantics/ByteFlows.lean#L14) |
| `def` | [`lts`](../TDN/Semantics/ByteFlows.lean#L38) |
| `def` | [`Safe`](../TDN/Semantics/ByteFlows.lean#L42) |
| `lemma` | [`step_preserves_bytes`](../TDN/Semantics/ByteFlows.lean#L45) |
| `theorem` | [`all_executions_preserve_byte_properties`](../TDN/Semantics/ByteFlows.lean#L108) |
| `theorem` | [`network_trace_on_one_carrier`](../TDN/Semantics/ByteFlows.lean#L122) |

</details>

### ByteLineage

Source: [ByteLineage.lean](../TDN/Semantics/ByteLineage.lean). Namespace: `TDN.ByteLineage`.

`ByteLineage` records a path from an admitted byte's source state to its current state. Its steps include network processing and permitted assembly changes. [`HasOrigin`](../TDN/Semantics/ByteLineage.lean#L15) states that such a source and path exist.

[`every_byte_has_source_path`](../TDN/Semantics/ByteLineage.lean#L19) proves that every byte present after a `ByteFlows` execution from an empty collection has an admitted source path. [`local_checks_preserve_lineage`](../TDN/Semantics/ByteLineage.lean#L38) carries a property along that path when network steps and assembly each preserve it. The result lets a proof identify encryption events along a copied or reassembled byte's own path.

Direct imports: [ByteFlows](#byteflows).

<details>
<summary>All 5 named declarations in ByteLineage</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`Step`](../TDN/Semantics/ByteLineage.lean#L5) |
| `def` | [`lts`](../TDN/Semantics/ByteLineage.lean#L12) |
| `def` | [`HasOrigin`](../TDN/Semantics/ByteLineage.lean#L15) |
| `theorem` | [`every_byte_has_source_path`](../TDN/Semantics/ByteLineage.lean#L19) |
| `lemma` | [`local_checks_preserve_lineage`](../TDN/Semantics/ByteLineage.lean#L38) |

</details>

### PlaintextAssembly

Source: [PlaintextAssembly.lean](../TDN/Semantics/PlaintextAssembly.lean). Namespace: `TDN.Execution`.

[`PlaintextAssembly`](../TDN/Semantics/PlaintextAssembly.lean#L6) permits assembly between received states at the same interface when both states have empty encryption-tag lists. [`plaintext_assembly_preserves_domain`](../TDN/Semantics/PlaintextAssembly.lean#L10) proves that such a change preserves [`DomainInvariant`](../TDN/Semantics/ExecutionDomains.lean#L38).

The proof works because the received-state domain invariant depends on the interface and expected stack. It gives a specific assembly relation for byte-flow applications. Authenticated ciphertext assembly uses the separate authentication model.

Direct imports: [ByteFlows](#byteflows), [ExecutionDomains](#executiondomains).

<details>
<summary>All 2 named declarations in PlaintextAssembly</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`PlaintextAssembly`](../TDN/Semantics/PlaintextAssembly.lean#L6) |
| `lemma` | [`plaintext_assembly_preserves_domain`](../TDN/Semantics/PlaintextAssembly.lean#L10) |

</details>

### ResponseByteFlows

Source: [ResponseByteFlows.lean](../TDN/Semantics/ResponseByteFlows.lean). Namespace: `TDN.ResponseByteFlows`.

`ResponseByteFlows` combines byte collections with the generated-response model. New byte origins and assembly are permitted only in ordinary network states. Reply generation and emission then occur through `KernelResponses`.

[`all_fragment_and_response_histories_preserve_bytes`](../TDN/Semantics/ResponseByteFlows.lean#L31) uses strict response output guards. [`all_fragment_and_permitted_response_histories_preserve_bytes`](../TDN/Semantics/ResponseByteFlows.lean#L61) allows external replies when their emission preserves the byte property. Both require safe injection, invariant-preserving network steps, and safe assembly. The latter theorem retains the source state's property through reply generation and routing, which supports reasoning about copied bytes in replies.

Direct imports: [ByteFlows](#byteflows), [KernelResponses](#kernelresponses).

<details>
<summary>All 6 named declarations in ResponseByteFlows</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`source`](../TDN/Semantics/ResponseByteFlows.lean#L6) |
| `def` | [`assembly`](../TDN/Semantics/ResponseByteFlows.lean#L11) |
| `def` | [`system`](../TDN/Semantics/ResponseByteFlows.lean#L16) |
| `lemma` | [`assembled_response_state_preserves`](../TDN/Semantics/ResponseByteFlows.lean#L20) |
| `theorem` | [`all_fragment_and_response_histories_preserve_bytes`](../TDN/Semantics/ResponseByteFlows.lean#L31) |
| `theorem` | [`all_fragment_and_permitted_response_histories_preserve_bytes`](../TDN/Semantics/ResponseByteFlows.lean#L61) |

</details>

### ByteProtectionEvents

Source: [ByteProtectionEvents.lean](../TDN/Semantics/ByteProtectionEvents.lean). Namespace: `TDN.ByteProtectionEvents`.

`ByteProtectionEvents` follows protection tags along byte-origin paths that include IP execution, generated responses, and plaintext assembly. [`tags`](../TDN/Semantics/ByteProtectionEvents.lean#L10) reads the source frame's tags during response generation and routing. [`EncryptionEvent`](../TDN/Semantics/ByteProtectionEvents.lean#L19) identifies an actual underlying IP encryption step.

[`trace_tag_addition_has_encryption`](../TDN/Semantics/ByteProtectionEvents.lean#L49) proves that a tag appearing along such a path has a corresponding encryption event. [`domain_lineage_preservation`](../TDN/Semantics/ByteProtectionEvents.lean#L63) preserves the allowed-domain invariant through the combined model under local domain conditions and strict/uniform response checks. The module prevents copying or assembly steps from being mistaken for encryption operations in the proof.

Direct imports: [ByteLineage](#bytelineage), [ResponseByteFlows](#responsebyteflows), [PlaintextAssembly](#plaintextassembly), [UniformDomainResponses](#uniformdomainresponses), [ExecutionEvents](#executionevents).

<details>
<summary>All 6 named declarations in ByteProtectionEvents</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`tags`](../TDN/Semantics/ByteProtectionEvents.lean#L10) |
| `def` | [`system`](../TDN/Semantics/ByteProtectionEvents.lean#L14) |
| `def` | [`EncryptionEvent`](../TDN/Semantics/ByteProtectionEvents.lean#L19) |
| `lemma` | [`added_tag_is_actual_encryption`](../TDN/Semantics/ByteProtectionEvents.lean#L27) |
| `theorem` | [`trace_tag_addition_has_encryption`](../TDN/Semantics/ByteProtectionEvents.lean#L49) |
| `lemma` | [`domain_lineage_preservation`](../TDN/Semantics/ByteProtectionEvents.lean#L63) |

</details>

### MixedByteFlows

Source: [MixedByteFlows.lean](../TDN/Semantics/MixedByteFlows.lean). Namespace: `TDN.MultiProtocolExecution`.

`MixedByteFlows` applies byte-origin reasoning to the IPsec/MACsec/carrier model. [`PlainByteAssembly`](../TDN/Semantics/MixedByteFlows.lean#L7) permits same-interface assembly of received plaintext into a datagram or Ethernet body. [`mixed_byte_execution_preserves_stack`](../TDN/Semantics/MixedByteFlows.lean#L26) lifts the mixed stack invariant to all resulting byte carriers when injection and local conditions are checked.

[`byteLineage`](../TDN/Semantics/MixedByteFlows.lean#L40) tracks the individual source paths. [`byte_path_layer_addition_has_encryption`](../TDN/Semantics/MixedByteFlows.lean#L68) locates an IPsec or MACsec encryption event on such a path. [`mixed_byte_path_requires_ordered_encryptions`](../TDN/Semantics/MixedByteFlows.lean#L88) proves Inner-before-Outer order under the two-layer placement premise. The scope is the mixed network and stated plaintext assembly relation; generated-response composition is provided separately for the IP model.

Direct imports: [ByteLineage](#bytelineage), [MultiProtocolEvents](#multiprotocolevents).

<details>
<summary>All 11 named declarations in MixedByteFlows</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`PlainByteAssembly`](../TDN/Semantics/MixedByteFlows.lean#L7) |
| `lemma` | [`plain_byte_assembly_preserves_stack`](../TDN/Semantics/MixedByteFlows.lean#L13) |
| `def` | [`byteSystem`](../TDN/Semantics/MixedByteFlows.lean#L23) |
| `theorem` | [`mixed_byte_execution_preserves_stack`](../TDN/Semantics/MixedByteFlows.lean#L26) |
| `def` | [`byteLineage`](../TDN/Semantics/MixedByteFlows.lean#L40) |
| `lemma` | [`byte_lineage_preserves_stack`](../TDN/Semantics/MixedByteFlows.lean#L42) |
| `def` | [`ByteEncryptionEvent`](../TDN/Semantics/MixedByteFlows.lean#L49) |
| `lemma` | [`byte_layer_added_only_by_encryption`](../TDN/Semantics/MixedByteFlows.lean#L54) |
| `theorem` | [`byte_path_layer_addition_has_encryption`](../TDN/Semantics/MixedByteFlows.lean#L68) |
| `def` | [`ByteOrderedEncryptions`](../TDN/Semantics/MixedByteFlows.lean#L80) |
| `theorem` | [`mixed_byte_path_requires_ordered_encryptions`](../TDN/Semantics/MixedByteFlows.lean#L88) |

</details>

## Trust and access

[Trust](#trust), [IKEContexts](#ikecontexts), [KeySources](#keysources), [SequenceFreshness](#sequencefreshness), [AccessControl](#accesscontrol)

### Trust

Source: [Trust.lean](../TDN/Semantics/Trust.lean). Namespace: `TDN.Trust`.

`Trust` models certificate-authority and pre-shared-key trust domains. [`Identity`](../TDN/Semantics/Trust.lean#L5) stores a domain, issuer, and trusted issuer list. [`Admits`](../TDN/Semantics/Trust.lean#L10) checks issuer membership. [`Scoped`](../TDN/Semantics/Trust.lean#L15) requires both the local issuer and every trusted issuer to belong to the identity's domain under a supplied authority-ownership function.

[`scoped_authorities_exclude_cross_domain`](../TDN/Semantics/Trust.lean#L24) rules out mutual admission between different domains under those conditions. [`SharedKeyIdentity`](../TDN/Semantics/Trust.lean#L30), [`KeyAdmits`](../TDN/Semantics/Trust.lean#L34), and [`scoped_keys_exclude_cross_domain`](../TDN/Semantics/Trust.lean#L36) give the corresponding equality-based key argument. The library treats issuer and key identities as supplied data. Certificate validation, possession of secrets, and correct ownership assignments require evidence or explicit implementation assumptions.

Direct imports: `Mathlib.Data.List.Basic`.

<details>
<summary>All 9 named declarations in Trust</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Identity`](../TDN/Semantics/Trust.lean#L5) |
| `def` | [`Admits`](../TDN/Semantics/Trust.lean#L10) |
| `def` | [`MutuallyAdmits`](../TDN/Semantics/Trust.lean#L13) |
| `def` | [`Scoped`](../TDN/Semantics/Trust.lean#L15) |
| `lemma` | [`admitted_domain_eq`](../TDN/Semantics/Trust.lean#L19) |
| `theorem` | [`scoped_authorities_exclude_cross_domain`](../TDN/Semantics/Trust.lean#L24) |
| `structure` | [`SharedKeyIdentity`](../TDN/Semantics/Trust.lean#L30) |
| `def` | [`KeyAdmits`](../TDN/Semantics/Trust.lean#L34) |
| `theorem` | [`scoped_keys_exclude_cross_domain`](../TDN/Semantics/Trust.lean#L36) |

</details>

### IKEContexts

Source: [IKEContexts.lean](../TDN/Semantics/IKEContexts.lean). Namespace: `TDN.IKEContexts`.

`IKEContexts` checks reciprocal observations of an IKE/CHILD-SA pair. [`Endpoint`](../TDN/Semantics/IKEContexts.lean#L5) stores identities, addresses, IKE SPIs, inbound/outbound SPIs, traffic-selector ranges, initiator role, and the PFS flag. [`Peer`](../TDN/Semantics/IKEContexts.lean#L23) checks that each observation matches the opposite direction of the other.

[`reciprocal_peers_agree_on_directional_record`](../TDN/Semantics/IKEContexts.lean#L48) proves agreement between the sender's [`sendName`](../TDN/Semantics/IKEContexts.lean#L40) and receiver's [`receiveName`](../TDN/Semantics/IKEContexts.lean#L44). [`reciprocal_peers_share_key_under_derivation_contract`](../TDN/Semantics/IKEContexts.lean#L53) applies a supplied premise that reciprocal peers derive matching keys. The second theorem explicitly depends on that key-derivation contract; the observed identifiers alone establish the directional record agreement.

Direct imports: `Mathlib.Data.List.Basic`.

<details>
<summary>All 6 named declarations in IKEContexts</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Endpoint`](../TDN/Semantics/IKEContexts.lean#L5) |
| `def` | [`Peer`](../TDN/Semantics/IKEContexts.lean#L23) |
| `def` | [`sendName`](../TDN/Semantics/IKEContexts.lean#L40) |
| `def` | [`receiveName`](../TDN/Semantics/IKEContexts.lean#L44) |
| `theorem` | [`reciprocal_peers_agree_on_directional_record`](../TDN/Semantics/IKEContexts.lean#L48) |
| `theorem` | [`reciprocal_peers_share_key_under_derivation_contract`](../TDN/Semantics/IKEContexts.lean#L53) |

Explicit instances:

- [Instance at line 36](../TDN/Semantics/IKEContexts.lean#L36)

</details>

### KeySources

Source: [KeySources.lean](../TDN/Semantics/KeySources.lean). Namespace: `TDN.KeySources`.

`KeySources` tracks how key-agreement participants were created. A participant originates either from an authenticated exchange or from pre-shared configuration. The configuration enables the pre-shared path only when both CAK and CKN are present.

[`executions_have_only_authenticated_sources`](../TDN/Semantics/KeySources.lean#L67) proves that every retained participant comes from an authenticated exchange when the pre-shared path is disabled and the execution starts empty. The model includes participant creation, removal, and unchanged progress steps. A concrete application must connect those permitted creation paths to the actual key-management implementation.

Direct imports: `Cslib.Foundations.Semantics.LTS.Basic`, `Mathlib.Data.List.Basic`.

<details>
<summary>All 11 named declarations in KeySources</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Config`](../TDN/Semantics/KeySources.lean#L6) |
| `def` | [`Config.preSharedEnabled`](../TDN/Semantics/KeySources.lean#L11) |
| `inductive` | [`Origin`](../TDN/Semantics/KeySources.lean#L14) |
| `structure` | [`Participant`](../TDN/Semantics/KeySources.lean#L19) |
| `abbrev` | [`State`](../TDN/Semantics/KeySources.lean#L24) |
| `inductive` | [`Action`](../TDN/Semantics/KeySources.lean#L26) |
| `inductive` | [`Step`](../TDN/Semantics/KeySources.lean#L32) |
| `def` | [`system`](../TDN/Semantics/KeySources.lean#L45) |
| `def` | [`OnlyAuthenticatedSources`](../TDN/Semantics/KeySources.lean#L47) |
| `lemma` | [`creation_preserves_authenticated_sources`](../TDN/Semantics/KeySources.lean#L50) |
| `theorem` | [`executions_have_only_authenticated_sources`](../TDN/Semantics/KeySources.lean#L67) |

</details>

### SequenceFreshness

Source: [SequenceFreshness.lean](../TDN/Semantics/SequenceFreshness.lean). Namespace: `TDN.SequenceFreshness`.

`SequenceFreshness` relates a packet number to a recent counter sample. [`Transmission`](../TDN/Semantics/SequenceFreshness.lean#L6) records association, generation, packet number, and send time. [`Sample`](../TDN/Semantics/SequenceFreshness.lean#L13) records the next packet number at a sampling time. [`CounterSampleValid`](../TDN/Semantics/SequenceFreshness.lean#L23) requires every earlier recorded transmission for the same counter to have a smaller number.

[`accepted_transmission_is_recent`](../TDN/Semantics/SequenceFreshness.lean#L30) derives an age bound when the counter sample is recent, its next number has been installed or exceeded, and the packet passes a zero-window replay test. The history-membership and counter-validity premises are explicit. [`installed_samples_have_matching_updates`](../TDN/Semantics/SequenceFreshness.lean#L51) uses `Admission` to require a matching earlier update for every admitted installation. The receive rule is a lower-bound check; the module does not implement a complete replay bitmap or counter-wrap protocol.

Direct imports: [Admission](#admission), `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 8 named declarations in SequenceFreshness</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Transmission`](../TDN/Semantics/SequenceFreshness.lean#L6) |
| `structure` | [`Sample`](../TDN/Semantics/SequenceFreshness.lean#L13) |
| `def` | [`SameCounter`](../TDN/Semantics/SequenceFreshness.lean#L20) |
| `def` | [`CounterSampleValid`](../TDN/Semantics/SequenceFreshness.lean#L23) |
| `def` | [`accepts`](../TDN/Semantics/SequenceFreshness.lean#L27) |
| `theorem` | [`accepted_transmission_is_recent`](../TDN/Semantics/SequenceFreshness.lean#L30) |
| `def` | [`InstallMatches`](../TDN/Semantics/SequenceFreshness.lean#L45) |
| `theorem` | [`installed_samples_have_matching_updates`](../TDN/Semantics/SequenceFreshness.lean#L51) |

</details>

### AccessControl

Source: [AccessControl.lean](../TDN/Semantics/AccessControl.lean). Namespace: `TDN.AccessControl`.

`AccessControl` authorizes a request using an authenticated certificate fingerprint, a role mapping, and exact method/path permissions. `Request.normalizedPath` is the path presented to the authorization function. [`authorize`](../TDN/Semantics/AccessControl.lean#L17) denies unknown fingerprints and otherwise checks for a matching permission.

[`authorized_request_has_permission`](../TDN/Semantics/AccessControl.lean#L24) recovers the matching role and permission from a successful decision. The denial theorems reject unmapped peers and absent paths. [`role_permission_restricts_operations`](../TDN/Semantics/AccessControl.lean#L54) lifts a check over a role's permission list to every authorized request. Authentication of the fingerprint and correct path normalization are inputs to the model.

Direct imports: `Mathlib.Data.List.Basic`.

<details>
<summary>All 7 named declarations in AccessControl</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Permission`](../TDN/Semantics/AccessControl.lean#L5) |
| `structure` | [`Request`](../TDN/Semantics/AccessControl.lean#L11) |
| `def` | [`authorize`](../TDN/Semantics/AccessControl.lean#L17) |
| `lemma` | [`authorized_request_has_permission`](../TDN/Semantics/AccessControl.lean#L24) |
| `theorem` | [`unmapped_peer_is_denied`](../TDN/Semantics/AccessControl.lean#L37) |
| `theorem` | [`absent_path_is_denied`](../TDN/Semantics/AccessControl.lean#L43) |
| `theorem` | [`role_permission_restricts_operations`](../TDN/Semantics/AccessControl.lean#L54) |

</details>

## Events and general trace arguments

[Admission](#admission), [TraceEvents](#traceevents), [TraceAccounting](#traceaccounting), [RestrictedExecution](#restrictedexecution)

### Admission

Source: [Admission.lean](../TDN/Semantics/Admission.lean). Namespace: `TDN.Admission`.

`Admission` defines a generic history in which selected events require a prior supporting event. `Step.record` adds a new event only if each triggered obligation has a matching event in the existing history. The trigger and matching relation are caller-supplied predicates.

[`all_admitted_events_have_prerequisites`](../TDN/Semantics/Admission.lean#L33) proves that every triggered event in a history reached from empty has a supporting event in the retained history. The transition rule enforces the prior-history condition. Timestamp ordering can be included in the supplied prerequisite relation when required.

Direct imports: `Cslib.Foundations.Semantics.LTS.Basic`.

<details>
<summary>All 5 named declarations in Admission</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`Step`](../TDN/Semantics/Admission.lean#L5) |
| `def` | [`lts`](../TDN/Semantics/Admission.lean#L11) |
| `def` | [`HasPrerequisites`](../TDN/Semantics/Admission.lean#L14) |
| `lemma` | [`step_preserves_prerequisites`](../TDN/Semantics/Admission.lean#L18) |
| `theorem` | [`all_admitted_events_have_prerequisites`](../TDN/Semantics/Admission.lean#L33) |

</details>

### TraceEvents

Source: [TraceEvents.lean](../TDN/Semantics/TraceEvents.lean). Namespace: `TDN.TraceEvents`.

`TraceEvents` finds a particular kind of step within a finite execution. [`Contains`](../TDN/Semantics/TraceEvents.lean#L5) decomposes the action list into an earlier trace, one witnessed step, and a later trace. The event predicate can inspect the states on both sides and the action itself.

[`changing_predicate_has_event`](../TDN/Semantics/TraceEvents.lean#L13) proves that a property holding initially and failing finally must be lost at some actual step. [`map_event`](../TDN/Semantics/TraceEvents.lean#L31) strengthens the description of an already located event using a one-step argument. The execution-event modules reuse those results to locate encryption and decryption operations.

Direct imports: `Cslib.Foundations.Semantics.LTS.Basic`.

<details>
<summary>All 3 named declarations in TraceEvents</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Contains`](../TDN/Semantics/TraceEvents.lean#L5) |
| `theorem` | [`changing_predicate_has_event`](../TDN/Semantics/TraceEvents.lean#L13) |
| `theorem` | [`map_event`](../TDN/Semantics/TraceEvents.lean#L31) |

</details>

### TraceAccounting

Source: [TraceAccounting.lean](../TDN/Semantics/TraceAccounting.lean). Namespace: `TDN.TraceAccounting`.

`TraceAccounting` adds a one-step arithmetic balance across a finite trace. The caller provides a natural-number state measure, a credit for each action, a debit for each action, and a balance equation for every permitted step.

[`trace_balance`](../TDN/Semantics/TraceAccounting.lean#L7) proves the complete-run balance. [`increase_requires_credit`](../TDN/Semantics/TraceAccounting.lean#L21) bounds the total increase by the sum of credits. `ExecutionHistory` instantiates the measure with envelope count and the credits/debits with encryption/decryption events. Other applications can reuse the same proofs with a different measure.

Direct imports: `Cslib.Foundations.Semantics.LTS.Basic`, `Mathlib.Data.List.Basic`, `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 2 named declarations in TraceAccounting</summary>

| Kind | Declaration |
| --- | --- |
| `theorem` | [`trace_balance`](../TDN/Semantics/TraceAccounting.lean#L7) |
| `theorem` | [`increase_requires_credit`](../TDN/Semantics/TraceAccounting.lean#L21) |

</details>

### RestrictedExecution

Source: [RestrictedExecution.lean](../TDN/Semantics/RestrictedExecution.lean). Namespace: `TDN.RestrictedExecution`.

`RestrictedExecution.within` retains only steps whose starting and ending states satisfy a supplied scope predicate. [`project_trace`](../TDN/Semantics/RestrictedExecution.lean#L8) proves that every restricted trace is also an original trace.

[`actual_event_in_scope`](../TDN/Semantics/RestrictedExecution.lean#L16) transfers an event witness to the original system and retains the scope conditions at the event's endpoints. Boundary-decryption proofs instantiate the predicate with membership in one component. A caller must separately establish that the execution being analyzed stays within that scope.

Direct imports: [TraceEvents](#traceevents).

<details>
<summary>All 3 named declarations in RestrictedExecution</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`within`](../TDN/Semantics/RestrictedExecution.lean#L5) |
| `theorem` | [`project_trace`](../TDN/Semantics/RestrictedExecution.lean#L8) |
| `theorem` | [`actual_event_in_scope`](../TDN/Semantics/RestrictedExecution.lean#L16) |

</details>

## Packet sizes and cover traffic

[PacketLength](#packetlength), [CoverTraffic](#covertraffic)

### PacketLength

Source: [PacketLength.lean](../TDN/Semantics/PacketLength.lean). Namespace: `TDN.PacketLength`.

`PacketLength` computes a wire length from payload bytes, trailer bytes, padding alignment, and fixed overhead. [`alignedWireLength`](../TDN/Semantics/PacketLength.lean#L7) rounds the payload plus trailer upward to an alignment boundary, then adds the fixed overhead.

[`aligned_wire_length_monotone`](../TDN/Semantics/PacketLength.lean#L10) proves that larger payloads cannot produce a smaller modeled wire length. [`all_sizes_fit_from_maximum`](../TDN/Semantics/PacketLength.lean#L19) therefore reduces a bound for every payload size to one check at the maximum. The caller supplies the actual overheads, MTU, and payload limit. A meaningful protocol application also uses a positive alignment and accounts for each encapsulation layer.

Direct imports: `Mathlib.Data.Nat.Basic`, `Mathlib.Order.Monotone.Defs`, `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 3 named declarations in PacketLength</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`alignedWireLength`](../TDN/Semantics/PacketLength.lean#L7) |
| `theorem` | [`aligned_wire_length_monotone`](../TDN/Semantics/PacketLength.lean#L10) |
| `theorem` | [`all_sizes_fit_from_maximum`](../TDN/Semantics/PacketLength.lean#L19) |

</details>

### CoverTraffic

Source: [CoverTraffic.lean](../TDN/Semantics/CoverTraffic.lean). Namespace: `TDN.CoverTraffic`.

`CoverTraffic` models a bounded packet queue serviced by scheduled transmission attempts. [`Config`](../TDN/Semantics/CoverTraffic.lean#L7) specifies record size, header size, queue limit, and interval. [`enqueue`](../TDN/Semantics/CoverTraffic.lean#L27) retains only nonempty packets that fit and arrive while the queue has room. A tick consumes the head or an empty payload, records an attempted padded length, advances the deadline, and increments the sequence.

[`all_executions_have_bounded_queues_and_fixed_records`](../TDN/Semantics/CoverTraffic.lean#L143) proves the queue bound and fixed attempted record size under a valid configuration. [`equal_schedule_gives_equal_size_observations`](../TDN/Semantics/CoverTraffic.lean#L149) proves equal time/size/success observations for two safe states when their attempt times and success flags already match. The schedule equality is a premise. The results do not guarantee periodic delivery by a real scheduler or hide losses, timing differences, or other traffic features.

Direct imports: `Cslib.Foundations.Semantics.LTS.Basic`, `Mathlib.Data.List.Basic`, `Lean.Elab.Tactic.Omega`.

<details>
<summary>All 23 named declarations in CoverTraffic</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Config`](../TDN/Semantics/CoverTraffic.lean#L7) |
| `def` | [`Config.Valid`](../TDN/Semantics/CoverTraffic.lean#L14) |
| `abbrev` | [`Packet`](../TDN/Semantics/CoverTraffic.lean#L21) |
| `def` | [`QueueValid`](../TDN/Semantics/CoverTraffic.lean#L23) |
| `def` | [`enqueue`](../TDN/Semantics/CoverTraffic.lean#L27) |
| `def` | [`payload`](../TDN/Semantics/CoverTraffic.lean#L31) |
| `def` | [`paddedBytes`](../TDN/Semantics/CoverTraffic.lean#L36) |
| `lemma` | [`padding_gives_fixed_length`](../TDN/Semantics/CoverTraffic.lean#L39) |
| `lemma` | [`enqueue_preserves_queue`](../TDN/Semantics/CoverTraffic.lean#L46) |
| `lemma` | [`tail_preserves_queue`](../TDN/Semantics/CoverTraffic.lean#L63) |
| `lemma` | [`payload_fits`](../TDN/Semantics/CoverTraffic.lean#L76) |
| `structure` | [`Attempt`](../TDN/Semantics/CoverTraffic.lean#L83) |
| `structure` | [`State`](../TDN/Semantics/CoverTraffic.lean#L89) |
| `def` | [`initial`](../TDN/Semantics/CoverTraffic.lean#L96) |
| `def` | [`nextDeadline`](../TDN/Semantics/CoverTraffic.lean#L98) |
| `lemma` | [`deadline_advances`](../TDN/Semantics/CoverTraffic.lean#L102) |
| `inductive` | [`Action`](../TDN/Semantics/CoverTraffic.lean#L107) |
| `inductive` | [`Step`](../TDN/Semantics/CoverTraffic.lean#L112) |
| `def` | [`system`](../TDN/Semantics/CoverTraffic.lean#L124) |
| `def` | [`Safe`](../TDN/Semantics/CoverTraffic.lean#L126) |
| `lemma` | [`step_preserves_size_and_capacity`](../TDN/Semantics/CoverTraffic.lean#L129) |
| `theorem` | [`all_executions_have_bounded_queues_and_fixed_records`](../TDN/Semantics/CoverTraffic.lean#L143) |
| `theorem` | [`equal_schedule_gives_equal_size_observations`](../TDN/Semantics/CoverTraffic.lean#L149) |

Explicit instances:

- [Instance at line 17](../TDN/Semantics/CoverTraffic.lean#L17)

</details>

## Native processing, source bytes, and boundary checks

### BinaryWire

Source: [BinaryWire.lean](../TDN/Semantics/BinaryWire.lean).

Converts integers to fixed-width bytes and reads integer fields back. The proofs require each value to fit its chosen width. These results support source headers, fragment fields and ESP headers without depending on a network configuration.

<details>
<summary>All 13 named declarations in BinaryWire</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`unsigned_accumulator`](../TDN/Semantics/BinaryWire.lean#L6) |
| `lemma` | [`unsigned_append`](../TDN/Semantics/BinaryWire.lean#L17) |
| `lemma` | [`unsigned_bound`](../TDN/Semantics/BinaryWire.lean#L23) |
| `lemma` | [`field_bound`](../TDN/Semantics/BinaryWire.lean#L33) |
| `def` | [`encodeUnsigned`](../TDN/Semantics/BinaryWire.lean#L42) |
| `lemma` | [`encodeUnsigned_length`](../TDN/Semantics/BinaryWire.lean#L46) |
| `theorem` | [`encodeUnsigned_decodes`](../TDN/Semantics/BinaryWire.lean#L52) |
| `theorem` | [`field_encoded_segment`](../TDN/Semantics/BinaryWire.lean#L71) |
| `lemma` | [`field_append_before`](../TDN/Semantics/BinaryWire.lean#L80) |
| `lemma` | [`field_append_after`](../TDN/Semantics/BinaryWire.lean#L88) |
| `lemma` | [`field_encodeUnsigned`](../TDN/Semantics/BinaryWire.lean#L93) |
| `lemma` | [`field_two_bytes`](../TDN/Semantics/BinaryWire.lean#L99) |
| `lemma` | [`decoded_fragment_offset_from_field`](../TDN/Semantics/BinaryWire.lean#L115) |

</details>

### BoundaryObservation

Source: [BoundaryObservation.lean](../TDN/Semantics/BoundaryObservation.lean).

Connects a packet observed at a physical boundary to the modeled operations that produced it. The outbound argument follows filtering, any selected IPsec operation, and routing until transmission is ready. The inbound argument requires a real modeled decryption step for the corresponding policy annotation. The caller supplies the configuration and a permitted native execution.

<details>
<summary>All 19 named declarations in BoundaryObservation</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`BoundaryPacket`](../TDN/Semantics/BoundaryObservation.lean#L6) |
| `lemma` | [`boundary_packet_keeps_endpoints`](../TDN/Semantics/BoundaryObservation.lean#L13) |
| `lemma` | [`IPsec_output_has_configured_outer_header`](../TDN/Semantics/BoundaryObservation.lean#L20) |
| `lemma` | [`IPsec_input_has_configured_outer_header`](../TDN/Semantics/BoundaryObservation.lean#L41) |
| `lemma` | [`outer_route_keeps_boundary_header`](../TDN/Semantics/BoundaryObservation.lean#L72) |
| `lemma` | [`wire_keeps_boundary_header`](../TDN/Semantics/BoundaryObservation.lean#L82) |
| `inductive` | [`OutboundSuffix`](../TDN/Semantics/BoundaryObservation.lean#L89) |
| `lemma` | [`outbound_suffix_has_ready_state`](../TDN/Semantics/BoundaryObservation.lean#L98) |
| `lemma` | [`outbound_suffix_is_native_execution`](../TDN/Semantics/BoundaryObservation.lean#L108) |
| `lemma` | [`IPsec_suffix_boundary_packet_uses_installed_policy`](../TDN/Semantics/BoundaryObservation.lean#L117) |
| `inductive` | [`FirstReadyRun`](../TDN/Semantics/BoundaryObservation.lean#L135) |
| `lemma` | [`first_ready_run_is_native_execution`](../TDN/Semantics/BoundaryObservation.lean#L144) |
| `lemma` | [`first_ready_run_finishes_ready`](../TDN/Semantics/BoundaryObservation.lean#L153) |
| `lemma` | [`first_ready_run_from_ready_is_identity`](../TDN/Semantics/BoundaryObservation.lean#L160) |
| `lemma` | [`dropped_state_has_no_first_ready_run`](../TDN/Semantics/BoundaryObservation.lean#L167) |
| `lemma` | [`first_ready_run_from_encapsulated_is_one_route`](../TDN/Semantics/BoundaryObservation.lean#L177) |
| `theorem` | [`first_ready_run_from_filtered_is_native_suffix`](../TDN/Semantics/BoundaryObservation.lean#L192) |
| `theorem` | [`outbound_policy_annotation_forces_actual_IPsec`](../TDN/Semantics/BoundaryObservation.lean#L210) |
| `theorem` | [`inbound_policy_annotation_requires_actual_decryption`](../TDN/Semantics/BoundaryObservation.lean#L225) |

</details>

### BytePartition

Source: [BytePartition.lean](../TDN/Semantics/BytePartition.lean).

Splits a byte list into bounded, nonempty pieces. The proofs show that concatenating the pieces restores the original bytes and that each piece respects the capacity. The supplied recursion bound must allow the complete input to be processed.

<details>
<summary>All 6 named declarations in BytePartition</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`bytePartition`](../TDN/Semantics/BytePartition.lean#L5) |
| `lemma` | [`byte_partition_nonempty`](../TDN/Semantics/BytePartition.lean#L11) |
| `lemma` | [`byte_partition_restores_bytes`](../TDN/Semantics/BytePartition.lean#L19) |
| `lemma` | [`byte_partition_piece_bound`](../TDN/Semantics/BytePartition.lean#L29) |
| `inductive` | [`BoundedPartition`](../TDN/Semantics/BytePartition.lean#L56) |
| `theorem` | [`byte_partition_is_bounded`](../TDN/Semantics/BytePartition.lean#L65) |

</details>

### CanonicalRootEncoding

Source: [CanonicalRootEncoding.lean](../TDN/Semantics/CanonicalRootEncoding.lean).

`canonicalRoot` reconstructs a representative source packet from a modeled frame. For IP traffic, the packet fields determine the network and transport headers, while the stored payload determines the application bytes. For Ethernet traffic, it rebuilds the Ethernet header and decodes the stored payload. The proof shows that the rebuilt packet satisfies the modeled decoding conditions and preserves the application bytes and original header identities. Reconstructed IPv4 identification and fragment flags are set to zero. The construction gives later byte-length proofs a source packet they can compute from the current frame.

<details>
<summary>All 6 named declarations in CanonicalRootEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`matched_transport_template`](../TDN/Semantics/CanonicalRootEncoding.lean#L7) |
| `def` | [`canonicalIPRoot`](../TDN/Semantics/CanonicalRootEncoding.lean#L36) |
| `theorem` | [`canonical_IP_root_decodes`](../TDN/Semantics/CanonicalRootEncoding.lean#L45) |
| `lemma` | [`matched_Ethernet_header_bounds`](../TDN/Semantics/CanonicalRootEncoding.lean#L113) |
| `def` | [`canonicalRoot`](../TDN/Semantics/CanonicalRootEncoding.lean#L134) |
| `theorem` | [`canonical_root_properties`](../TDN/Semantics/CanonicalRootEncoding.lean#L143) |

</details>

### DecodedHeaderProperties

Source: [DecodedHeaderProperties.lean](../TDN/Semantics/DecodedHeaderProperties.lean).

Extracts address, protocol, header-size and representability conditions from a decoded source datagram. The results let later proofs use the decoder conditions without inspecting the original byte list repeatedly.

<details>
<summary>All 3 named declarations in DecodedHeaderProperties</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`matched_network_header_properties`](../TDN/Semantics/DecodedHeaderProperties.lean#L5) |
| `lemma` | [`matched_transport_ICMP_representable`](../TDN/Semantics/DecodedHeaderProperties.lean#L45) |
| `theorem` | [`decoded_IP_header_properties`](../TDN/Semantics/DecodedHeaderProperties.lean#L62) |

</details>

### ESPWire

Source: [ESPWire.lean](../TDN/Semantics/ESPWire.lean).

Builds the modeled ESP header, IV, padding, trailer and protected bytes. The general proofs establish the exact encoded length and successful decoding after encoding. The caller supplies an encryption function together with proofs of its output length and successful decoding after encryption. Cryptographic secrecy and nonce freshness need separate arguments.

<details>
<summary>All 18 named declarations in ESPWire</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`GCMPrimitive`](../TDN/Semantics/ESPWire.lean#L9) |
| `def` | [`paddingLength`](../TDN/Semantics/ESPWire.lean#L19) |
| `lemma` | [`padding_length_bound`](../TDN/Semantics/ESPWire.lean#L22) |
| `lemma` | [`padded_length`](../TDN/Semantics/ESPWire.lean#L26) |
| `def` | [`padding`](../TDN/Semantics/ESPWire.lean#L32) |
| `lemma` | [`padding_length`](../TDN/Semantics/ESPWire.lean#L35) |
| `def` | [`protectedPlaintext`](../TDN/Semantics/ESPWire.lean#L39) |
| `lemma` | [`protected_plaintext_length`](../TDN/Semantics/ESPWire.lean#L43) |
| `def` | [`espAAD`](../TDN/Semantics/ESPWire.lean#L51) |
| `lemma` | [`aad_length`](../TDN/Semantics/ESPWire.lean#L54) |
| `def` | [`encodeESP`](../TDN/Semantics/ESPWire.lean#L58) |
| `def` | [`openESP`](../TDN/Semantics/ESPWire.lean#L65) |
| `lemma` | [`encoded_ESP_length`](../TDN/Semantics/ESPWire.lean#L69) |
| `lemma` | [`open_encoded_ESP`](../TDN/Semantics/ESPWire.lean#L78) |
| `def` | [`unpadESP`](../TDN/Semantics/ESPWire.lean#L104) |
| `lemma` | [`unpad_protected_plaintext`](../TDN/Semantics/ESPWire.lean#L111) |
| `def` | [`decodeESP`](../TDN/Semantics/ESPWire.lean#L150) |
| `theorem` | [`decode_encoded_ESP`](../TDN/Semantics/ESPWire.lean#L154) |

</details>

### EthernetHeaderEncoding

Source: [EthernetHeaderEncoding.lean](../TDN/Semantics/EthernetHeaderEncoding.lean).

Constructs Ethernet headers with supported VLAN tags. The matching theorem proves that the generated bytes contain the supplied addresses, EtherType and tag fields when those fields fit their encoded widths.

<details>
<summary>All 6 named declarations in EthernetHeaderEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`encodeVLANs`](../TDN/Semantics/EthernetHeaderEncoding.lean#L5) |
| `lemma` | [`encoded_VLAN_length`](../TDN/Semantics/EthernetHeaderEncoding.lean#L9) |
| `lemma` | [`encoded_VLAN_fields`](../TDN/Semantics/EthernetHeaderEncoding.lean#L15) |
| `def` | [`encodeEthernetHeader`](../TDN/Semantics/EthernetHeaderEncoding.lean#L42) |
| `lemma` | [`encoded_Ethernet_header_length`](../TDN/Semantics/EthernetHeaderEncoding.lean#L46) |
| `theorem` | [`encoded_Ethernet_header_matches`](../TDN/Semantics/EthernetHeaderEncoding.lean#L51) |

</details>

### EthernetSizeBudgets

Source: [EthernetSizeBudgets.lean](../TDN/Semantics/EthernetSizeBudgets.lean).

Preserves a plain Ethernet payload size bound across the supported native steps. Link and bridge conditions require a receiving interface to support the sending interface’s MTU. The supporting reassembly lemma recovers the payload bound from a valid single Ethernet frame.

<details>
<summary>All 5 named declarations in EthernetSizeBudgets</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`EthernetSizeBound`](../TDN/Semantics/EthernetSizeBudgets.lean#L8) |
| `structure` | [`EthernetMTUChecks`](../TDN/Semantics/EthernetSizeBudgets.lean#L12) |
| `lemma` | [`Ethernet_no_visible`](../TDN/Semantics/EthernetSizeBudgets.lean#L16) |
| `theorem` | [`native_step_preserves_Ethernet_size`](../TDN/Semantics/EthernetSizeBudgets.lean#L22) |
| `lemma` | [`Ethernet_reassembly_size`](../TDN/Semantics/EthernetSizeBudgets.lean#L67) |

</details>

### ForwardedDatagramEncoding

Source: [ForwardedDatagramEncoding.lean](../TDN/Semantics/ForwardedDatagramEncoding.lean).

Updates a source datagram header to reflect the hop limit after forwarding. The proofs retain the other modeled header fields and the source transport header. The serializer initializes fields outside the modeled comparison, including checksums; its matching claim follows the fields listed in the formal decoder.

<details>
<summary>All 5 named declarations in ForwardedDatagramEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`HeaderIdentity.actual_is_nominal_with_hop`](../TDN/Semantics/ForwardedDatagramEncoding.lean#L5) |
| `def` | [`forwardedNetworkHeader`](../TDN/Semantics/ForwardedDatagramEncoding.lean#L17) |
| `lemma` | [`forwarded_network_header_matches`](../TDN/Semantics/ForwardedDatagramEncoding.lean#L23) |
| `lemma` | [`forwarded_transport_header_matches`](../TDN/Semantics/ForwardedDatagramEncoding.lean#L62) |
| `lemma` | [`initial_forwarded_network_bytes`](../TDN/Semantics/ForwardedDatagramEncoding.lean#L71) |

</details>

### FragmentPlan

Source: [FragmentPlan.lean](../TDN/Semantics/FragmentPlan.lean).

Constructs fragment records from a bounded byte partition. The proofs account for offsets, nonempty pieces, alignment, total length and restoration of the original data. The caller supplies the fragment-header encoder and its field conditions.

<details>
<summary>All 8 named declarations in FragmentPlan</summary>

| Kind | Declaration |
| --- | --- |
| `abbrev` | [`FragmentHeaderEncoder`](../TDN/Semantics/FragmentPlan.lean#L6) |
| `def` | [`makeFragments`](../TDN/Semantics/FragmentPlan.lean#L8) |
| `lemma` | [`made_fragments_as_pieces`](../TDN/Semantics/FragmentPlan.lean#L16) |
| `structure` | [`FragmentPlanFacts`](../TDN/Semantics/FragmentPlan.lean#L24) |
| `theorem` | [`made_fragments_follow_plan`](../TDN/Semantics/FragmentPlan.lean#L33) |
| `lemma` | [`BoundedPartition.chunks_nonempty`](../TDN/Semantics/FragmentPlan.lean#L69) |
| `lemma` | [`BoundedPartition.restores_bytes`](../TDN/Semantics/FragmentPlan.lean#L74) |
| `theorem` | [`made_fragments_are_valid_pieces`](../TDN/Semantics/FragmentPlan.lean#L85) |

</details>

### HeaderedEvents

Source: [HeaderedEvents.lean](../TDN/Semantics/HeaderedEvents.lean).

Proves the order of Inner and Outer encryption while retaining the headers used by the actual modeled filters. A final two-layer stack identifies an earlier Inner encryption followed by an Outer encryption. The caller supplies the initial stack, placement conditions, and local header-processing conditions.

<details>
<summary>All 2 named declarations in HeaderedEvents</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`headered_encryption_output_layout`](../TDN/Semantics/HeaderedEvents.lean#L7) |
| `theorem` | [`headered_nested_stack_requires_ordered_encryptions`](../TDN/Semantics/HeaderedEvents.lean#L17) |

</details>

### HeaderedStack

Source: [HeaderedStack.lean](../TDN/Semantics/HeaderedStack.lean).

Maintains the expected encryption layers as packets move through routing, filtering, encapsulation and decryption. The argument uses the header currently visible to each operation. Checked local conditions and the initial invariant imply that every finite execution preserves the expected stack.

<details>
<summary>All 14 named declarations in HeaderedStack</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`HeaderIdentity.source`](../TDN/Semantics/HeaderedStack.lean#L6) |
| `lemma` | [`HeaderIdentity.destination`](../TDN/Semantics/HeaderedStack.lean#L11) |
| `lemma` | [`Frame.forwarded_visible`](../TDN/Semantics/HeaderedStack.lean#L16) |
| `lemma` | [`Frame.pop_visible`](../TDN/Semantics/HeaderedStack.lean#L26) |
| `abbrev` | [`withoutHeaderProcessing`](../TDN/Semantics/HeaderedStack.lean#L37) |
| `abbrev` | [`HeaderedLocalConditions`](../TDN/Semantics/HeaderedStack.lean#L39) |
| `lemma` | [`carrier_bodies_without_headers`](../TDN/Semantics/HeaderedStack.lean#L42) |
| `def` | [`HeaderedLocalHeader`](../TDN/Semantics/HeaderedStack.lean#L46) |
| `def` | [`HeaderedAcceptedHook`](../TDN/Semantics/HeaderedStack.lean#L50) |
| `def` | [`HeaderedStackInvariant`](../TDN/Semantics/HeaderedStack.lean#L57) |
| `lemma` | [`selected_associations_same_header`](../TDN/Semantics/HeaderedStack.lean#L78) |
| `lemma` | [`headered_hook_stack_effect`](../TDN/Semantics/HeaderedStack.lean#L85) |
| `lemma` | [`headered_step_preserves_stack`](../TDN/Semantics/HeaderedStack.lean#L106) |
| `theorem` | [`headered_executions_preserve_stack`](../TDN/Semantics/HeaderedStack.lean#L290) |

</details>

### HookPrograms

Source: [HookPrograms.lean](../TDN/Semantics/HookPrograms.lean).

Adds the actual receiving or sending interface to a rule program. The proofs show how the added interface conditions affect evaluation and preserve the corresponding native admission decision. A caller provides the original rules, interface names and interface context.

<details>
<summary>All 15 named declarations in HookPrograms</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Rule.withContext`](../TDN/Semantics/HookPrograms.lean#L5) |
| `def` | [`contextProgram`](../TDN/Semantics/HookPrograms.lean#L8) |
| `lemma` | [`context_rule_matches`](../TDN/Semantics/HookPrograms.lean#L11) |
| `theorem` | [`context_program_evaluation`](../TDN/Semantics/HookPrograms.lean#L20) |
| `lemma` | [`context_rule_requires_context`](../TDN/Semantics/HookPrograms.lean#L34) |
| `theorem` | [`context_program_rejects_wrong_context`](../TDN/Semantics/HookPrograms.lean#L40) |
| `def` | [`Program.withContext`](../TDN/Semantics/HookPrograms.lean#L59) |
| `lemma` | [`Program.context_evaluation`](../TDN/Semantics/HookPrograms.lean#L62) |
| `def` | [`IfacePolicy.withContext`](../TDN/Semantics/HookPrograms.lean#L68) |
| `def` | [`contextPolicies`](../TDN/Semantics/HookPrograms.lean#L72) |
| `lemma` | [`lookup_context_policies`](../TDN/Semantics/HookPrograms.lean#L76) |
| `theorem` | [`contextual_link_admission_preserves_actual_hook`](../TDN/Semantics/HookPrograms.lean#L90) |
| `def` | [`Config.withLinkContext`](../TDN/Semantics/HookPrograms.lean#L114) |
| `theorem` | [`link_context_preserves_native_admission`](../TDN/Semantics/HookPrograms.lean#L118) |
| `theorem` | [`link_context_preserves_native_step_admission`](../TDN/Semantics/HookPrograms.lean#L132) |

</details>

### IPFragmentation

Source: [IPFragmentation.lean](../TDN/Semantics/IPFragmentation.lean).

Chooses fragment capacities from the IP header size and MTU, then constructs IPv4 or IPv6 fragments. The reassembly theorem proves that the resulting fragments reconstruct the datagram within the supplied size and header conditions.

<details>
<summary>All 8 named declarations in IPFragmentation</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`fragmentHeaderSize`](../TDN/Semantics/IPFragmentation.lean#L9) |
| `def` | [`fragmentCapacity`](../TDN/Semantics/IPFragmentation.lean#L12) |
| `def` | [`encodeIPFragmentHeader`](../TDN/Semantics/IPFragmentation.lean#L15) |
| `lemma` | [`fragment_capacity_bounds`](../TDN/Semantics/IPFragmentation.lean#L21) |
| `theorem` | [`encoded_IP_fragment_is_valid`](../TDN/Semantics/IPFragmentation.lean#L36) |
| `def` | [`Datagram.fragmentIP`](../TDN/Semantics/IPFragmentation.lean#L104) |
| `theorem` | [`Datagram.fragment_IP_reassembles`](../TDN/Semantics/IPFragmentation.lean#L109) |
| `theorem` | [`Datagram.fragment_IP_reassembles_from_header`](../TDN/Semantics/IPFragmentation.lean#L137) |

</details>

### IPsecBodyShape

Source: [IPsecBodyShape.lean](../TDN/Semantics/IPsecBodyShape.lean).

Tracks whether a packet contains only the supported IPsec layers and a plain inner body. The preservation lemma rules out introducing unsupported MACsec or carrier wrappers when those mechanisms are absent from the supplied configuration.

<details>
<summary>All 3 named declarations in IPsecBodyShape</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Body.IPsecOnly`](../TDN/Semantics/IPsecBodyShape.lean#L5) |
| `lemma` | [`Config.visible_implies_body_header`](../TDN/Semantics/IPsecBodyShape.lean#L16) |
| `lemma` | [`step_preserves_IPsec_body_shape`](../TDN/Semantics/IPsecBodyShape.lean#L27) |

</details>

### IPsecFrameEncoding

Source: [IPsecFrameEncoding.lean](../TDN/Semantics/IPsecFrameEncoding.lean).

Serializes and decodes nested IPsec bodies while preserving their original payload and modeled headers. The reusable results connect the encoded byte length to the recursive IPsec size calculation. The caller supplies the encryption function and its required length and decoding properties, supported IPv4 tunnel parameters and coherent visible and hidden headers.

<details>
<summary>All 17 named declarations in IPsecFrameEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Parameters`](../TDN/Semantics/IPsecFrameEncoding.lean#L8) |
| `structure` | [`Codec`](../TDN/Semantics/IPsecFrameEncoding.lean#L15) |
| `def` | [`KnownIPv4Seal`](../TDN/Semantics/IPsecFrameEncoding.lean#L22) |
| `def` | [`nextHeader`](../TDN/Semantics/IPsecFrameEncoding.lean#L26) |
| `lemma` | [`next_header_bound`](../TDN/Semantics/IPsecFrameEncoding.lean#L31) |
| `def` | [`networkLength`](../TDN/Semantics/IPsecFrameEncoding.lean#L38) |
| `def` | [`leafNetwork`](../TDN/Semantics/IPsecFrameEncoding.lean#L44) |
| `def` | [`encodeBody`](../TDN/Semantics/IPsecFrameEncoding.lean#L48) |
| `def` | [`decodeBody`](../TDN/Semantics/IPsecFrameEncoding.lean#L63) |
| `def` | [`encodeFrame`](../TDN/Semantics/IPsecFrameEncoding.lean#L78) |
| `def` | [`decodeFrame`](../TDN/Semantics/IPsecFrameEncoding.lean#L82) |
| `lemma` | [`known_outer_header_size`](../TDN/Semantics/IPsecFrameEncoding.lean#L87) |
| `theorem` | [`initial_body_serialization`](../TDN/Semantics/IPsecFrameEncoding.lean#L100) |
| `lemma` | [`source_IP_body_from_original`](../TDN/Semantics/IPsecFrameEncoding.lean#L114) |
| `lemma` | [`ESP_network_length_at_least_inner`](../TDN/Semantics/IPsecFrameEncoding.lean#L126) |
| `theorem` | [`decode_encoded_body`](../TDN/Semantics/IPsecFrameEncoding.lean#L133) |
| `theorem` | [`encoded_body_network_length`](../TDN/Semantics/IPsecFrameEncoding.lean#L190) |

</details>

### IPsecInput

Source: [IPsecInput.lean](../TDN/Semantics/IPsecInput.lean).

Connects admitted decryption and subsequent routing to the installed IPsec policy and visible header. The lemmas retain endpoint addresses and authentication facts through the receiving path. They require coherent headers and the recorded policy, association and processing relations.

<details>
<summary>All 6 named declarations in IPsecInput</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`coherent_IPsec_visible_fields`](../TDN/Semantics/IPsecInput.lean#L5) |
| `def` | [`IPsecInputAtom`](../TDN/Semantics/IPsecInput.lean#L20) |
| `def` | [`IPsecInputPossible`](../TDN/Semantics/IPsecInput.lean#L33) |
| `lemma` | [`admitted_decryption_has_possible_rule`](../TDN/Semantics/IPsecInput.lean#L43) |
| `lemma` | [`coherent_same_body_has_same_visible_source`](../TDN/Semantics/IPsecInput.lean#L75) |
| `lemma` | [`ingress_route_detailed_authentication`](../TDN/Semantics/IPsecInput.lean#L96) |

Explicit instances:

- [Instance at line 29](../TDN/Semantics/IPsecInput.lean#L29)
- [Instance at line 38](../TDN/Semantics/IPsecInput.lean#L38)

</details>

### IPsecLinkEncoding

Source: [IPsecLinkEncoding.lean](../TDN/Semantics/IPsecLinkEncoding.lean).

`linkEncoding` gives a modeled frame an Ethernet representation. IP traffic receives an Ethernet header with the appropriate IPv4 or IPv6 EtherType and the bytes produced by the IPsec emission model. The Ethernet source and destination fields are zero placeholders. An existing Ethernet body retains its modeled header and payload. `encoded_link_describes_reachable_IPsec_frame` proves that the resulting header and byte layout describe a reachable frame, assuming source decoding, consistent headers and the established packet-size limits. That connection lets bridge-rule checks operate on the represented transmitted frame.

<details>
<summary>All 4 named declarations in IPsecLinkEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`IPLinkHeader`](../TDN/Semantics/IPsecLinkEncoding.lean#L7) |
| `def` | [`linkEncoding`](../TDN/Semantics/IPsecLinkEncoding.lean#L11) |
| `lemma` | [`IP_link_header_decoded`](../TDN/Semantics/IPsecLinkEncoding.lean#L21) |
| `theorem` | [`encoded_link_describes_reachable_IPsec_frame`](../TDN/Semantics/IPsecLinkEncoding.lean#L31) |

</details>

### IPsecOptionForms

Source: [IPsecOptionForms.lean](../TDN/Semantics/IPsecOptionForms.lean).

Extends the finite IPsec packet descriptions with IPv4-header options. Its matching lemma connects the resulting rule conditions to the packet fields. The supplied source, destination, interface and header-word values determine the supported packet class.

<details>
<summary>All 2 named declarations in IPsecOptionForms</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`IPsecForm.maskWithOptions`](../TDN/Semantics/IPsecOptionForms.lean#L5) |
| `lemma` | [`IPsecForm.maskWithOptions_matches`](../TDN/Semantics/IPsecOptionForms.lean#L10) |

</details>

### IPsecPacketForms

Source: [IPsecPacketForms.lean](../TDN/Semantics/IPsecPacketForms.lean).

Describes the supported ESP and UDP request/reply forms used in the boundary-rule proofs. Each form fixes its protocol, relevant ports and framing conditions. The proofs relate decoded packet bytes to those forms and their finite rule descriptions.

<details>
<summary>All 13 named declarations in IPsecPacketForms</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`IPsecForm`](../TDN/Semantics/IPsecPacketForms.lean#L6) |
| `def` | [`IPsecForm.all`](../TDN/Semantics/IPsecPacketForms.lean#L10) |
| `def` | [`IPsecForm.protocol`](../TDN/Semantics/IPsecPacketForms.lean#L12) |
| `def` | [`IPsecForm.sourcePort`](../TDN/Semantics/IPsecPacketForms.lean#L16) |
| `def` | [`IPsecForm.destinationPort`](../TDN/Semantics/IPsecPacketForms.lean#L21) |
| `def` | [`IPsecForm.requestFraming`](../TDN/Semantics/IPsecPacketForms.lean#L26) |
| `def` | [`IPsecForm.replyFraming`](../TDN/Semantics/IPsecPacketForms.lean#L30) |
| `def` | [`IPsecForm.Matches`](../TDN/Semantics/IPsecPacketForms.lean#L34) |
| `lemma` | [`request_framing_has_form`](../TDN/Semantics/IPsecPacketForms.lean#L41) |
| `lemma` | [`reply_framing_has_form`](../TDN/Semantics/IPsecPacketForms.lean#L58) |
| `lemma` | [`decoded_IPsec_has_form`](../TDN/Semantics/IPsecPacketForms.lean#L75) |
| `def` | [`IPsecForm.mask`](../TDN/Semantics/IPsecPacketForms.lean#L96) |
| `lemma` | [`IPsecForm.mask_matches`](../TDN/Semantics/IPsecPacketForms.lean#L105) |

</details>

### IPsecWireEmission

Source: [IPsecWireEmission.lean](../TDN/Semantics/IPsecWireEmission.lean).

Constructs the emitted datagram from the current plain or nested IPsec packet body. The proofs bind its raw length and visible header to the serializer, then establish reconstruction from the MTU-selected fragments. The result uses the same encryption primitive and field-comparison assumptions as the source and ESP encoders.

<details>
<summary>All 13 named declarations in IPsecWireEmission</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`protectedData`](../TDN/Semantics/IPsecWireEmission.lean#L8) |
| `def` | [`bareEmission`](../TDN/Semantics/IPsecWireEmission.lean#L16) |
| `def` | [`wireEmission`](../TDN/Semantics/IPsecWireEmission.lean#L36) |
| `lemma` | [`bare_emission_raw`](../TDN/Semantics/IPsecWireEmission.lean#L42) |
| `lemma` | [`wire_emission_raw`](../TDN/Semantics/IPsecWireEmission.lean#L49) |
| `lemma` | [`wire_emission_body`](../TDN/Semantics/IPsecWireEmission.lean#L58) |
| `lemma` | [`wire_emission_network`](../TDN/Semantics/IPsecWireEmission.lean#L67) |
| `lemma` | [`wire_Ethernet_size`](../TDN/Semantics/IPsecWireEmission.lean#L77) |
| `lemma` | [`wire_fitting_fragment_count`](../TDN/Semantics/IPsecWireEmission.lean#L83) |
| `lemma` | [`forwarded_header_unfragmented`](../TDN/Semantics/IPsecWireEmission.lean#L103) |
| `lemma` | [`bare_emission_IP_properties`](../TDN/Semantics/IPsecWireEmission.lean#L119) |
| `lemma` | [`reachable_visible_representable`](../TDN/Semantics/IPsecWireEmission.lean#L209) |
| `theorem` | [`wire_IP_reassembles`](../TDN/Semantics/IPsecWireEmission.lean#L242) |

</details>

### IPv4FragmentEncoding

Source: [IPv4FragmentEncoding.lean](../TDN/Semantics/IPv4FragmentEncoding.lean).

Constructs IPv4 fragment headers and proves their identification, offset, length and more-fragments fields. The theorem requires representable addresses and header values, valid fragment alignment and a bounded total length.

<details>
<summary>All 5 named declarations in IPv4FragmentEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`ipv4FragmentFlags`](../TDN/Semantics/IPv4FragmentEncoding.lean#L5) |
| `def` | [`encodeIPv4Fragment`](../TDN/Semantics/IPv4FragmentEncoding.lean#L8) |
| `lemma` | [`ipv4_fragment_flags_bound`](../TDN/Semantics/IPv4FragmentEncoding.lean#L13) |
| `theorem` | [`encoded_IPv4_fragment_fields`](../TDN/Semantics/IPv4FragmentEncoding.lean#L17) |
| `lemma` | [`encoded_IPv4_fragment_size`](../TDN/Semantics/IPv4FragmentEncoding.lean#L39) |

</details>

### IPv6FragmentEncoding

Source: [IPv6FragmentEncoding.lean](../TDN/Semantics/IPv6FragmentEncoding.lean).

Constructs the supported IPv6 base and fragment headers. The field theorem connects the encoded bytes to the next-header value, payload length, fragment offset and more-fragments bit under the supplied bounds.

<details>
<summary>All 4 named declarations in IPv6FragmentEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`fragmentMoreBit`](../TDN/Semantics/IPv6FragmentEncoding.lean#L5) |
| `def` | [`encodeIPv6FragmentHeader`](../TDN/Semantics/IPv6FragmentEncoding.lean#L7) |
| `lemma` | [`encoded_IPv6_fragment_header_length`](../TDN/Semantics/IPv6FragmentEncoding.lean#L15) |
| `theorem` | [`encoded_IPv6_fragment_fields`](../TDN/Semantics/IPv6FragmentEncoding.lean#L20) |

</details>

### KeyInterface

Source: [KeyInterface.lean](../TDN/Semantics/KeyInterface.lean).

Models a protected key store and its operations. The reusable proofs exclude forbidden key exports and require authorization for reads across every modeled execution. The caller supplies key confidentiality, principal permissions and an initial safe store. Applying the results to a token requires correspondence with its actual interfaces.

<details>
<summary>All 13 named declarations in KeyInterface</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Object`](../TDN/Semantics/KeyInterface.lean#L5) |
| `def` | [`Object.Restricted`](../TDN/Semantics/KeyInterface.lean#L12) |
| `def` | [`StoreSafe`](../TDN/Semantics/KeyInterface.lean#L15) |
| `inductive` | [`Event`](../TDN/Semantics/KeyInterface.lean#L18) |
| `inductive` | [`Action`](../TDN/Semantics/KeyInterface.lean#L23) |
| `def` | [`Action.events`](../TDN/Semantics/KeyInterface.lean#L34) |
| `inductive` | [`Step`](../TDN/Semantics/KeyInterface.lean#L41) |
| `def` | [`system`](../TDN/Semantics/KeyInterface.lean#L69) |
| `lemma` | [`step_preserves_store`](../TDN/Semantics/KeyInterface.lean#L74) |
| `lemma` | [`step_export_impossible`](../TDN/Semantics/KeyInterface.lean#L101) |
| `lemma` | [`step_read_authorized`](../TDN/Semantics/KeyInterface.lean#L127) |
| `theorem` | [`protected_exports_impossible`](../TDN/Semantics/KeyInterface.lean#L144) |
| `theorem` | [`all_reads_authorized`](../TDN/Semantics/KeyInterface.lean#L160) |

</details>

### LinkAdmission

Source: [LinkAdmission.lean](../TDN/Semantics/LinkAdmission.lean).

Represents ordered link-layer filtering at a named input or output interface. A frame record connects Ethernet bytes, IP fields and MACsec framing to a modeled body. Admission requires a present interface policy and acceptance by the selected directional program.

<details>
<summary>All 12 named declarations in LinkAdmission</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Program`](../TDN/Semantics/LinkAdmission.lean#L5) |
| `structure` | [`IfacePolicy`](../TDN/Semantics/LinkAdmission.lean#L10) |
| `def` | [`Program.Accepts`](../TDN/Semantics/LinkAdmission.lean#L15) |
| `structure` | [`Frame`](../TDN/Semantics/LinkAdmission.lean#L18) |
| `def` | [`Frame.Packet`](../TDN/Semantics/LinkAdmission.lean#L24) |
| `def` | [`Frame.Decoded`](../TDN/Semantics/LinkAdmission.lean#L32) |
| `def` | [`MACsecFraming`](../TDN/Semantics/LinkAdmission.lean#L35) |
| `def` | [`Frame.DescribesBody`](../TDN/Semantics/LinkAdmission.lean#L45) |
| `def` | [`lookup`](../TDN/Semantics/LinkAdmission.lean#L55) |
| `def` | [`Admitted`](../TDN/Semantics/LinkAdmission.lean#L58) |
| `def` | [`payloadCode`](../TDN/Semantics/LinkAdmission.lean#L73) |
| `def` | [`Frame.Describes`](../TDN/Semantics/LinkAdmission.lean#L76) |

Explicit instances:

- [Instance at line 41](../TDN/Semantics/LinkAdmission.lean#L41)
- [Instance at line 63](../TDN/Semantics/LinkAdmission.lean#L63)
- [Instance at line 68](../TDN/Semantics/LinkAdmission.lean#L68)

</details>

### LocalAddressProjection

Source: [LocalAddressProjection.lean](../TDN/Semantics/LocalAddressProjection.lean).

Replaces the local-address predicate in an execution configuration and proves which policy decisions remain unchanged. The proofs make their equality conditions explicit for the packet and input, forwarding or output decision in question.

<details>
<summary>All 6 named declarations in LocalAddressProjection</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Config.withLocalAddresses`](../TDN/Semantics/LocalAddressProjection.lean#L5) |
| `lemma` | [`local_address_projection_preserves_policy_packet`](../TDN/Semantics/LocalAddressProjection.lean#L8) |
| `lemma` | [`local_address_projection_preserves_input_admission`](../TDN/Semantics/LocalAddressProjection.lean#L13) |
| `lemma` | [`local_address_projection_preserves_forward_decision`](../TDN/Semantics/LocalAddressProjection.lean#L19) |
| `lemma` | [`local_address_projection_preserves_input_decision`](../TDN/Semantics/LocalAddressProjection.lean#L30) |
| `lemma` | [`local_address_projection_preserves_output_decision`](../TDN/Semantics/LocalAddressProjection.lean#L41) |

</details>

### MultiProtocolHeaders

Source: [MultiProtocolHeaders.lean](../TDN/Semantics/MultiProtocolHeaders.lean).

Tracks the visible and hidden headers through forwarding, IPsec, MACsec and carrier operations. The step lemma proves header consistency for one operation, and the execution theorem extends that result to any finite run. Generated header bounds and initial header consistency remain required inputs.

<details>
<summary>All 18 named declarations in MultiProtocolHeaders</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`HeaderIdentity.decrement`](../TDN/Semantics/MultiProtocolHeaders.lean#L5) |
| `lemma` | [`Body.coherent_visible`](../TDN/Semantics/MultiProtocolHeaders.lean#L12) |
| `lemma` | [`Body.coherent_set_active`](../TDN/Semantics/MultiProtocolHeaders.lean#L19) |
| `lemma` | [`Frame.coherent_visible`](../TDN/Semantics/MultiProtocolHeaders.lean#L27) |
| `lemma` | [`Frame.forwarded_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L39) |
| `lemma` | [`Frame.push_ipsec_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L49) |
| `lemma` | [`Frame.push_carrier_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L56) |
| `lemma` | [`Frame.push_macsec_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L63) |
| `lemma` | [`Frame.pop_ipsec_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L68) |
| `lemma` | [`Frame.pop_macsec_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L76) |
| `lemma` | [`Frame.pop_carrier_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L84) |
| `lemma` | [`unwrap_carrier_has_body`](../TDN/Semantics/MultiProtocolHeaders.lean#L92) |
| `def` | [`HeaderBounds`](../TDN/Semantics/MultiProtocolHeaders.lean#L110) |
| `lemma` | [`step_preserves_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L113) |
| `theorem` | [`all_executions_preserve_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L156) |
| `lemma` | [`field_byte_bound`](../TDN/Semantics/MultiProtocolHeaders.lean#L170) |
| `lemma` | [`matched_network_hop_bound`](../TDN/Semantics/MultiProtocolHeaders.lean#L181) |
| `lemma` | [`decoded_source_headers`](../TDN/Semantics/MultiProtocolHeaders.lean#L192) |

</details>

### MultiProtocolIdentity

Source: [MultiProtocolIdentity.lean](../TDN/Semantics/MultiProtocolIdentity.lean).

Shows that the original packet header survives modeled wrapping, unwrapping and forwarding. The single-step result is lifted to every finite execution. The result concerns the original header retained by the model.

<details>
<summary>All 3 named declarations in MultiProtocolIdentity</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`unwrap_preserves_original_header`](../TDN/Semantics/MultiProtocolIdentity.lean#L6) |
| `lemma` | [`step_preserves_original_header`](../TDN/Semantics/MultiProtocolIdentity.lean#L19) |
| `theorem` | [`all_executions_preserve_original_header`](../TDN/Semantics/MultiProtocolIdentity.lean#L27) |

</details>

### MultiProtocolIfaces

Source: [MultiProtocolIfaces.lean](../TDN/Semantics/MultiProtocolIfaces.lean).

Keeps every reachable packet state within an explicit interface inventory. Local conditions cover each possible interface change. The general execution theorem reuses those conditions across any finite run.

<details>
<summary>All 3 named declarations in MultiProtocolIfaces</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`IfaceConditions`](../TDN/Semantics/MultiProtocolIfaces.lean#L5) |
| `lemma` | [`step_preserves_iface_inventory`](../TDN/Semantics/MultiProtocolIfaces.lean#L16) |
| `theorem` | [`all_executions_stay_in_iface_inventory`](../TDN/Semantics/MultiProtocolIfaces.lean#L46) |

</details>

### NativeAdmission

Source: [NativeAdmission.lean](../TDN/Semantics/NativeAdmission.lean).

Provides decidability instances for concrete rule acceptance and association-to-policy binding. The instances let Lean compute these finite conditions when a network application supplies concrete records.

<details>
<summary>All 0 named declarations in NativeAdmission</summary>

| Kind | Declaration |
| --- | --- |

Explicit instances:

- [Instance at line 5](../TDN/Semantics/NativeAdmission.lean#L5)
- [Instance at line 10](../TDN/Semantics/NativeAdmission.lean#L10)

</details>

### NativeHookFacts

Source: [NativeHookFacts.lean](../TDN/Semantics/NativeHookFacts.lean).

Preserves interface, source-address and authentication facts between arrival, route selection and filtering. Several lemmas show that route and association choices depend on the specified address fields. These facts connect finite rule checks to arbitrary eligible packets.

<details>
<summary>All 8 named declarations in NativeHookFacts</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`ingress_has_native_ifaces`](../TDN/Semantics/NativeHookFacts.lean#L6) |
| `lemma` | [`route_from_ingress_preserves_local_state`](../TDN/Semantics/NativeHookFacts.lean#L15) |
| `lemma` | [`association_matches_depends_on_addresses`](../TDN/Semantics/NativeHookFacts.lean#L29) |
| `lemma` | [`selected_associations_depend_on_addresses`](../TDN/Semantics/NativeHookFacts.lean#L35) |
| `lemma` | [`selected_route_depends_on_destination`](../TDN/Semantics/NativeHookFacts.lean#L42) |
| `def` | [`addressPoint`](../TDN/Semantics/NativeHookFacts.lean#L48) |
| `lemma` | [`decrypted_route_has_authentication`](../TDN/Semantics/NativeHookFacts.lean#L53) |
| `lemma` | [`ingress_route_authentication`](../TDN/Semantics/NativeHookFacts.lean#L61) |

</details>

### NativeSizeBudgets

Source: [NativeSizeBudgets.lean](../TDN/Semantics/NativeSizeBudgets.lean).

States the size conditions needed at each packet-processing phase. Its main theorem proves that one permitted native step preserves those conditions. The proof accounts for source datagrams, ordered filtering, route selection, successful decryption and the length added by nested ESP.

<details>
<summary>All 13 named declarations in NativeSizeBudgets</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`BodySizeBudget`](../TDN/Semantics/NativeSizeBudgets.lean#L9) |
| `lemma` | [`body_budget_has_length`](../TDN/Semantics/NativeSizeBudgets.lean#L19) |
| `lemma` | [`decoded_source_body_budget`](../TDN/Semantics/NativeSizeBudgets.lean#L48) |
| `def` | [`AuthenticationSizeBound`](../TDN/Semantics/NativeSizeBudgets.lean#L62) |
| `def` | [`FilteredSizeBound`](../TDN/Semantics/NativeSizeBudgets.lean#L67) |
| `def` | [`SizeRouted`](../TDN/Semantics/NativeSizeBudgets.lean#L75) |
| `def` | [`ReadySizeBound`](../TDN/Semantics/NativeSizeBudgets.lean#L80) |
| `def` | [`SizeInvariant`](../TDN/Semantics/NativeSizeBudgets.lean#L86) |
| `structure` | [`SizeChecks`](../TDN/Semantics/NativeSizeBudgets.lean#L105) |
| `lemma` | [`filtered_size_from_checks`](../TDN/Semantics/NativeSizeBudgets.lean#L138) |
| `lemma` | [`authentication_bound_empty`](../TDN/Semantics/NativeSizeBudgets.lean#L191) |
| `lemma` | [`size_ready_if_not_required`](../TDN/Semantics/NativeSizeBudgets.lean#L196) |
| `theorem` | [`native_step_preserves_size_budget`](../TDN/Semantics/NativeSizeBudgets.lean#L204) |

</details>

### OrderedSizeGuards

Source: [OrderedSizeGuards.lean](../TDN/Semantics/OrderedSizeGuards.lean).

Derives size bounds from ordered firewall rules. A bound can come from the accepting rule, an earlier oversized-packet denial, or the size established by authenticated decryption. The program theorem proves the bound for every accepted packet under its explicit route and policy conditions.

<details>
<summary>All 9 named declarations in OrderedSizeGuards</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`EarlierSizeGuard`](../TDN/Semantics/OrderedSizeGuards.lean#L5) |
| `def` | [`SizeBoundAtom`](../TDN/Semantics/OrderedSizeGuards.lean#L16) |
| `def` | [`RuleSizeBound`](../TDN/Semantics/OrderedSizeGuards.lean#L26) |
| `def` | [`RouteExcludesPolicy`](../TDN/Semantics/OrderedSizeGuards.lean#L38) |
| `lemma` | [`route_and_policy_overlap`](../TDN/Semantics/OrderedSizeGuards.lean#L45) |
| `lemma` | [`checked_rule_size_bound`](../TDN/Semantics/OrderedSizeGuards.lean#L51) |
| `def` | [`SizedRuleCheck`](../TDN/Semantics/OrderedSizeGuards.lean#L89) |
| `def` | [`SizedProgramChecks`](../TDN/Semantics/OrderedSizeGuards.lean#L99) |
| `theorem` | [`checked_program_size_bounds`](../TDN/Semantics/OrderedSizeGuards.lean#L127) |

Explicit instances:

- [Instance at line 10](../TDN/Semantics/OrderedSizeGuards.lean#L10)
- [Instance at line 21](../TDN/Semantics/OrderedSizeGuards.lean#L21)
- [Instance at line 31](../TDN/Semantics/OrderedSizeGuards.lean#L31)
- [Instance at line 41](../TDN/Semantics/OrderedSizeGuards.lean#L41)
- [Instance at line 108](../TDN/Semantics/OrderedSizeGuards.lean#L108)
- [Instance at line 115](../TDN/Semantics/OrderedSizeGuards.lean#L115)

</details>

### PacketHeaderEncoding

Source: [PacketHeaderEncoding.lean](../TDN/Semantics/PacketHeaderEncoding.lean).

Constructs the modeled IPv4, IPv6, UDP, TCP and ICMP header fields and proves that the decoder reads them back. Width and length bounds prevent truncation. Checksums and unused fields are initialized to zero, and the matching condition covers the listed field comparisons and sizes. Protocol checksum validation remains separate.

<details>
<summary>All 17 named declarations in PacketHeaderEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`encodeIPv4Header`](../TDN/Semantics/PacketHeaderEncoding.lean#L5) |
| `lemma` | [`encoded_IPv4_header_length`](../TDN/Semantics/PacketHeaderEncoding.lean#L15) |
| `theorem` | [`encoded_IPv4_header_matches`](../TDN/Semantics/PacketHeaderEncoding.lean#L22) |
| `def` | [`encodeIPv6Header`](../TDN/Semantics/PacketHeaderEncoding.lean#L42) |
| `lemma` | [`encoded_IPv6_header_length`](../TDN/Semantics/PacketHeaderEncoding.lean#L47) |
| `theorem` | [`encoded_IPv6_header_matches`](../TDN/Semantics/PacketHeaderEncoding.lean#L51) |
| `def` | [`encodeUDPHeader`](../TDN/Semantics/PacketHeaderEncoding.lean#L68) |
| `lemma` | [`encoded_UDP_header_length`](../TDN/Semantics/PacketHeaderEncoding.lean#L72) |
| `theorem` | [`encoded_UDP_header_matches`](../TDN/Semantics/PacketHeaderEncoding.lean#L76) |
| `def` | [`encodeICMPHeader`](../TDN/Semantics/PacketHeaderEncoding.lean#L87) |
| `lemma` | [`encoded_ICMP_header_length`](../TDN/Semantics/PacketHeaderEncoding.lean#L90) |
| `theorem` | [`encoded_ICMP_header_matches`](../TDN/Semantics/PacketHeaderEncoding.lean#L94) |
| `def` | [`encodeTCPHeader`](../TDN/Semantics/PacketHeaderEncoding.lean#L107) |
| `lemma` | [`encoded_TCP_header_length`](../TDN/Semantics/PacketHeaderEncoding.lean#L113) |
| `theorem` | [`encoded_TCP_header_matches`](../TDN/Semantics/PacketHeaderEncoding.lean#L118) |
| `lemma` | [`encoded_IPv4_flags`](../TDN/Semantics/PacketHeaderEncoding.lean#L142) |
| `lemma` | [`encoded_IPv4_identity`](../TDN/Semantics/PacketHeaderEncoding.lean#L148) |

</details>

### PacketProcessing

Source: [PacketProcessing.lean](../TDN/Semantics/PacketProcessing.lean).

Defines raw packet decoding, IP and link-layer filter contexts, and the observed processing inventory. The inventory records interface names, header generation and supported encryption-size or encapsulation settings. These definitions state the conditions needed to connect byte observations with packet-processing proofs.

<details>
<summary>All 38 named declarations in PacketProcessing</summary>

| Kind | Declaration |
| --- | --- |
| `inductive` | [`Hook`](../TDN/Semantics/PacketProcessing.lean#L6) |
| `inductive` | [`RawPacket`](../TDN/Semantics/PacketProcessing.lean#L10) |
| `def` | [`RawPacket.Bytes`](../TDN/Semantics/PacketProcessing.lean#L15) |
| `def` | [`RawPacket.Decoded`](../TDN/Semantics/PacketProcessing.lean#L19) |
| `def` | [`RawPacket.Complete`](../TDN/Semantics/PacketProcessing.lean#L36) |
| `def` | [`RawPacket.Fragment`](../TDN/Semantics/PacketProcessing.lean#L45) |
| `inductive` | [`DecodeOutcome`](../TDN/Semantics/PacketProcessing.lean#L56) |
| `def` | [`DecodeOutcome.Valid`](../TDN/Semantics/PacketProcessing.lean#L60) |
| `def` | [`Ingress`](../TDN/Semantics/PacketProcessing.lean#L67) |
| `def` | [`inputPacket`](../TDN/Semantics/PacketProcessing.lean#L72) |
| `def` | [`InputAdmitted`](../TDN/Semantics/PacketProcessing.lean#L77) |
| `structure` | [`Context`](../TDN/Semantics/PacketProcessing.lean#L83) |
| `def` | [`Context.Packet`](../TDN/Semantics/PacketProcessing.lean#L90) |
| `def` | [`Context.AtHook`](../TDN/Semantics/PacketProcessing.lean#L98) |
| `structure` | [`LinkContext`](../TDN/Semantics/PacketProcessing.lean#L118) |
| `structure` | [`CarrierEncoding`](../TDN/Semantics/PacketProcessing.lean#L124) |
| `def` | [`CarrierEncoding.header`](../TDN/Semantics/PacketProcessing.lean#L130) |
| `def` | [`CarrierEncoding.session`](../TDN/Semantics/PacketProcessing.lean#L133) |
| `def` | [`carrierNetworkOrder`](../TDN/Semantics/PacketProcessing.lean#L136) |
| `def` | [`CarrierEncoding.Valid`](../TDN/Semantics/PacketProcessing.lean#L139) |
| `structure` | [`CarrierBinding`](../TDN/Semantics/PacketProcessing.lean#L151) |
| `structure` | [`MKAEndpoint`](../TDN/Semantics/PacketProcessing.lean#L159) |
| `structure` | [`IPsecSizeBinding`](../TDN/Semantics/PacketProcessing.lean#L166) |
| `def` | [`IPsecSizeBinding.EncodedSize`](../TDN/Semantics/PacketProcessing.lean#L172) |
| `def` | [`IPsecSizeBinding.Valid`](../TDN/Semantics/PacketProcessing.lean#L175) |
| `structure` | [`Inventory`](../TDN/Semantics/PacketProcessing.lean#L185) |
| `inductive` | [`UDPMode`](../TDN/Semantics/PacketProcessing.lean#L194) |
| `structure` | [`UDPBinding`](../TDN/Semantics/PacketProcessing.lean#L198) |
| `def` | [`UDPBinding.Tuple`](../TDN/Semantics/PacketProcessing.lean#L215) |
| `def` | [`UDPBinding.Framing`](../TDN/Semantics/PacketProcessing.lean#L220) |
| `def` | [`UDPBinding.WellFormed`](../TDN/Semantics/PacketProcessing.lean#L229) |
| `def` | [`words16`](../TDN/Semantics/PacketProcessing.lean#L258) |
| `def` | [`ChecksumValid`](../TDN/Semantics/PacketProcessing.lean#L263) |
| `def` | [`networkOrder`](../TDN/Semantics/PacketProcessing.lean#L266) |
| `def` | [`pseudoHeader`](../TDN/Semantics/PacketProcessing.lean#L269) |
| `def` | [`optionsValid`](../TDN/Semantics/PacketProcessing.lean#L277) |
| `def` | [`IPv4OptionsValid`](../TDN/Semantics/PacketProcessing.lean#L287) |
| `def` | [`RawPacket.PreHookValid`](../TDN/Semantics/PacketProcessing.lean#L290) |

Explicit instances:

- [Instance at line 147](../TDN/Semantics/PacketProcessing.lean#L147)
- [Instance at line 181](../TDN/Semantics/PacketProcessing.lean#L181)
- [Instance at line 243](../TDN/Semantics/PacketProcessing.lean#L243)
- [Instance at line 248](../TDN/Semantics/PacketProcessing.lean#L248)
- [Instance at line 253](../TDN/Semantics/PacketProcessing.lean#L253)
- [Instance at line 310](../TDN/Semantics/PacketProcessing.lean#L310)
- [Instance at line 315](../TDN/Semantics/PacketProcessing.lean#L315)
- [Instance at line 318](../TDN/Semantics/PacketProcessing.lean#L318)
- [Instance at line 322](../TDN/Semantics/PacketProcessing.lean#L322)
- [Instance at line 326](../TDN/Semantics/PacketProcessing.lean#L326)

</details>

### PacketSource

Source: [PacketSource.lean](../TDN/Semantics/PacketSource.lean).

Defines an application request, its network and transport headers, emitted datagrams, fragments and possible source errors. The validity conditions require correct header fields, payload preservation and reconstruction from fragments. A concrete source processor must prove those conditions for all its outcomes. Header validity also requires that hop limits and protocol fields fit their encoded widths, that IPv6 next-header metadata agrees with the selected protocol, and that ICMP has no synthetic transport ports.

<details>
<summary>All 35 named declarations in PacketSource</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`unsigned`](../TDN/Semantics/PacketSource.lean#L6) |
| `def` | [`field`](../TDN/Semantics/PacketSource.lean#L9) |
| `def` | [`protocolNumber`](../TDN/Semantics/PacketSource.lean#L12) |
| `inductive` | [`Mode`](../TDN/Semantics/PacketSource.lean#L19) |
| `structure` | [`Request`](../TDN/Semantics/PacketSource.lean#L24) |
| `def` | [`Request.Overhead`](../TDN/Semantics/PacketSource.lean#L34) |
| `def` | [`HeaderRepresentable`](../TDN/Semantics/PacketSource.lean#L37) |
| `def` | [`Request.HeadersRepresentable`](../TDN/Semantics/PacketSource.lean#L44) |
| `def` | [`Request.TemplateValid`](../TDN/Semantics/PacketSource.lean#L49) |
| `def` | [`Request.PayloadMatches`](../TDN/Semantics/PacketSource.lean#L72) |
| `def` | [`Request.ProtocolLimit`](../TDN/Semantics/PacketSource.lean#L78) |
| `def` | [`Request.PacketSize`](../TDN/Semantics/PacketSource.lean#L84) |
| `def` | [`Request.MtuOverhead`](../TDN/Semantics/PacketSource.lean#L87) |
| `def` | [`Request.MtuBytes`](../TDN/Semantics/PacketSource.lean#L92) |
| `def` | [`NetworkHeaderMatches`](../TDN/Semantics/PacketSource.lean#L95) |
| `def` | [`TransportHeaderMatches`](../TDN/Semantics/PacketSource.lean#L114) |
| `def` | [`EthernetHeaderMatches`](../TDN/Semantics/PacketSource.lean#L126) |
| `structure` | [`Fragment`](../TDN/Semantics/PacketSource.lean#L135) |
| `def` | [`Fragment.Raw`](../TDN/Semantics/PacketSource.lean#L141) |
| `def` | [`Fragment.MtuBytes`](../TDN/Semantics/PacketSource.lean#L144) |
| `def` | [`Fragment.AsPiece`](../TDN/Semantics/PacketSource.lean#L149) |
| `def` | [`Fragment.IPv4Fields`](../TDN/Semantics/PacketSource.lean#L152) |
| `def` | [`Fragment.IPv6Fields`](../TDN/Semantics/PacketSource.lean#L160) |
| `structure` | [`Datagram`](../TDN/Semantics/PacketSource.lean#L174) |
| `def` | [`Datagram.Data`](../TDN/Semantics/PacketSource.lean#L181) |
| `def` | [`Datagram.Raw`](../TDN/Semantics/PacketSource.lean#L184) |
| `def` | [`Datagram.MtuBytes`](../TDN/Semantics/PacketSource.lean#L187) |
| `def` | [`Datagram.Decoded`](../TDN/Semantics/PacketSource.lean#L192) |
| `def` | [`Datagram.HeaderFrom`](../TDN/Semantics/PacketSource.lean#L206) |
| `def` | [`Datagram.Reassembles`](../TDN/Semantics/PacketSource.lean#L219) |
| `def` | [`Datagram.ValidFor`](../TDN/Semantics/PacketSource.lean#L241) |
| `inductive` | [`Error`](../TDN/Semantics/PacketSource.lean#L252) |
| `inductive` | [`Outcome`](../TDN/Semantics/PacketSource.lean#L256) |
| `def` | [`Outcome.Valid`](../TDN/Semantics/PacketSource.lean#L260) |
| `structure` | [`Processing`](../TDN/Semantics/PacketSource.lean#L277) |

</details>

### PayloadEncoding

Source: [PayloadEncoding.lean](../TDN/Semantics/PayloadEncoding.lean).

Encodes payload bytes as a natural number and proves that distinct byte lists remain distinguishable. The decoding theorem recovers the original bytes. These results connect symbolic packet identity to the bytes stored in a frame observation.

<details>
<summary>All 8 named declarations in PayloadEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`payloadCode_concat`](../TDN/Semantics/PayloadEncoding.lean#L6) |
| `lemma` | [`payloadCode_as_digits`](../TDN/Semantics/PayloadEncoding.lean#L10) |
| `lemma` | [`digits_payloadCode`](../TDN/Semantics/PayloadEncoding.lean#L17) |
| `theorem` | [`payloadCode_injective`](../TDN/Semantics/PayloadEncoding.lean#L29) |
| `lemma` | [`Frame.Describes.plain_Ethernet_payload`](../TDN/Semantics/PayloadEncoding.lean#L43) |
| `lemma` | [`Frame.Describes.plain_IP_payload`](../TDN/Semantics/PayloadEncoding.lean#L51) |
| `def` | [`decodePayload`](../TDN/Semantics/PayloadEncoding.lean#L65) |
| `lemma` | [`decodePayload_payloadCode`](../TDN/Semantics/PayloadEncoding.lean#L68) |

</details>

### PlannedFragmentation

Source: [PlannedFragmentation.lean](../TDN/Semantics/PlannedFragmentation.lean).

Applies a fragment plan to a datagram and proves reassembly. A separate result shows that a packet larger than the MTU needs multiple pieces. The proof relies on the bounded partition and fragment-header conditions.

<details>
<summary>All 7 named declarations in PlannedFragmentation</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`made_fragments_length`](../TDN/Semantics/PlannedFragmentation.lean#L5) |
| `lemma` | [`partition_of_oversized_packet_has_multiple_chunks`](../TDN/Semantics/PlannedFragmentation.lean#L12) |
| `def` | [`Datagram.withPlannedFragments`](../TDN/Semantics/PlannedFragmentation.lean#L24) |
| `lemma` | [`Datagram.planned_body`](../TDN/Semantics/PlannedFragmentation.lean#L30) |
| `lemma` | [`Datagram.planned_data`](../TDN/Semantics/PlannedFragmentation.lean#L33) |
| `lemma` | [`Datagram.planned_raw`](../TDN/Semantics/PlannedFragmentation.lean#L36) |
| `theorem` | [`Datagram.planned_fragments_reassemble`](../TDN/Semantics/PlannedFragmentation.lean#L39) |

</details>

### PolicyMasks

Source: [PolicyMasks.lean](../TDN/Semantics/PolicyMasks.lean).

Describes a set of packets using finite conditions on addresses, protocols, ports and interfaces. The coverage proof checks ordered rules and establishes that every packet satisfying the description is allowed. Rejected earlier conditions remain part of the proof, so an accepting rule cannot hide a preceding denial.

<details>
<summary>All 10 named declarations in PolicyMasks</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`Mask`](../TDN/Semantics/PolicyMasks.lean#L5) |
| `def` | [`Mask.Matches`](../TDN/Semantics/PolicyMasks.lean#L22) |
| `def` | [`Mask.Allows`](../TDN/Semantics/PolicyMasks.lean#L34) |
| `lemma` | [`Mask.allowed_atom_holds`](../TDN/Semantics/PolicyMasks.lean#L53) |
| `def` | [`Mask.Rejects`](../TDN/Semantics/PolicyMasks.lean#L82) |
| `lemma` | [`Mask.rejected_atom_fails`](../TDN/Semantics/PolicyMasks.lean#L97) |
| `def` | [`Mask.Covers`](../TDN/Semantics/PolicyMasks.lean#L128) |
| `def` | [`Mask.finiteCovers`](../TDN/Semantics/PolicyMasks.lean#L134) |
| `lemma` | [`Mask.finiteCovers_correct`](../TDN/Semantics/PolicyMasks.lean#L141) |
| `theorem` | [`Mask.covered_packets_are_allowed`](../TDN/Semantics/PolicyMasks.lean#L152) |

Explicit instances:

- [Instance at line 50](../TDN/Semantics/PolicyMasks.lean#L50)
- [Instance at line 94](../TDN/Semantics/PolicyMasks.lean#L94)
- [Instance at line 149](../TDN/Semantics/PolicyMasks.lean#L149)

</details>

### RawIPsecFraming

Source: [RawIPsecFraming.lean](../TDN/Semantics/RawIPsecFraming.lean).

Derives supported IKE and UDP-encapsulated ESP framing from the original packet bytes. The lemmas connect byte offsets and lengths with the packet fields used by filter proofs. They require the relevant decoding and eligibility premises.

<details>
<summary>All 4 named declarations in RawIPsecFraming</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`two_byte_field`](../TDN/Semantics/RawIPsecFraming.lean#L6) |
| `lemma` | [`decoded_IPv4_UDP_framing`](../TDN/Semantics/RawIPsecFraming.lean#L27) |
| `lemma` | [`eligible_IKE_has_framing`](../TDN/Semantics/RawIPsecFraming.lean#L59) |
| `lemma` | [`eligible_UDPESP_has_framing`](../TDN/Semantics/RawIPsecFraming.lean#L98) |

</details>

### SourceCodec

Source: [SourceCodec.lean](../TDN/Semantics/SourceCodec.lean).

Separates the conditions for successful packet generation from the conditions for source errors. The main theorem combines both sets of conditions and establishes validity for every result returned by a supplied source processor.

<details>
<summary>All 4 named declarations in SourceCodec</summary>

| Kind | Declaration |
| --- | --- |
| `structure` | [`EmissionConditions`](../TDN/Semantics/SourceCodec.lean#L5) |
| `structure` | [`ErrorConditions`](../TDN/Semantics/SourceCodec.lean#L36) |
| `lemma` | [`emitted_datagram_valid`](../TDN/Semantics/SourceCodec.lean#L50) |
| `theorem` | [`processing_outcomes_valid`](../TDN/Semantics/SourceCodec.lean#L66) |

</details>

### SourceDatagramEncoding

Source: [SourceDatagramEncoding.lean](../TDN/Semantics/SourceDatagramEncoding.lean).

Builds an IP source datagram from an application request. The proofs preserve its payload, selected addresses and transport fields, source fragment flags and declared lengths. Valid request templates and size bounds provide the required encoding premises.

<details>
<summary>All 10 named declarations in SourceDatagramEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`sourceFlags`](../TDN/Semantics/SourceDatagramEncoding.lean#L6) |
| `lemma` | [`source_flags_fit`](../TDN/Semantics/SourceDatagramEncoding.lean#L9) |
| `lemma` | [`source_flags_are_not_fragments`](../TDN/Semantics/SourceDatagramEncoding.lean#L13) |
| `lemma` | [`source_flags_match_df`](../TDN/Semantics/SourceDatagramEncoding.lean#L18) |
| `def` | [`sourceHeader`](../TDN/Semantics/SourceDatagramEncoding.lean#L23) |
| `def` | [`encodeSourceDatagram`](../TDN/Semantics/SourceDatagramEncoding.lean#L30) |
| `lemma` | [`Request.ip_template_parts`](../TDN/Semantics/SourceDatagramEncoding.lean#L39) |
| `theorem` | [`source_IP_datagram_decodes`](../TDN/Semantics/SourceDatagramEncoding.lean#L55) |
| `lemma` | [`source_IP_datagram_flags`](../TDN/Semantics/SourceDatagramEncoding.lean#L145) |
| `theorem` | [`source_IP_whole_datagram_valid`](../TDN/Semantics/SourceDatagramEncoding.lean#L153) |

</details>

### SourceEthernetEncoding

Source: [SourceEthernetEncoding.lean](../TDN/Semantics/SourceEthernetEncoding.lean).

Builds an Ethernet source datagram from a header and payload. The proofs establish the supported header interpretation, payload identity and valid whole-frame emission within the supplied MTU.

<details>
<summary>All 4 named declarations in SourceEthernetEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`encodeSourceEthernet`](../TDN/Semantics/SourceEthernetEncoding.lean#L6) |
| `lemma` | [`source_Ethernet_mtu_bytes`](../TDN/Semantics/SourceEthernetEncoding.lean#L10) |
| `theorem` | [`source_Ethernet_datagram_decodes`](../TDN/Semantics/SourceEthernetEncoding.lean#L13) |
| `theorem` | [`source_Ethernet_whole_datagram_valid`](../TDN/Semantics/SourceEthernetEncoding.lean#L27) |

</details>

### SourceHeaderEncoding

Source: [SourceHeaderEncoding.lean](../TDN/Semantics/SourceHeaderEncoding.lean).

Selects the network and transport encoders for a supported source request. The template conditions spell out the supported protocols and field bounds. The matching theorems connect those conditions to the generated bytes.

<details>
<summary>All 9 named declarations in SourceHeaderEncoding</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`TransportTemplate`](../TDN/Semantics/SourceHeaderEncoding.lean#L6) |
| `def` | [`encodeTransportHeader`](../TDN/Semantics/SourceHeaderEncoding.lean#L11) |
| `theorem` | [`source_transport_header_matches`](../TDN/Semantics/SourceHeaderEncoding.lean#L16) |
| `lemma` | [`transport_template_protocol_bound`](../TDN/Semantics/SourceHeaderEncoding.lean#L44) |
| `def` | [`NetworkTemplate`](../TDN/Semantics/SourceHeaderEncoding.lean#L55) |
| `def` | [`networkHeaderSize`](../TDN/Semantics/SourceHeaderEncoding.lean#L61) |
| `def` | [`networkProtocolLimit`](../TDN/Semantics/SourceHeaderEncoding.lean#L64) |
| `def` | [`encodeNetworkHeader`](../TDN/Semantics/SourceHeaderEncoding.lean#L67) |
| `theorem` | [`source_network_header_matches`](../TDN/Semantics/SourceHeaderEncoding.lean#L71) |

</details>

### SourceHeaderRepresentability

Source: [SourceHeaderRepresentability.lean](../TDN/Semantics/SourceHeaderRepresentability.lean).

Proves that a valid emitted datagram requires fields that fit their packet encodings. The results identify necessary hop-limit, protocol and header conditions for source requests.

<details>
<summary>All 2 named declarations in SourceHeaderRepresentability</summary>

| Kind | Declaration |
| --- | --- |
| `lemma` | [`Datagram.valid_source_hop_bound`](../TDN/Semantics/SourceHeaderRepresentability.lean#L5) |
| `lemma` | [`Datagram.valid_source_header_representable`](../TDN/Semantics/SourceHeaderRepresentability.lean#L23) |

</details>

### SourceIPFragmentation

Source: [SourceIPFragmentation.lean](../TDN/Semantics/SourceIPFragmentation.lean).

Connects source-request encoding to IP fragmentation. The resulting datagram preserves the application payload and source fields, and its fragments satisfy the source-validity condition for the configured MTU.

<details>
<summary>All 3 named declarations in SourceIPFragmentation</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`encodeFragmentedSourceDatagram`](../TDN/Semantics/SourceIPFragmentation.lean#L6) |
| `lemma` | [`source_IP_fragmentation_preserves`](../TDN/Semantics/SourceIPFragmentation.lean#L11) |
| `theorem` | [`source_IP_fragmented_datagram_valid`](../TDN/Semantics/SourceIPFragmentation.lean#L23) |

</details>

### SourceIPSegmentation

Source: [SourceIPSegmentation.lean](../TDN/Semantics/SourceIPSegmentation.lean).

Splits stream data into source datagrams that fit the MTU and protocol-length limits. The validity theorem accounts for every segment and preserves the complete application byte sequence. Datagram requests retain the corresponding fragmentation behavior.

<details>
<summary>All 6 named declarations in SourceIPSegmentation</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Request.segmentCapacity`](../TDN/Semantics/SourceIPSegmentation.lean#L5) |
| `lemma` | [`Request.ip_overhead_bounds`](../TDN/Semantics/SourceIPSegmentation.lean#L8) |
| `lemma` | [`Request.segment_capacity_positive`](../TDN/Semantics/SourceIPSegmentation.lean#L22) |
| `def` | [`sourceIPDatagrams`](../TDN/Semantics/SourceIPSegmentation.lean#L29) |
| `lemma` | [`source_whole_application`](../TDN/Semantics/SourceIPSegmentation.lean#L36) |
| `theorem` | [`source_IP_datagrams_valid`](../TDN/Semantics/SourceIPSegmentation.lean#L40) |

</details>

### SourceProcessing

Source: [SourceProcessing.lean](../TDN/Semantics/SourceProcessing.lean).

Implements the modeled source processor for supported IP and Ethernet requests. It emits datagrams or reports an invalid template, invalid MTU, excessive protocol length or a forbidden oversized datagram. Its general correctness theorem requires an MTU of at least 1280 and establishes the specified result for every request.

<details>
<summary>All 8 named declarations in SourceProcessing</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`processSource`](../TDN/Semantics/SourceProcessing.lean#L10) |
| `theorem` | [`source_processing_valid_for_representable_headers`](../TDN/Semantics/SourceProcessing.lean#L26) |
| `def` | [`sourceProcessing`](../TDN/Semantics/SourceProcessing.lean#L95) |
| `lemma` | [`Request.template_headers_representable`](../TDN/Semantics/SourceProcessing.lean#L98) |
| `theorem` | [`source_processing_valid`](../TDN/Semantics/SourceProcessing.lean#L106) |
| `lemma` | [`source_IP_emission_shape`](../TDN/Semantics/SourceProcessing.lean#L113) |
| `lemma` | [`source_Ethernet_emission_shape`](../TDN/Semantics/SourceProcessing.lean#L132) |
| `lemma` | [`source_IP_datagrams_have_source_headers`](../TDN/Semantics/SourceProcessing.lean#L148) |

Explicit instances:

- [Instance at line 6](../TDN/Semantics/SourceProcessing.lean#L6)

</details>

### SourceProcessingCodec

Source: [SourceProcessingCodec.lean](../TDN/Semantics/SourceProcessingCodec.lean).

Packages the source processor correctness results into its successful-emission and error conditions. Other proofs can reuse those conditions without repeating the source processor case analysis.

<details>
<summary>All 2 named declarations in SourceProcessingCodec</summary>

| Kind | Declaration |
| --- | --- |
| `theorem` | [`source_processing_emission_conditions`](../TDN/Semantics/SourceProcessingCodec.lean#L6) |
| `theorem` | [`source_processing_error_conditions`](../TDN/Semantics/SourceProcessingCodec.lean#L44) |

</details>

### SourceTemplateCounterexample

Source: [SourceTemplateCounterexample.lean](../TDN/Semantics/SourceTemplateCounterexample.lean).

Preserves concrete failures of the earlier request-template conditions. The examples cover a hop limit of 256, an inconsistent IPv6 next-header value and nonzero ICMP transport ports. The corrected template rejects those unrepresentable requests with the specified error result.

<details>
<summary>All 16 named declarations in SourceTemplateCounterexample</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Request.TemplateValidBeforeRepresentability`](../TDN/Semantics/SourceTemplateCounterexample.lean#L6) |
| `def` | [`Outcome.ValidBeforeRepresentability`](../TDN/Semantics/SourceTemplateCounterexample.lean#L30) |
| `theorem` | [`request_with_unrepresentable_hop_has_no_valid_outcome`](../TDN/Semantics/SourceTemplateCounterexample.lean#L48) |
| `theorem` | [`request_with_unrepresentable_header_has_no_valid_outcome`](../TDN/Semantics/SourceTemplateCounterexample.lean#L78) |
| `def` | [`oversizedHopRequest`](../TDN/Semantics/SourceTemplateCounterexample.lean#L108) |
| `lemma` | [`oversized_hop_old_template_is_allowed`](../TDN/Semantics/SourceTemplateCounterexample.lean#L118) |
| `theorem` | [`oversized_hop_request_cannot_be_processed`](../TDN/Semantics/SourceTemplateCounterexample.lean#L122) |
| `def` | [`ipv6NextHeaderMismatchRequest`](../TDN/Semantics/SourceTemplateCounterexample.lean#L129) |
| `def` | [`nonzeroICMPPortRequest`](../TDN/Semantics/SourceTemplateCounterexample.lean#L139) |
| `lemma` | [`ipv6_next_header_mismatch_old_template_is_allowed`](../TDN/Semantics/SourceTemplateCounterexample.lean#L147) |
| `lemma` | [`nonzero_icmp_port_old_template_is_allowed`](../TDN/Semantics/SourceTemplateCounterexample.lean#L152) |
| `theorem` | [`ipv6_next_header_mismatch_cannot_be_processed`](../TDN/Semantics/SourceTemplateCounterexample.lean#L156) |
| `theorem` | [`nonzero_icmp_port_cannot_be_processed`](../TDN/Semantics/SourceTemplateCounterexample.lean#L164) |
| `theorem` | [`oversized_hop_receives_valid_unsupported_result`](../TDN/Semantics/SourceTemplateCounterexample.lean#L172) |
| `theorem` | [`ipv6_next_header_mismatch_receives_valid_unsupported_result`](../TDN/Semantics/SourceTemplateCounterexample.lean#L177) |
| `theorem` | [`nonzero_icmp_port_receives_valid_unsupported_result`](../TDN/Semantics/SourceTemplateCounterexample.lean#L182) |

</details>

### TraceProjection

Source: [TraceProjection.lean](../TDN/Semantics/TraceProjection.lean).

Maps detailed executions to a simpler transition system. Actions omitted by the mapping must preserve the represented state. The general theorem constructs the corresponding simpler execution from the per-step mapping condition.

<details>
<summary>All 3 named declarations in TraceProjection</summary>

| Kind | Declaration |
| --- | --- |
| `theorem` | [`optional_actions`](../TDN/Semantics/TraceProjection.lean#L5) |
| `theorem` | [`action_member_has_actual_step`](../TDN/Semantics/TraceProjection.lean#L30) |
| `theorem` | [`project_execution`](../TDN/Semantics/TraceProjection.lean#L44) |

</details>

### WholePacketEmission

Source: [WholePacketEmission.lean](../TDN/Semantics/WholePacketEmission.lean).

Emits a datagram as one fragment when it fits and constructs fragments when necessary. The proofs show that both choices reassemble to the original bytes. The one-fragment lemma connects a proved MTU bound to the packet-sizing requirement.

<details>
<summary>All 19 named declarations in WholePacketEmission</summary>

| Kind | Declaration |
| --- | --- |
| `def` | [`Datagram.wholeFragment`](../TDN/Semantics/WholePacketEmission.lean#L5) |
| `def` | [`Datagram.asWhole`](../TDN/Semantics/WholePacketEmission.lean#L8) |
| `lemma` | [`Datagram.asWhole_body`](../TDN/Semantics/WholePacketEmission.lean#L11) |
| `lemma` | [`Datagram.asWhole_application`](../TDN/Semantics/WholePacketEmission.lean#L14) |
| `lemma` | [`Datagram.asWhole_raw`](../TDN/Semantics/WholePacketEmission.lean#L17) |
| `lemma` | [`Datagram.asWhole_mtuBytes`](../TDN/Semantics/WholePacketEmission.lean#L20) |
| `lemma` | [`Datagram.asWhole_decoded`](../TDN/Semantics/WholePacketEmission.lean#L23) |
| `lemma` | [`Datagram.asWhole_headerFrom`](../TDN/Semantics/WholePacketEmission.lean#L27) |
| `lemma` | [`Datagram.asWhole_fragment_count`](../TDN/Semantics/WholePacketEmission.lean#L31) |
| `lemma` | [`Datagram.whole_fragment_mtuBytes`](../TDN/Semantics/WholePacketEmission.lean#L34) |
| `lemma` | [`Datagram.whole_fragment_pieces_valid`](../TDN/Semantics/WholePacketEmission.lean#L40) |
| `def` | [`Datagram.UnfragmentedHeader`](../TDN/Semantics/WholePacketEmission.lean#L47) |
| `lemma` | [`Datagram.decoded_header_is_unfragmented`](../TDN/Semantics/WholePacketEmission.lean#L55) |
| `theorem` | [`Datagram.whole_packet_reassembles_from_header`](../TDN/Semantics/WholePacketEmission.lean#L67) |
| `theorem` | [`Datagram.whole_packet_reassembles`](../TDN/Semantics/WholePacketEmission.lean#L90) |
| `def` | [`Datagram.fragmentOnlyWhenNeeded`](../TDN/Semantics/WholePacketEmission.lean#L114) |
| `lemma` | [`Datagram.needed_fragmentation_preserves_raw`](../TDN/Semantics/WholePacketEmission.lean#L117) |
| `lemma` | [`Datagram.fitting_packet_uses_one_fragment`](../TDN/Semantics/WholePacketEmission.lean#L122) |
| `theorem` | [`Datagram.fragment_only_when_needed_reassembles`](../TDN/Semantics/WholePacketEmission.lean#L127) |

</details>

## Validation and maintenance

The active library is checked by `lake build`. The [scope guide](theory_scope.md) records which modules and regression cases were retired. The remaining tests exercise the packet, path, authentication, and encryption arguments. The all-theorem axiom audit runs through `scripts/construction/audit_axioms.lean`.

The catalog lists every explicit named declaration and every explicit decidability instance in the inspected source files. The source links identify the current declaration lines. When adding or renaming a module, update its explanation, declaration index, imports, and the counts at the beginning of the document. When changing a theorem's premises, update the corresponding explanation of what a caller must supply.

Build a module and its dependencies from the repository root with:

```sh
lake build TDN.Semantics.ExecutionInvariant
```

Inspect a declaration in Lean by importing its module and using its namespace-qualified name:

```lean
import TDN.Semantics.ExecutionInvariant

#check TDN.Execution.execution_preserves_stack_invariant
#print TDN.Execution.LocalStackConditions
```

`#check` shows the declaration's type, including its parameters, premises, and conclusion. `#print` shows the definition or theorem body, which helps trace how the result depends on the smaller declarations listed in the catalog.
