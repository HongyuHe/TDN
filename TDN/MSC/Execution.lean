import TDN.MSC.LocalPolicy
import TDN.MSC.Operational
import TDN.Network.Execution

/-!
The MSC instantiation connects the generic execution relation to the snapshot.
Routes, policy rules, XFRM policies/SAs, port state, and MTUs come from typed
runtime records. INPUT and FORWARD decisions use the independently imported
filter tables. Each symbolic protected message may follow any permitted finite
wire/switch/forwarding execution; no fixed inner-then-outer route is assumed.

The model covers complete IPv4 datagrams under fixed sampled state and trusted
IPsec operations. Optional management ports are absent. Actual packet origin,
fragmentation, state changes over time, and implementation fidelity remain
explicit boundaries until the corresponding models are connected.
-/
namespace TDN.MSC.Execution
open Deployment
open TDN.Network (IPv4Header WirePacket)
open TDN.Network.Execution

def ports (node : String) : List String :=
  ((device? node).map (fun d => d.interfaces.map Interface.name)).getD []

def floor (endpoint : Endpoint String) : Nat :=
  match ((device? endpoint.node).bind (fun d => d.interfaces.find? (fun i => i.name == endpoint.port))).map Interface.zone with
  | some .gray => 1
  | some .black => 2
  | _ => 0

def packetView (input output : String) (header : IPv4Header)
    (inputTag outputTag : Option Nat) : RoutedPacket :=
  { input := input, output := output, source := header.source,
    destination := header.destination, protocol := header.protocol,
    destinationPort := header.destinationPort, headerWords := header.headerWords,
    inPolicy := inputTag, outPolicy := outputTag }

def declaredWires : List (Endpoint String × Endpoint String) :=
  links.flatMap fun link =>
    [(⟨link.a, link.aPort⟩, ⟨link.b, link.bPort⟩), (⟨link.b, link.bPort⟩, ⟨link.a, link.aPort⟩)]

def observedPorts : List (Endpoint String × TDN.Network.ObservedInterface) :=
  devices.flatMap fun device => device.interfaces.filterMap fun port =>
    ((liveInterfaces device.id).find? (fun actual => actual.name == port.name)).map
      (fun actual => (⟨device.id, port.name⟩, actual))

/-- Wire adjacency comes from reciprocal observed veth peer indices. A
separate finite check requires exactly the declared link set, so missing or
extra observed links cannot silently replace the intended topology. -/
def wires : List (Endpoint String × Endpoint String) :=
  observedPorts.flatMap fun a => observedPorts.filterMap fun b =>
    if a.2.peerIndex == some b.2.index && b.2.peerIndex == some a.2.index then
      some (a.1, b.1)
    else none

/-- NORMAL switching is conservatively allowed to choose any other retained
port of the same switch. That over-approximation includes flooding and loops;
the protection invariant must survive every choice. -/
def bridges : List (Endpoint String × Endpoint String) :=
  devices.flatMap fun device =>
    match (operational? device.id).bind TDN.Network.OperationalSnapshot.switching with
    | none => []
    | some observed =>
      if observed.normalOnly && !observed.vlanConfigured && observed.controllers.isEmpty &&
          observed.bridge == "br0" && observed.failMode == "secure" then
        observed.ports.flatMap fun a => observed.ports.filterMap fun b =>
          if a == b then none else some (⟨device.id, a⟩, ⟨device.id, b⟩)
      else []

def model : Model String :=
  { observed := operational?, retainedPorts := ports,
    inputFilter := fun node input header =>
      (localDecision .input node (packetView input "" header none none)).getD false,
    outputFilter := fun node output header =>
      (localDecision .output node (packetView "" output header none none)).getD false,
    forwardFilter := fun node input output header inputTag outputTag =>
      (forwardDecision node (packetView input output header inputTag outputTag)).getD false,
    linked := fun a b => (a, b) ∈ wires,
    bridge := fun a b => (a, b) ∈ bridges,
    protectionFloor := floor }

def ruleSignature (rule : ForwardRule) (input output : String)
    (inputTag outputTag : Option Nat) : Bool :=
  optionalMatch rule.input input && optionalMatch rule.output output &&
    policyMatch rule.inPolicy inputTag && policyMatch rule.outPolicy outputTag

def forwardSignature (node input output : String) (inputTag outputTag : Option Nat) : Bool :=
  ((forwardingTable? node).map fun table =>
    table.rules.any (fun rule => ruleSignature rule input output inputTag outputTag) || table.defaultAccept).getD false

def inputPossible (node input : String) : Bool :=
  ((localTable? .input node).map fun table =>
    table.rules.any (fun rule => optionalMatch rule.input input) || table.defaultAccept).getD false

theorem matching_rule_has_signature (rule : ForwardRule) (packet : RoutedPacket)
    (matched : rule.matches packet = true) :
    ruleSignature rule packet.input packet.output packet.inPolicy packet.outPolicy = true := by
  simp_all [ForwardRule.matches, ruleSignature]

theorem accepted_forward_has_signature (node input output : String) (header : IPv4Header)
    (inputTag outputTag : Option Nat)
    (accepted : model.forwardFilter node input output header inputTag outputTag = true) :
    forwardSignature node input output inputTag outputTag = true := by
  change (forwardDecision node (packetView input output header inputTag outputTag)).getD false = true at accepted
  cases lookup : forwardingTable? node with
  | none => simp [forwardDecision, lookup] at accepted
  | some table =>
    simp only [forwardDecision, lookup, Option.map_some, Option.getD_some] at accepted
    simp only [ForwardTable.accepts, Bool.or_eq_true, List.any_eq_true] at accepted
    simp only [forwardSignature, lookup, Option.map_some, Option.getD_some, Bool.or_eq_true, List.any_eq_true]
    rcases accepted with ⟨rule, member, matched⟩ | default
    · exact Or.inl ⟨rule, member, matching_rule_has_signature rule _ matched⟩
    · exact Or.inr default

theorem accepted_input_has_port_signature (node input : String) (header : IPv4Header)
    (accepted : model.inputFilter node input header = true) : inputPossible node input = true := by
  change (localDecision .input node (packetView input "" header none none)).getD false = true at accepted
  cases lookup : localTable? .input node with
  | none => simp [localDecision, lookup] at accepted
  | some table =>
    simp only [localDecision, lookup, Option.map_some, Option.getD_some] at accepted
    simp only [ForwardTable.accepts, Bool.or_eq_true, List.any_eq_true] at accepted
    simp only [inputPossible, lookup, Option.map_some, Option.getD_some, Bool.or_eq_true, List.any_eq_true]
    rcases accepted with ⟨rule, member, matched⟩ | default
    · have required : optionalMatch rule.input input = true := by
        have signature := matching_rule_has_signature rule _ matched
        simp only [ruleSignature, Bool.and_eq_true] at signature
        exact signature.1.1.1
      exact Or.inl ⟨rule, member, required⟩
    · exact Or.inr default

/-- The finite certificate quantifies over every retained interface pair and
every possible observed request ID. Address and protocol fields are abstracted
away by a conservative rule signature, so the result covers arbitrary headers.
A broad unguarded encryptor rule makes the certificate fail. -/
theorem processing_budget_certificate : ∀ d ∈ devices,
    ∀ input ∈ ports d.id, ∀ output ∈ ports d.id,
    ∀ inputTag ∈ model.tags d.id, ∀ outputTag ∈ model.tags d.id,
    (inputTag.isSome = true → inputPossible d.id input = true) →
    forwardSignature d.id input output inputTag outputTag = true →
    floor ⟨d.id, output⟩ ≤ floor ⟨d.id, input⟩ - tagCost inputTag + tagCost outputTag := by decide

theorem observed_data_port_indices_unique :
    (observedPorts.map (fun port => port.2.index)).Nodup := by decide

theorem observed_wires_equal_declared : wires.Perm declaredWires := by decide

theorem wire_protection_levels_match : ∀ edge ∈ wires, floor edge.1 = floor edge.2 := by decide

theorem switch_protection_levels_match : ∀ edge ∈ bridges, floor edge.1 = floor edge.2 := by decide

/-- Lift the finite signature certificate to all packet headers. Matching a
complete rule implies matching its interface/policy signature. A successful
decryption also supplies an actual accepted local INPUT event. -/
theorem processing_budget : ProcessingBudget model := by
  intro node input output header inputTag outputTag inputMember outputMember inTag outTag receiveAllowed filtered
  cases declared : device? node with
  | none => simp [model, ports, declared] at inputMember
  | some device =>
    have member : device ∈ devices := List.mem_of_find?_eq_some declared
    have identity : device.id = node := by
      have matched := List.find?_some declared
      simpa using matched
    have certificate := processing_budget_certificate device member
    rw [identity] at certificate
    apply certificate input inputMember output outputMember inputTag inTag outputTag outTag
    · intro tagged
      obtain ⟨wireHeader, accepted⟩ := receiveAllowed tagged
      exact accepted_input_has_port_signature node input wireHeader accepted
    · exact accepted_forward_has_signature node input output header inputTag outputTag filtered

variable {Message : Type}

/-- An arbitrary finite execution preserves the protection level required by
its current interface. The induction theorem is generic; only the finite
wire, bridge, and filter/XFRM signature certificates are specific to MSC. -/
theorem every_execution_preserves_protection {before after : State String Message}
    (path : TDN.Network.Reach (Step model) before after)
    (initial : Protected model before) : Protected model after :=
  executions_preserve_protection model processing_budget
    (fun a b edge => wire_protection_levels_match (a, b) edge)
    (fun a b edge => switch_protection_levels_match (a, b) edge) path initial

theorem red_origin_execution_has_required_layers {before after : State String Message}
    (path : TDN.Network.Reach (Step model) before after)
    (red : floor before.location = 0)
    (payload : after.packet.message.isSome = true) :
    floor after.location ≤ after.packet.depth := by
  have initial : Protected model before := by
    intro _
    change floor before.location ≤ before.packet.depth
    rw [red]
    exact Nat.zero_le _
  exact every_execution_preserves_protection path initial payload

/-- OR-4's protected-payload counterpart: a modeled Red-origin payload that
reaches a Gray interface already carries at least one encryption layer.
Control packets have `message = none` and retain their explicit exception. -/
theorem gray_payload_has_encryption_layer {before after : State String Message}
    (path : TDN.Network.Reach (Step model) before after)
    (red : floor before.location = 0) (gray : floor after.location = 1)
    (payload : after.packet.message.isSome = true) : 1 ≤ after.packet.depth := by
  have layers := red_origin_execution_has_required_layers path red payload
  simpa only [gray] using layers

/-- Every modeled Red-origin payload on a Black interface has undergone at
least two still-present encapsulations. The conclusion follows from actual
admitted steps, rather than a function that always composes two wrappers. -/
theorem black_payload_has_nested_protection {before after : State String Message}
    (path : TDN.Network.Reach (Step model) before after)
    (red : floor before.location = 0) (black : floor after.location = 2)
    (payload : after.packet.message.isSome = true) : 2 ≤ after.packet.depth := by
  have layers := red_origin_execution_has_required_layers path red payload
  simpa only [black] using layers

theorem no_plaintext_red_to_black_execution {before after : State String Message}
    (red : floor before.location = 0) (black : floor after.location = 2)
    (payload : after.packet.message.isSome = true) (plaintext : after.packet.depth = 0) :
    ¬ TDN.Network.Reach (Step model) before after := by
  intro path
  have layers := black_payload_has_nested_protection path red black payload
  omega

/-- Starting with a clear Red application packet makes both the origin and
the payload premise explicit. Message preservation supplies the corresponding
payload fact at every later state of the execution. -/
theorem clear_red_message_is_doubly_wrapped_on_black (start : Endpoint String)
    (header : IPv4Header) (message : Message) (after : State String Message)
    (red : floor start = 0) (black : floor after.location = 2)
    (path : TDN.Network.Reach (Step model)
      ⟨start, .output, .clear header (some message)⟩ after) :
    after.packet.message = some message ∧ 2 ≤ after.packet.depth := by
  have preserved := execution_preserves_message model path
  have payload : after.packet.message.isSome = true := by
    rw [← preserved]
    rfl
  exact ⟨preserved.symm, black_payload_has_nested_protection path red black payload⟩

end TDN.MSC.Execution
