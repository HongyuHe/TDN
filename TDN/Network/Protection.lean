import TDN.Network.Execution

/-!
Layer provenance records which observed security associations created a packet's
wrappers. A separate stack invariant records their order. The two arguments
compose: stack labels identify required kinds of protection, and provenance
connects each wrapper to an actual observed SA used by a sealing operation.
The proofs apply to arbitrary node, message, and layer-label types.
-/
namespace TDN.Network.Protection
open Execution
variable {Node Message Layer : Type}

def layerLabels (classify : Nat → Layer) : WirePacket Message → List Layer
  | .clear _ _ => []
  | .cipher _ identity body => classify identity.reqid :: layerLabels classify body

def popped (tag : Option Nat) (layers : List Layer) : List Layer :=
  if tag.isSome then layers.tail else layers

def pushed (classify : Nat → Layer) (tag : Option Nat) (layers : List Layer) : List Layer :=
  match tag with
  | none => layers
  | some request => classify request :: layers

def transformed (classify : Nat → Layer) (inputTag outputTag : Option Nat) (layers : List Layer) : List Layer :=
  pushed classify outputTag (popped inputTag layers)

/-- Every layer comes from an observed SA. This proposition retains exact seal
structure, including the generated outer header and the packet inside it. -/
inductive GeneratedLayers (model : Model Node) : WirePacket Message → Prop where
  | clear (header : IPv4Header) (message : Option Message) : GeneratedLayers model (.clear header message)
  | wrap (node : Node) (state : XfrmState) (body : WirePacket Message)
      (observed : state ∈ model.states node) (inside : GeneratedLayers model body) :
      GeneratedLayers model (body.seal state)

def realizeLayers (origins : List (Node × XfrmState)) (header : IPv4Header)
    (message : Option Message) : WirePacket Message :=
  origins.foldr (fun origin body => body.seal origin.2) (.clear header message)

/-- The provenance representation supports any number of layers. Each returned
entry names the observed owner and full SA, ordered from outermost to innermost. -/
theorem generated_layers_have_observed_origin_list (model : Model Node) (classify : Nat → Layer)
    (packet : WirePacket Message) (generated : GeneratedLayers model packet) :
    ∃ origins header message,
      (∀ origin ∈ origins, origin.2 ∈ model.states origin.1) ∧
      packet = realizeLayers origins header message ∧
      layerLabels classify packet = origins.map (fun origin => classify origin.2.reqid) := by
  induction generated with
  | clear header message => exact ⟨[], header, message, by simp, rfl, rfl⟩
  | wrap node state body observed inside ih =>
    obtain ⟨origins, header, message, members, realization, labels⟩ := ih
    refine ⟨(node, state) :: origins, header, message, ?_, ?_, ?_⟩
    · intro origin member
      rcases List.mem_cons.mp member with equal | tail
      · simpa [equal] using observed
      · exact members origin tail
    · simpa only [realizeLayers, List.foldr_cons] using congrArg (fun packet => packet.seal state) realization
    · simpa [layerLabels, WirePacket.seal, CipherIdentity.ofState] using congrArg (List.cons (classify state.reqid)) labels

theorem send_is_unchanged_or_observed_seal (model : Model Node) (node : Node)
    (packet sent : WirePacket Message) (tag : Option Nat)
    (accepted : model.send node packet = some (sent, tag)) :
    (sent = packet ∧ tag = none) ∨
    ∃ state ∈ model.states node, sent = packet.seal state ∧ tag = some state.reqid := by
  cases selected : model.policy node "out" packet.header with
  | none =>
    simp [Model.send, selected] at accepted
    exact Or.inl ⟨accepted.1.symm, accepted.2.symm⟩
  | some policy =>
    cases state : (model.states node).find? (stateMatches policy) with
    | none => simp [Model.send, selected, state] at accepted
    | some sa =>
      simp [Model.send, selected, state] at accepted
      obtain ⟨rfl, rfl⟩ := accepted
      have matched := List.find?_some state
      have reqid : sa.reqid = policy.reqid := by simp_all [stateMatches]
      exact Or.inr ⟨sa, List.mem_of_find?_eq_some state, rfl, congrArg some reqid.symm⟩

theorem receive_is_unchanged_or_unwrapped (model : Model Node) (node : Node) (port : String)
    (packet body : WirePacket Message) (tag : Option Nat)
    (accepted : model.receive node port packet = some (body, tag)) :
    (body = packet ∧ tag = none) ∨
    ∃ header identity, packet = .cipher header identity body ∧ tag.isSome = true := by
  cases packet with
  | clear header message =>
    simp [Model.receive] at accepted
    exact Or.inl ⟨accepted.1.symm, accepted.2.symm⟩
  | cipher header identity inner =>
    unfold Model.receive at accepted
    cases outer : model.route node header with
    | none => simp [outer] at accepted
    | some route =>
      by_cases localRoute : route.kind = "local"
      · by_cases filter : model.inputFilter node port header = true
        · simp [outer, localRoute, filter, Option.bind_eq_some_iff] at accepted
          obtain ⟨_, _, _, _, _, _, _, _, equal⟩ := accepted
          obtain ⟨rfl, rfl⟩ := equal
          exact Or.inr ⟨header, identity, rfl, rfl⟩
        · simp [outer, localRoute, filter] at accepted
      · simp [outer, localRoute] at accepted
        exact Or.inl ⟨accepted.1.symm, accepted.2.symm⟩

theorem send_stack_accounting (model : Model Node) (classify : Nat → Layer) (node : Node)
    (packet sent : WirePacket Message) (tag : Option Nat)
    (accepted : model.send node packet = some (sent, tag)) :
    layerLabels classify sent = pushed classify tag (layerLabels classify packet) := by
  rcases send_is_unchanged_or_observed_seal model node packet sent tag accepted with unchanged | sealed
  · obtain ⟨rfl, rfl⟩ := unchanged
    rfl
  · obtain ⟨state, _, rfl, rfl⟩ := sealed
    rfl

theorem receive_stack_accounting (model : Model Node) (classify : Nat → Layer) (node : Node) (port : String)
    (packet body : WirePacket Message) (tag : Option Nat)
    (accepted : model.receive node port packet = some (body, tag)) :
    layerLabels classify body = popped tag (layerLabels classify packet) := by
  rcases receive_is_unchanged_or_unwrapped model node port packet body tag accepted with unchanged | unwrapped
  · obtain ⟨rfl, rfl⟩ := unchanged
    rfl
  · obtain ⟨header, identity, rfl, present⟩ := unwrapped
    simp [popped, present, layerLabels]

theorem generated_cipher_has_generated_body (model : Model Node) (header : IPv4Header)
    (identity : CipherIdentity) (body : WirePacket Message)
    (generated : GeneratedLayers model (.cipher header identity body)) : GeneratedLayers model body := by
  cases generated with
  | wrap _ _ _ _ inside => exact inside

theorem forwarding_preserves_layer_provenance (model : Model Node) (node : Node) (input : String)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result)
    (generated : GeneratedLayers model packet) : GeneratedLayers model result.packet := by
  obtain ⟨received, sent, _, _, _⟩ := forward_evidence model node input packet result accepted
  have bodyGenerated : GeneratedLayers model result.body := by
    rcases receive_is_unchanged_or_unwrapped model node input packet result.body result.inputTag received with unchanged | unwrapped
    · simpa [unchanged.1] using generated
    · obtain ⟨header, identity, same, _⟩ := unwrapped
      rw [same] at generated
      exact generated_cipher_has_generated_body model header identity result.body generated
  rcases send_is_unchanged_or_observed_seal model node result.body result.packet result.outputTag sent with unchanged | sealed
  · simpa [unchanged.1] using bodyGenerated
  · obtain ⟨state, member, same, _⟩ := sealed
    rw [same]
    exact .wrap node state result.body member bodyGenerated

theorem executions_preserve_layer_provenance (model : Model Node) {before after : State Node Message}
    (path : Reach (Step model) before after)
    (initial : GeneratedLayers model before.packet) : GeneratedLayers model after.packet := by
  induction path with
  | refl => exact initial
  | step edge _ ih =>
    apply ih
    cases edge with
    | wire => exact initial
    | switch => exact initial
    | forward node input packet result accepted =>
      exact forwarding_preserves_layer_provenance model node input packet result accepted initial

/-- A tagged outbound operation must have selected a matching observed policy.
The filter and this policy inspect the same unwrapped header. -/
theorem tagged_send_has_matching_policy (model : Model Node) (node : Node)
    (packet sent : WirePacket Message) (tag : Nat)
    (accepted : model.send node packet = some (sent, some tag)) :
    ∃ policy ∈ model.policies node, policy.direction = "out" ∧ policy.reqid = tag ∧
      policy.source.contains packet.header.source = true ∧
      policy.destination.contains packet.header.destination = true := by
  cases selected : model.policy node "out" packet.header with
  | none => simp [Model.send, selected] at accepted
  | some policy =>
    cases state : (model.states node).find? (stateMatches policy) with
    | none => simp [Model.send, selected, state] at accepted
    | some sa =>
      simp [Model.send, selected, state] at accepted
      have member := Routing.selected_is_member _ _ policy selected
      have selectedFields := (List.mem_filter.mp member).2
      simp only [Bool.and_eq_true, beq_iff_eq, selectorMatches] at selectedFields
      exact ⟨policy, (List.mem_filter.mp member).1, selectedFields.1, accepted.2,
        selectedFields.2.1, selectedFields.2.2⟩

def StackInvariant (classify : Nat → Layer) (required : Endpoint Node → List Layer)
    (state : State Node Message) : Prop :=
  state.packet.message.isSome = true → layerLabels classify state.packet = required state.location

def ProcessingStack (model : Model Node) (classify : Nat → Layer)
    (required : Endpoint Node → List Layer) : Prop :=
  ∀ node input output header inputTag outputTag,
    input ∈ model.retainedPorts node → output ∈ model.retainedPorts node →
    inputTag ∈ model.tags node → outputTag ∈ model.tags node →
    (inputTag.isSome = true → ∃ wireHeader, model.inputFilter node input wireHeader = true) →
    (∀ tag, outputTag = some tag → ∃ policy ∈ model.policies node,
      policy.direction = "out" ∧ policy.reqid = tag ∧
      policy.source.contains header.source = true ∧ policy.destination.contains header.destination = true) →
    model.forwardFilter node input output header inputTag outputTag = true →
    required ⟨node, output⟩ = transformed classify inputTag outputTag (required ⟨node, input⟩)

theorem forwarding_preserves_stack (model : Model Node) (classify : Nat → Layer)
    (required : Endpoint Node → List Layer) (certificate : ProcessingStack model classify required)
    (node : Node) (input : String) (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result)
    (initial : StackInvariant classify required ⟨⟨node, input⟩, .input, packet⟩) :
    StackInvariant classify required ⟨⟨node, result.route.output⟩, .output, result.packet⟩ := by
  obtain ⟨received, sent, filtered, inputUp, outputUp⟩ := forward_evidence model node input packet result accepted
  obtain ⟨inMessage, _, inTag, admitted⟩ := receive_layer_accounting model node input packet result.body result.inputTag received
  obtain ⟨outMessage, _, outTag⟩ := send_layer_accounting model node result.body result.packet result.outputTag sent
  have localStack := certificate node input result.route.output result.body.header result.inputTag result.outputTag
    (live_port_is_retained model node input _ inputUp)
    (live_port_is_retained model node result.route.output _ outputUp) inTag outTag
    (fun tag => ⟨packet.header, admitted tag⟩)
    (fun tag same => tagged_send_has_matching_policy model node result.body result.packet tag (same ▸ sent)) filtered
  have incoming := receive_stack_accounting model classify node input packet result.body result.inputTag received
  have outgoing := send_stack_accounting model classify node result.body result.packet result.outputTag sent
  intro present
  have origin : packet.message.isSome = true := by
    change result.packet.message.isSome = true at present
    simpa only [outMessage, ← inMessage] using present
  change layerLabels classify result.packet = required ⟨node, result.route.output⟩
  rw [localStack, outgoing, incoming, initial origin]
  rfl

theorem executions_preserve_stack (model : Model Node) (classify : Nat → Layer)
    (required : Endpoint Node → List Layer) (certificate : ProcessingStack model classify required)
    (wire : ∀ a b, model.linked a b → required a = required b)
    (bridge : ∀ a b, model.bridge a b → required a = required b)
    {before after : State Node Message} (path : Reach (Step model) before after)
    (initial : StackInvariant classify required before) : StackInvariant classify required after := by
  induction path with
  | refl => exact initial
  | step edge _ ih =>
    apply ih
    cases edge with
    | wire a b packet linked _ _ => simpa only [StackInvariant, wire a b linked] using initial
    | switch a b packet linked _ _ => simpa only [StackInvariant, bridge a b linked] using initial
    | forward node input packet result accepted =>
      exact forwarding_preserves_stack model classify required certificate node input packet result accepted initial

/-- An exact two-label stack with generated provenance consists of two real
modeled seal operations. Their order and complete observed SAs remain visible
in the conclusion, rather than being replaced by a count of wrappers. -/
theorem generated_two_layer_structure (model : Model Node) (classify : Nat → Layer)
    (outside inside : Layer) (packet : WirePacket Message)
    (generated : GeneratedLayers model packet)
    (stack : layerLabels classify packet = [outside, inside]) :
    ∃ outerNode outerState innerNode innerState header message,
      outerState ∈ model.states outerNode ∧ innerState ∈ model.states innerNode ∧
      classify outerState.reqid = outside ∧ classify innerState.reqid = inside ∧
      packet = ((WirePacket.clear header message).seal innerState).seal outerState := by
  cases generated with
  | clear => simp [layerLabels] at stack
  | wrap outerNode outerState body outerMember bodyGenerated =>
    have outerStack : classify outerState.reqid = outside ∧ layerLabels classify body = [inside] := by
      simpa [layerLabels, WirePacket.seal, CipherIdentity.ofState] using stack
    cases bodyGenerated with
    | clear => simp [layerLabels] at outerStack
    | wrap innerNode innerState root innerMember rootGenerated =>
      have innerStack : classify innerState.reqid = inside ∧ layerLabels classify root = [] := by
        simpa [layerLabels, WirePacket.seal, CipherIdentity.ofState] using outerStack.2
      cases rootGenerated with
      | clear header message =>
        exact ⟨outerNode, outerState, innerNode, innerState, header, message,
          outerMember, innerMember, outerStack.1, innerStack.1, rfl⟩
      | wrap => simp [layerLabels, WirePacket.seal] at innerStack

theorem generated_one_layer_structure (model : Model Node) (classify : Nat → Layer)
    (label : Layer) (packet : WirePacket Message) (generated : GeneratedLayers model packet)
    (stack : layerLabels classify packet = [label]) :
    ∃ node state header message, state ∈ model.states node ∧ classify state.reqid = label ∧
      packet = (WirePacket.clear header message).seal state := by
  cases generated with
  | clear => simp [layerLabels] at stack
  | wrap node state body member inside =>
    have parts : classify state.reqid = label ∧ layerLabels classify body = [] := by
      simpa [layerLabels, WirePacket.seal, CipherIdentity.ofState] using stack
    cases inside with
    | clear header message => exact ⟨node, state, header, message, member, parts.1, rfl⟩
    | wrap => simp [layerLabels, WirePacket.seal] at parts

end TDN.Network.Protection
