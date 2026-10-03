import TDN.MSC.Execution
import TDN.MSC.Authentication
import TDN.Network.Protection

/-!
The protection stack is derived from admitted packet processing. Gray carries
one inner layer; Black carries an outer layer around that inner layer. Concrete
interface, filter, selector, and observed-SA facts provide the finite premise.
Generic induction covers arbitrary finite executions and preserves the exact
seal structure that connects each layer to an observed security association.
-/
namespace TDN.MSC.Protection
open Deployment
open TDN.Network (IPv4Header WirePacket XfrmPolicy XfrmState)
open TDN.Network.Execution
open TDN.Network.Protection
open TDN.MSC.Execution

def roleOfTag (request : Nat) : Option Role :=
  (tunnels.find? (fun tunnel => tunnel.reqid == request)).bind (fun tunnel => role? tunnel.owner)

def requiredStack (endpoint : Endpoint String) : List (Option Role) :=
  match floor endpoint with
  | 1 => [some .inner]
  | 2 => [some .outer, some .inner]
  | _ => []

def prefixCompatible (optional : Option Prefix) (selected : Prefix) : Bool :=
  optional.all (fun cidr => cidr.compatible selected)

def outputTagPossible (node : String) (rule : ForwardRule) : Option Nat → Bool
  | none => true
  | some request => (model.policies node).any fun policy =>
      policy.direction == "out" && policy.reqid == request &&
      prefixCompatible rule.source policy.source && prefixCompatible rule.destination policy.destination

/-- A matching rule and outgoing XFRM policy inspect the same source/destination.
Their compatibility removes impossible decrypt-and-reencrypt combinations from
the conservative tag signature without enumerating all IPv4 packet headers. -/
def stackSignature (node input output : String) (inputTag outputTag : Option Nat) : Bool :=
  ((forwardingTable? node).map fun table => table.rules.any (fun rule =>
    ruleSignature rule input output inputTag outputTag && outputTagPossible node rule outputTag) ||
      table.defaultAccept).getD false

theorem stack_transition_certificate : ∀ d ∈ devices,
    ∀ input ∈ ports d.id, ∀ output ∈ ports d.id,
    ∀ inputTag ∈ model.tags d.id, ∀ outputTag ∈ model.tags d.id,
    (inputTag.isSome = true → inputPossible d.id input = true) →
    stackSignature d.id input output inputTag outputTag = true →
    requiredStack ⟨d.id, output⟩ =
      transformed roleOfTag inputTag outputTag (requiredStack ⟨d.id, input⟩) := by decide

theorem wire_stacks_match : ∀ edge ∈ wires, requiredStack edge.1 = requiredStack edge.2 := by decide

theorem bridge_stacks_match : ∀ edge ∈ bridges, requiredStack edge.1 = requiredStack edge.2 := by decide

theorem observed_request_ids_identify_roles : ∀ observation ∈ operationalSnapshots,
    ∀ state ∈ observation.states.getD [], roleOfTag state.reqid = role? observation.device := by decide

theorem observed_state_owners_have_tunnels : ∀ observation ∈ operationalSnapshots,
    ∀ state ∈ observation.states.getD [], ∃ tunnel ∈ tunnels, tunnel.owner = observation.device := by decide

theorem inner_outer_tunnel_trusts_differ : ∀ outerTunnel ∈ tunnels, ∀ innerTunnel ∈ tunnels,
    role? outerTunnel.owner = some .outer → role? innerTunnel.owner = some .inner →
      outerTunnel.trust ≠ innerTunnel.trust := by decide

theorem observed_sa_identifies_owner_role (node : String) (state : XfrmState)
    (member : state ∈ model.states node) : roleOfTag state.reqid = role? node := by
  cases lookup : operational? node with
  | none => simp [Model.states, model, lookup] at member
  | some observation =>
    have observed : observation ∈ operationalSnapshots := List.mem_of_find?_eq_some lookup
    have identity : observation.device = node := by simpa using List.find?_some lookup
    have source : state ∈ observation.states.getD [] := by simpa [Model.states, model, lookup] using member
    simpa [identity] using observed_request_ids_identify_roles observation observed state source

theorem observed_sa_has_owner_tunnel (node : String) (state : XfrmState)
    (member : state ∈ model.states node) : ∃ tunnel ∈ tunnels, tunnel.owner = node := by
  cases lookup : operational? node with
  | none => simp [Model.states, model, lookup] at member
  | some observation =>
    have observed : observation ∈ operationalSnapshots := List.mem_of_find?_eq_some lookup
    have identity : observation.device = node := by simpa using List.find?_some lookup
    have source : state ∈ observation.states.getD [] := by simpa [Model.states, model, lookup] using member
    simpa [identity] using observed_state_owners_have_tunnels observation observed state source

/-- An admitted SA has a sampled CHILD/IKE session with matching request ID,
endpoints, and SPI, plus a complete peer request accepted by the credential
policy. The record keeps the certificate/CRL audit used for that request. -/
def AdmittedSA (node : String) (state : XfrmState) : Prop :=
  ∃ audit ∈ (Authentication.audit? node).toList,
    ∃ session ∈ Authentication.sessions node, ∃ child ∈ session.children,
      state.reqid = child.reqid ∧
      ((state.source = session.localAddress ∧ state.destination = session.remoteAddress ∧ state.spi = child.outboundSPI) ∨
       (state.source = session.remoteAddress ∧ state.destination = session.localAddress ∧ state.spi = child.inboundSPI)) ∧
      ∃ request, Authentication.sessionRequest? audit session = some request ∧
        TDN.Network.Authentication.admits (Authentication.policy node) audit request = true

theorem observed_layer_state_has_admitted_peer (node : String) (state : XfrmState)
    (member : state ∈ model.states node) : AdmittedSA node state := by
  obtain ⟨tunnel, tunnelMember, owner⟩ := observed_sa_has_owner_tunnel node state member
  have present := (Authentication.authentication_observations_complete.2.2 tunnel tunnelMember).1
  rw [owner] at present
  cases lookup : Authentication.audit? node with
  | none => simp [lookup] at present
  | some audit =>
    have auditMember : audit ∈ (Authentication.audit? tunnel.owner).toList := by simp [owner, lookup]
    have stateMember : state ∈ liveStates tunnel.owner := by
      simpa only [Model.states, model, liveStates, owner] using member
    have binding := Authentication.sampled_xfrm_state_has_admitted_peer tunnel tunnelMember audit auditMember state stateMember
    rw [owner] at binding
    exact ⟨audit, by simp [lookup], binding⟩

theorem optional_prefixes_with_shared_address_are_compatible (constraint : Option Prefix)
    (selected : Prefix) (address : UInt32)
    (allowed : constraint.all (fun cidr => cidr.contains address) = true)
    (selectedAddress : selected.contains address = true) : prefixCompatible constraint selected = true := by
  cases constraint with
  | none => rfl
  | some cidr =>
    exact TDN.Network.Prefix.shared_address_implies_compatible cidr selected address allowed selectedAddress

theorem matching_rule_and_policy_are_compatible (node : String) (rule : ForwardRule)
    (packet : RoutedPacket) (request : Nat) (policy : XfrmPolicy)
    (member : policy ∈ model.policies node) (direction : policy.direction = "out")
    (requestId : policy.reqid = request)
    (source : policy.source.contains packet.source = true)
    (destination : policy.destination.contains packet.destination = true)
    (matched : rule.matches packet = true) : outputTagPossible node rule (some request) = true := by
  have sourceAllowed : rule.source.all (fun cidr => cidr.contains packet.source) = true := by
    simp_all [ForwardRule.matches]
  have destinationAllowed : rule.destination.all (fun cidr => cidr.contains packet.destination) = true := by
    simp_all [ForwardRule.matches]
  have sourceCompatible := optional_prefixes_with_shared_address_are_compatible rule.source policy.source packet.source sourceAllowed source
  have destinationCompatible := optional_prefixes_with_shared_address_are_compatible rule.destination policy.destination packet.destination destinationAllowed destination
  simp only [outputTagPossible, List.any_eq_true]
  exact ⟨policy, member, by simp [direction, requestId, sourceCompatible, destinationCompatible]⟩

theorem accepted_forward_has_stack_signature (node input output : String) (header : IPv4Header)
    (inputTag outputTag : Option Nat)
    (selected : ∀ request, outputTag = some request → ∃ policy ∈ model.policies node,
      policy.direction = "out" ∧ policy.reqid = request ∧
      policy.source.contains header.source = true ∧ policy.destination.contains header.destination = true)
    (accepted : model.forwardFilter node input output header inputTag outputTag = true) :
    stackSignature node input output inputTag outputTag = true := by
  change (forwardDecision node (packetView input output header inputTag outputTag)).getD false = true at accepted
  cases lookup : forwardingTable? node with
  | none => simp [forwardDecision, lookup] at accepted
  | some table =>
    simp only [forwardDecision, lookup, Option.map_some, Option.getD_some,
      ForwardTable.accepts, Bool.or_eq_true, List.any_eq_true] at accepted
    simp only [stackSignature, lookup, Option.map_some, Option.getD_some,
      Bool.or_eq_true, List.any_eq_true, Bool.and_eq_true]
    rcases accepted with ⟨rule, member, matched⟩ | default
    · refine Or.inl ⟨rule, member, matching_rule_has_signature rule _ matched, ?_⟩
      cases tag : outputTag with
      | none => rfl
      | some request =>
        obtain ⟨policy, policyMember, direction, id, source, destination⟩ := selected request tag
        exact matching_rule_and_policy_are_compatible node rule _ request policy policyMember direction id source destination matched
    · exact Or.inr default

theorem processing_preserves_required_stack : ProcessingStack model roleOfTag requiredStack := by
  intro node input output header inputTag outputTag inputMember outputMember inTag outTag receiveAllowed selected filtered
  cases declared : device? node with
  | none => simp [model, ports, declared] at inputMember
  | some device =>
    have member : device ∈ devices := List.mem_of_find?_eq_some declared
    have identity : device.id = node := by simpa using List.find?_some declared
    have certificate := stack_transition_certificate device member
    rw [identity] at certificate
    apply certificate input inputMember output outputMember inputTag inTag outputTag outTag
    · intro tagged
      obtain ⟨wireHeader, accepted⟩ := receiveAllowed tagged
      exact accepted_input_has_port_signature node input wireHeader accepted
    · exact accepted_forward_has_stack_signature node input output header inputTag outputTag selected filtered

variable {Message : Type}

theorem forward_uses_imported_acceptance (node input : String)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result) :
    forwardDecision node (packetView input result.route.output result.body.header result.inputTag result.outputTag) = some true := by
  have filtered := (forward_evidence model node input packet result accepted).2.2.1
  change (forwardDecision node
    (packetView input result.route.output result.body.header result.inputTag result.outputTag)).getD false = true at filtered
  cases decision : forwardDecision node
      (packetView input result.route.output result.body.header result.inputTag result.outputTag) with
  | none => simp [decision] at filtered
  | some value =>
    have allowed : value = true := by simpa [decision] using filtered
    simp [allowed]

/-- IR-3 and OR-2 have a local all-packet consequence. Any successful forward
from a gateway's inside interface performs an observed sealing operation.
No Red-origin or prior-stack premise is needed for this local guarantee. -/
theorem gateway_outbound_forward_adds_observed_layer (contract : TrafficContract)
    (member : contract ∈ encryptorContracts) (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward contract.device contract.inside packet = some result) :
    ∃ state ∈ model.states contract.device, result.packet = result.body.seal state := by
  have present := (encryptor_contract_directions contract member).2
  cases policy : contract.policy with
  | none => simp [policy] at present
  | some request =>
    have imported := forward_uses_imported_acceptance contract.device contract.inside packet result accepted
    have tag := (accepted_outbound_requires_declared_policy contract member _ request policy rfl imported).1
    have sent := (forward_evidence model contract.device contract.inside packet result accepted).2.1
    rcases send_is_unchanged_or_observed_seal model contract.device result.body result.packet result.outputTag sent with unchanged | sealed
    · change result.outputTag = some request at tag
      simp [unchanged.2] at tag
    · obtain ⟨state, observed, equal, _⟩ := sealed
      exact ⟨state, observed, equal⟩

/-- IR-5 has a local all-packet consequence. Successful forwarding from the
external interface removes one authenticated wrapper before routing the body.
The generic receive operation checked the matching observed inbound state. -/
theorem gateway_inbound_forward_removes_layer (contract : TrafficContract)
    (member : contract ∈ encryptorContracts) (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward contract.device contract.outside packet = some result) :
    ∃ header identity, packet = .cipher header identity result.body := by
  have present := (encryptor_contract_directions contract member).2
  cases policy : contract.policy with
  | none => simp [policy] at present
  | some request =>
    have imported := forward_uses_imported_acceptance contract.device contract.outside packet result accepted
    have tag := (accepted_inbound_requires_declared_policy contract member _ request policy rfl imported).1
    have received := (forward_evidence model contract.device contract.outside packet result accepted).1
    rcases receive_is_unchanged_or_unwrapped model contract.device contract.outside packet result.body result.inputTag received with unchanged | unwrapped
    · change result.inputTag = some request at tag
      simp [unchanged.2] at tag
    · obtain ⟨header, identity, equal, _⟩ := unwrapped
      exact ⟨header, identity, equal⟩

theorem every_execution_preserves_required_stack {before after : State String Message}
    (path : TDN.Network.Reach (Step model) before after)
    (initial : StackInvariant roleOfTag requiredStack before) : StackInvariant roleOfTag requiredStack after :=
  executions_preserve_stack model roleOfTag requiredStack processing_preserves_required_stack
    (fun a b member => wire_stacks_match (a, b) member)
    (fun a b member => bridge_stacks_match (a, b) member) path initial

theorem clear_red_execution_has_required_stack (start : Endpoint String)
    (header : IPv4Header) (message : Message) (after : State String Message)
    (red : floor start = 0)
    (path : TDN.Network.Reach (Step model) ⟨start, .output, .clear header (some message)⟩ after) :
    layerLabels roleOfTag after.packet = requiredStack after.location := by
  have initial : StackInvariant roleOfTag requiredStack
      (⟨start, .output, .clear header (some message)⟩ : State String Message) := by
    intro _
    simp [layerLabels, requiredStack, red]
  have preserved := execution_preserves_message model path
  apply every_execution_preserves_required_stack path initial
  rw [← preserved]
  rfl

/-- The Black-side packet is the original Red datagram sealed by an observed
inner SA and then an observed outer SA. Role checks force different logical
appliances. The conclusion follows from any admitted finite path, including
loops, and preserves the same application message and original IPv4 header. -/
theorem red_payload_on_black_has_ordered_observed_layers (start : Endpoint String)
    (header : IPv4Header) (message : Message) (after : State String Message)
    (red : floor start = 0) (black : floor after.location = 2)
    (path : TDN.Network.Reach (Step model) ⟨start, .output, .clear header (some message)⟩ after) :
    ∃ outerNode outerState innerNode innerState,
      outerState ∈ model.states outerNode ∧ innerState ∈ model.states innerNode ∧
      role? outerNode = some .outer ∧ role? innerNode = some .inner ∧ outerNode ≠ innerNode ∧
      after.packet = ((WirePacket.clear header (some message)).seal innerState).seal outerState := by
  have generated : GeneratedLayers model after.packet :=
    executions_preserve_layer_provenance model path (.clear header (some message))
  have stack : layerLabels roleOfTag after.packet = [some .outer, some .inner] := by
    simpa [requiredStack, black] using clear_red_execution_has_required_stack start header message after red path
  obtain ⟨outerNode, outerState, innerNode, innerState, original, payload,
    outerMember, innerMember, outerTag, innerTag, nested⟩ :=
    generated_two_layer_structure model roleOfTag (some .outer) (some .inner) after.packet generated stack
  have outerRole := (observed_sa_identifies_owner_role outerNode outerState outerMember).symm.trans outerTag
  have innerRole := (observed_sa_identifies_owner_role innerNode innerState innerMember).symm.trans innerTag
  have different : outerNode ≠ innerNode := by
    intro same
    rw [same, innerRole] at outerRole
    cases outerRole
  have sameHeader := execution_preserves_original_header model path
  have sameMessage := execution_preserves_message model path
  rw [nested] at sameHeader sameMessage
  change header = original at sameHeader
  change some message = payload at sameMessage
  subst original payload
  exact ⟨outerNode, outerState, innerNode, innerState, outerMember, innerMember, outerRole, innerRole, different, nested⟩

/-- OR-4's retained Red-payload claim identifies the actual inner layer on a
Gray interface. A protocol field or wrapper count alone is insufficient. -/
theorem red_payload_on_gray_has_observed_inner_layer (start : Endpoint String)
    (header : IPv4Header) (message : Message) (after : State String Message)
    (red : floor start = 0) (gray : floor after.location = 1)
    (path : TDN.Network.Reach (Step model) ⟨start, .output, .clear header (some message)⟩ after) :
    ∃ node state, state ∈ model.states node ∧ role? node = some .inner ∧
      after.packet = (WirePacket.clear header (some message)).seal state := by
  have generated : GeneratedLayers model after.packet :=
    executions_preserve_layer_provenance model path (.clear header (some message))
  have stack : layerLabels roleOfTag after.packet = [some .inner] := by
    simpa [requiredStack, gray] using clear_red_execution_has_required_stack start header message after red path
  obtain ⟨node, state, original, payload, member, tag, sealed⟩ :=
    generated_one_layer_structure model roleOfTag (some .inner) after.packet generated stack
  have role := (observed_sa_identifies_owner_role node state member).symm.trans tag
  have sameHeader := execution_preserves_original_header model path
  have sameMessage := execution_preserves_message model path
  rw [sealed] at sameHeader sameMessage
  change header = original at sameHeader
  change some message = payload at sameMessage
  subst original payload
  exact ⟨node, state, member, role, sealed⟩

/-- The end-to-end stack guarantee and the credential-admission guarantee meet
at their shared observed SA witnesses. Neither theorem assumes the conclusion
of the other; both derive their premises from the pinned operational evidence. -/
theorem red_payload_on_black_has_admitted_ordered_layers (start : Endpoint String)
    (header : IPv4Header) (message : Message) (after : State String Message)
    (red : floor start = 0) (black : floor after.location = 2)
    (path : TDN.Network.Reach (Step model) ⟨start, .output, .clear header (some message)⟩ after) :
    ∃ outerNode outerState innerNode innerState,
      outerState ∈ model.states outerNode ∧ innerState ∈ model.states innerNode ∧
      role? outerNode = some .outer ∧ role? innerNode = some .inner ∧ outerNode ≠ innerNode ∧
      AdmittedSA outerNode outerState ∧ AdmittedSA innerNode innerState ∧
      after.packet = ((WirePacket.clear header (some message)).seal innerState).seal outerState := by
  obtain ⟨outerNode, outerState, innerNode, innerState, outerMember, innerMember,
    outerRole, innerRole, different, packet⟩ :=
    red_payload_on_black_has_ordered_observed_layers start header message after red black path
  exact ⟨outerNode, outerState, innerNode, innerState, outerMember, innerMember,
    outerRole, innerRole, different, observed_layer_state_has_admitted_peer outerNode outerState outerMember,
    observed_layer_state_has_admitted_peer innerNode innerState innerMember, packet⟩

/-- The two observed layers belong to distinct declared trust domains. Public
CA-object checks in MSC.Authentication separately ground those domain names in
the collected public anchors. Shared worker-kernel independence is not claimed. -/
theorem observed_inner_outer_layers_have_distinct_trust (outerNode innerNode : String)
    (outerState innerState : XfrmState)
    (outerMember : outerState ∈ model.states outerNode) (innerMember : innerState ∈ model.states innerNode)
    (outerRole : role? outerNode = some .outer) (innerRole : role? innerNode = some .inner) :
    ∃ outerTunnel ∈ tunnels, ∃ innerTunnel ∈ tunnels,
      outerTunnel.owner = outerNode ∧ innerTunnel.owner = innerNode ∧ outerTunnel.trust ≠ innerTunnel.trust := by
  obtain ⟨outerTunnel, outerTunnelMember, outerOwner⟩ := observed_sa_has_owner_tunnel outerNode outerState outerMember
  obtain ⟨innerTunnel, innerTunnelMember, innerOwner⟩ := observed_sa_has_owner_tunnel innerNode innerState innerMember
  refine ⟨outerTunnel, outerTunnelMember, innerTunnel, innerTunnelMember, outerOwner, innerOwner, ?_⟩
  exact inner_outer_tunnel_trusts_differ outerTunnel outerTunnelMember innerTunnel innerTunnelMember
    (by simpa [outerOwner] using outerRole) (by simpa [innerOwner] using innerRole)

end TDN.MSC.Protection
