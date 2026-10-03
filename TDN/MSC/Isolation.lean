import TDN.MSC.Execution
import TDN.Network.SourcePolicy

/-!
The isolation proof follows admitted executions, including routes, XFRM
processing, filters, and switching. Its local invariant constrains the source
of clear traffic leaving an inner encryptor for Red. A wire certificate carries
the same constraint to the adjacent host. Induction propagates the constraint
through every finite execution. Disjoint Red address ranges then establish
security-level isolation for packets with a source in their originating range.

The original source header is preserved by this fixed-state IPv4 model. The
source-range premise describes legitimate host addressing. Authentication of
the physical sender and arbitrary spoofed-origin claims need further reasoning.
-/
namespace TDN.MSC.Isolation
open Deployment
open TDN.Network (IPv4Header WirePacket LabeledPrefix)
open TDN.Network.Execution
open TDN.Network.SourcePolicy
open TDN.MSC.Execution

def requiredSource (endpoint : Endpoint String) (phase : Phase) : Option Prefix := do
  let device ← device? endpoint.node
  let port ← device.interfaces.find? (fun i => i.name == endpoint.port)
  if port.zone != .red then none else
  let inner ← match device.role, phase with
    | .inner, .output => some device.id
    | .host, .input => (redNeighbors device.id).head?
    | _, _ => none
  let tunnel ← tunnel? inner
  Prefix.parse? tunnel.remoteSelector

def redDomains : List (LabeledPrefix (Option SecurityLevel)) :=
  devices.filterMap fun device =>
    if device.role == .host then
      (redPrefix? device.id).map fun network => ⟨device.level, network⟩
    else none

/-- Every observed virtual wire propagates the applicable source constraint.
Ports with no constraint can freely receive traffic; a required receiving
constraint must be supplied by the sending port. -/
theorem wires_preserve_source_constraint : ∀ edge ∈ wires,
    Compatible (requiredSource edge.1 .output) (requiredSource edge.2 .input) := by decide

theorem bridges_preserve_source_constraint : ∀ edge ∈ bridges,
    Compatible (requiredSource edge.1 .input) (requiredSource edge.2 .output) := by decide

/-- The imported rule certificate covers every possible outgoing interface.
Every accepting rule on a constrained output must explicitly require its
source range. The table's default must also deny. -/
theorem forwarding_source_certificate : ∀ table ∈ forwardTables,
    ∀ output ∈ ports table.device,
    ∀ network ∈ (requiredSource ⟨table.device, output⟩ .output).toList,
    table.defaultAccept = false ∧
    ∀ rule ∈ table.rules, optionalMatch rule.output output = true →
      rule.source = some network := by decide

theorem red_domains_separate_levels : ∀ a ∈ redDomains, ∀ b ∈ redDomains,
    a.label ≠ b.label → a.network.sameWidthApart b.network = true := by decide

theorem hosts_have_red_domains : ∀ host ∈ devices, host.role = .host →
    (redPrefix? host.id).isSome = true ∧
    ∀ network ∈ (redPrefix? host.id).toList, ⟨host.level, network⟩ ∈ redDomains := by decide

theorem host_input_source_domains : ∀ host ∈ devices, host.role = .host →
    ∀ port ∈ host.interfaces, port.zone = .red →
    (requiredSource ⟨host.id, port.name⟩ .input).isSome = true ∧
    ∀ network ∈ (requiredSource ⟨host.id, port.name⟩ .input).toList,
      ⟨host.level, network⟩ ∈ redDomains := by decide

theorem host_output_unconstrained : ∀ host ∈ devices, host.role = .host →
    ∀ port ∈ host.interfaces, requiredSource ⟨host.id, port.name⟩ .output = none := by decide

/-- An inner can forward only between its Red and Gray ports. No rule permits
same-side transit, and the sampled inner has no switch-bridge transition. -/
theorem inner_direction_certificate : ∀ table ∈ forwardTables,
    role? table.device = some .inner → table.defaultAccept = false ∧
    ∀ rule ∈ table.rules,
      (rule.input = some "red" ∧ rule.output = some "gray") ∨
      (rule.input = some "gray" ∧ rule.output = some "red") := by decide

theorem inner_switching_absent : ∀ edge ∈ bridges, role? edge.1.node ≠ some .inner := by decide

theorem inner_red_wire_reaches_host : ∀ edge ∈ wires,
    role? edge.1.node = some .inner → edge.1.port = "red" →
      role? edge.2.node = some .host := by decide

variable {Message : Type}

theorem inner_forward_crosses_red_boundary (node input : String) (inner : role? node = some .inner)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result) :
    (input = "red" ∧ result.route.output = "gray") ∨
    (input = "gray" ∧ result.route.output = "red") := by
  have filtered := (forward_evidence model node input packet result accepted).2.2.1
  change (forwardDecision node
    (packetView input result.route.output result.body.header result.inputTag result.outputTag)).getD false = true at filtered
  cases lookup : forwardingTable? node with
  | none => simp [forwardDecision, lookup] at filtered
  | some table =>
    have member : table ∈ forwardTables := List.mem_of_find?_eq_some lookup
    have identity : table.device = node := by simpa using List.find?_some lookup
    obtain ⟨deny, directions⟩ := inner_direction_certificate table member (by simpa [identity] using inner)
    simp only [forwardDecision, lookup, Option.map_some, Option.getD_some,
      ForwardTable.accepts, deny, Bool.or_false, List.any_eq_true] at filtered
    obtain ⟨rule, member, matched⟩ := filtered
    rcases directions rule member with outgoing | incoming
    · left
      simp_all [ForwardRule.matches, optionalMatch, packetView]
    · right
      simp_all [ForwardRule.matches, optionalMatch, packetView]

/-- SR-17's routing consequence follows from admitted operations. Traffic
received from Gray can leave an inner only toward its adjacent Red host.
There is no inner switch transition and no Gray-to-Gray routing transition. -/
theorem inner_gray_forward_reaches_only_red_host (node : String) (inner : role? node = some .inner)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node "gray" packet = some result)
    (next : Endpoint String) (linked : model.linked ⟨node, result.route.output⟩ next) :
    result.route.output = "red" ∧ role? next.node = some .host := by
  have direction := inner_forward_crosses_red_boundary node "gray" inner packet result accepted
  have output : result.route.output = "red" := by simpa using direction
  exact ⟨output, inner_red_wire_reaches_host _ linked inner output⟩

/-- Hosts terminate Red-side transit because sampled IPv4 forwarding is off. -/
theorem host_forwarding_disabled (host : Device) (member : host ∈ devices)
    (role : host.role = .host) (input : String) (packet : WirePacket Message) :
    model.forward host.id input packet = none := by
  have disabled : ((model.observed host.id).bind TDN.Network.OperationalSnapshot.forwarding) = some false := by
    have observed := observed_forwarding_matches_roles host member
    rw [role] at observed
    exact observed
  simp [Model.forward, disabled]

/-- A successful forwarding operation exposes the actual matched rule. For a
clear result, its original source header is the header inspected by the
filter. The finite rule certificate therefore establishes the local invariant
for every packet header, regardless of address, protocol, or message type. -/
theorem forwarding_establishes_source_constraint (node input : String)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward node input packet = some result) :
    Checked requiredSource ⟨⟨node, result.route.output⟩, .output, result.packet⟩ := by
  intro network required clear
  have filtered := clear_forward_filter_uses_original_header model node input packet result accepted clear
  have outputUp := (forward_evidence model node input packet result accepted).2.2.2.2
  have retained := live_port_is_retained model node result.route.output _ outputUp
  change result.route.output ∈ ports node at retained
  change (forwardDecision node
    (packetView input result.route.output result.packet.originalHeader result.inputTag result.outputTag)).getD false = true at filtered
  cases lookup : forwardingTable? node with
  | none => simp [forwardDecision, lookup] at filtered
  | some table =>
    have member : table ∈ forwardTables := List.mem_of_find?_eq_some lookup
    have identity : table.device = node := by simpa using List.find?_some lookup
    have certificate := forwarding_source_certificate table member result.route.output
    rw [identity] at certificate
    obtain ⟨deny, rules⟩ := certificate retained network (by simpa using required)
    simp only [forwardDecision, lookup, Option.map_some, Option.getD_some,
      ForwardTable.accepts, deny, Bool.or_false, List.any_eq_true] at filtered
    obtain ⟨rule, inTable, matched⟩ := filtered
    have outputMatched : optionalMatch rule.output result.route.output = true := by
      simp_all [ForwardRule.matches, packetView]
    have source := rules rule inTable outputMatched
    simp_all [ForwardRule.matches, packetView]

/-- Source constraints survive arbitrary admitted executions. The reusable
induction uses finite wire/bridge certificates and the local forwarding lemma.
No bound on path length or restriction against revisiting a device is needed. -/
theorem executions_preserve_source_constraint {before after : State String Message}
    (path : TDN.Network.Reach (Step model) before after)
    (initial : Checked requiredSource before) : Checked requiredSource after :=
  executions_preserve_source_policy model requiredSource
    (fun a b edge => wires_preserve_source_constraint (a, b) edge)
    (fun a b edge => bridges_preserve_source_constraint (a, b) edge)
    forwarding_establishes_source_constraint path initial

/-- A retained host has an observed empty XFRM policy list. Successful local
delivery consequently means that the packet arrived clear and unchanged. -/
theorem host_delivery_arrives_clear (host : Device) (member : host ∈ devices)
    (role : host.role = .host) (port : String) (packet delivered : WirePacket Message)
    (accepted : model.deliver host.id port packet = some delivered) :
    packet.depth = 0 ∧ delivered = packet := by
  apply delivery_without_xfrm_is_clear model host.id port packet delivered _ accepted
  have empty := (red_hosts_have_no_xfrm host member role).1
  simp only [Model.policies, model, empty, Option.getD_some]

/-- N-01's same-security-level communication restriction follows from packet execution.
A correctly addressed source host can deliver a clear datagram only to a host
with the same security label. The claim concerns this fixed sampled state and
the modeled IPv4 operations; labels have no dominance ordering. -/
theorem delivered_host_traffic_preserves_level
    (source target : Device) (sourceMember : source ∈ devices) (targetMember : target ∈ devices)
    (sourceRole : source.role = .host) (targetRole : target.role = .host)
    (sourcePort targetPort : Interface) (sourcePortMember : sourcePort ∈ source.interfaces)
    (targetPortMember : targetPort ∈ target.interfaces) (targetRed : targetPort.zone = .red)
    (sourceNetwork : Prefix) (sourcePrefix : redPrefix? source.id = some sourceNetwork)
    (header : IPv4Header) (message : Option Message)
    (sourceAddress : sourceNetwork.contains header.source = true)
    (packet delivered : WirePacket Message)
    (path : TDN.Network.Reach (Step model)
      ⟨⟨source.id, sourcePort.name⟩, .output, .clear header message⟩
      ⟨⟨target.id, targetPort.name⟩, .input, packet⟩)
    (accepted : model.deliver target.id targetPort.name packet = some delivered) :
    source.level = target.level := by
  have initial : Checked requiredSource
      (⟨⟨source.id, sourcePort.name⟩, .output, .clear header message⟩ : State String Message) := by
    intro network required _
    have absent := host_output_unconstrained source sourceMember sourceRole sourcePort sourcePortMember
    simp [absent] at required
  have constrained := executions_preserve_source_constraint path initial
  obtain ⟨clear, _⟩ := host_delivery_arrives_clear target targetMember targetRole _ packet delivered accepted
  obtain ⟨present, targetDomain⟩ := host_input_source_domains target targetMember targetRole
    targetPort targetPortMember targetRed
  cases required : requiredSource ⟨target.id, targetPort.name⟩ .input with
  | none => simp [required] at present
  | some network =>
    have inTarget := constrained network required clear
    have preserved := execution_preserves_original_header model path
    change header = packet.originalHeader at preserved
    change network.contains packet.originalHeader.source = true at inTarget
    rw [← preserved] at inTarget
    exact TDN.Network.labeled_prefix_members_share_label redDomains red_domains_separate_levels
      ⟨source.level, sourceNetwork⟩ ⟨target.level, network⟩
      ((hosts_have_red_domains source sourceMember sourceRole).2 sourceNetwork (by simpa using sourcePrefix))
      (targetDomain network (by simpa using required)) header.source sourceAddress inTarget

end TDN.MSC.Isolation
