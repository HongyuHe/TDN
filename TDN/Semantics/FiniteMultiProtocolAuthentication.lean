import TDN.Semantics.MultiProtocolAuthentication
import TDN.Semantics.FiniteMultiProtocol

namespace TDN.MultiProtocolExecution
open LayeredFrame

def ignoresTracking : PacketPolicy.Atom → Bool
  | .connectionStates _ => false
  | _ => true

lemma atom_holds_ignores_tracking (atom : PacketPolicy.Atom) (packet : PacketPolicy.Packet)
    (tracking : String) (independent : ignoresTracking atom = true) :
    atom.holds { packet with connectionState := tracking } ↔ atom.holds packet := by
  cases atom <;> simp_all only [ignoresTracking, Bool.false_eq_true, PacketPolicy.Atom.holds]

def carrierRecordPacket (device : Execution.DeviceData) (entry : Execution.PortData)
    (tracking : String) (port : CarrierPort) : PacketPolicy.Packet :=
  { carrierReceiveHeader port with
    ingress := entry.name, egress := entry.name,
    inboundPolicies := [],
    outboundPolicies := (Execution.selectedAssociations device.outbound
      (carrierReceiveHeader port)).map Execution.Association.id,
    connectionState := tracking }

def FiniteCarrierInputChecks (devices : List Execution.DeviceData)
    (ports : List Execution.PortData) (carriers : List CarrierPort) (tag : Nat) : Prop :=
  ∀ carrier ∈ carriers, ∀ entry ∈ ({} : Execution.PortData) :: ports,
    entry.owner = (Execution.portAt ports carrier.routingPort).owner →
    tag ∈ entry.stack →
    tag ∈ (Execution.portAt ports carrier.virtualPort).stack ∨
    ((Execution.deviceAt devices entry.owner).inputFallback = .deny ∧
      ∀ rule ∈ (Execution.deviceAt devices entry.owner).inputRules,
        rule.verdict = .allow → ∃ atom ∈ rule.atoms, ignoresTracking atom = true ∧
          ¬ atom.holds (carrierRecordPacket (Execution.deviceAt devices entry.owner)
            entry "" carrier))

instance (devices : List Execution.DeviceData) (ports : List Execution.PortData)
    (carriers : List CarrierPort) (tag : Nat) :
    Decidable (FiniteCarrierInputChecks devices ports carriers tag) := by
  unfold FiniteCarrierInputChecks
  infer_instance

theorem finite_carrier_input_checks_sound (devices : List Execution.DeviceData)
    (ports : List Execution.PortData) (routes : List Execution.Route)
    (links bridges : List (Nat × Nat)) (macPorts : List MACPort) (carriers : List CarrierPort)
    (tag : Nat) (checked : FiniteCarrierInputChecks devices ports carriers tag) :
    CarrierInputCheck (finiteConfig devices ports routes links bridges macPorts carriers)
      (Execution.finiteLayout ports) tag := by
  intro carrier configured entry tracking owner outside accepted
  rcases checked carrier configured (Execution.portAt ports entry)
      (Execution.port_at_member_or_default ports entry) owner outside with inside | ⟨fallback, rules⟩
  · exact inside
  · change Execution.accepts (Execution.deviceAt devices (Execution.portAt ports entry).owner).inputRules
      (Execution.deviceAt devices (Execution.portAt ports entry).owner).inputFallback
      (carrierRecordPacket (Execution.deviceAt devices (Execution.portAt ports entry).owner)
        (Execution.portAt ports entry) tracking carrier) at accepted
    rw [fallback] at accepted
    obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
    obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
    obtain ⟨atom, atomMember, independent, rejected⟩ := rules rule inRules allow
    have holds := PacketPolicy.matching_atom matched atomMember
    exact False.elim (rejected ((atom_holds_ignores_tracking atom
      (carrierRecordPacket (Execution.deviceAt devices (Execution.portAt ports entry).owner)
        (Execution.portAt ports entry) "" carrier) tracking independent).mp holds))

end TDN.MultiProtocolExecution
