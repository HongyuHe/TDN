import TDN.Semantics.MultiProtocolAuthentication
import TDN.Semantics.FiniteMultiProtocol

namespace TDN.MultiProtocolExecution
open LayeredFrame

def ignoresTracking : PacketPolicy.Atom → Bool
  | .connectionStates _ | .networkBytesRange _ _ | .ethernetHeaderBytes _ | .ipsecUDPFraming | .ipsecUDPFramingWithOptions | .ipsecUDPReplyFramingWithOptions => false
  | _ => true

lemma atom_holds_ignores_tracking (atom : PacketPolicy.Atom) (packet : PacketPolicy.Packet)
    (tracking : String) (networkBytes : Option Nat) (independent : ignoresTracking atom = true) :
    atom.holds { packet with connectionState := tracking, networkBytes := networkBytes } ↔ atom.holds packet := by
  cases atom <;> simp_all only [ignoresTracking, Bool.false_eq_true, PacketPolicy.Atom.holds, PacketPolicy.Packet.MKAFraming]

def carrierRecordPacket (device : Execution.DeviceData) (entry : Execution.IfaceData)
    (tracking : String) (networkBytes : Option Nat) (iface : CarrierIface) : PacketPolicy.Packet :=
  { carrierReceiveHeader iface with
    ingress := entry.name, egress := entry.name,
    inboundPolicies := [],
    outboundPolicies := (Execution.selectedAssociations device.outbound
      (carrierReceiveHeader iface)).map Execution.Association.id,
    connectionState := tracking, networkBytes := networkBytes }

def FiniteCarrierInputChecks (devices : List Execution.DeviceData)
    (ifaces : List Execution.IfaceData) (carriers : List CarrierIface) (tag : Nat) : Prop :=
  ∀ carrier ∈ carriers, ∀ entry ∈ ({} : Execution.IfaceData) :: ifaces,
    entry.owner = (Execution.ifaceAt ifaces carrier.routingIface).owner →
    tag ∈ entry.stack →
    tag ∈ (Execution.ifaceAt ifaces carrier.virtualIface).stack ∨
    ((Execution.deviceAt devices entry.owner).inputFallback = .deny ∧
      ∀ rule ∈ (Execution.deviceAt devices entry.owner).inputRules,
        rule.verdict = .allow → ∃ atom ∈ rule.atoms, ignoresTracking atom = true ∧
          ¬ atom.holds (carrierRecordPacket (Execution.deviceAt devices entry.owner)
            entry "" none carrier))

instance (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (carriers : List CarrierIface) (tag : Nat) :
    Decidable (FiniteCarrierInputChecks devices ifaces carriers tag) := by
  unfold FiniteCarrierInputChecks
  infer_instance

theorem finite_carrier_input_checks_sound (devices : List Execution.DeviceData)
    (ifaces : List Execution.IfaceData) (routes : List Execution.Route)
    (links bridges : List (Nat × Nat)) (macIfaces : List MACIface) (carriers : List CarrierIface)
    (tag : Nat) (checked : FiniteCarrierInputChecks devices ifaces carriers tag) :
    CarrierInputCheck (dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers)
      (Execution.expectedEncapStackFromRecords ifaces) tag := by
  intro carrier configured entry tracking networkBytes owner outside accepted
  rcases checked carrier configured (Execution.ifaceAt ifaces entry)
      (Execution.iface_at_member_or_default ifaces entry) owner outside with inside | ⟨fallback, rules⟩
  · exact inside
  · change Execution.accepts (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inputRules
      (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner).inputFallback
      (carrierRecordPacket (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner)
        (Execution.ifaceAt ifaces entry) tracking networkBytes carrier) at accepted
    rw [fallback] at accepted
    obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
    obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
    obtain ⟨atom, atomMember, independent, rejected⟩ := rules rule inRules allow
    have holds := PacketPolicy.matching_atom matched atomMember
    exact False.elim (rejected ((atom_holds_ignores_tracking atom
      (carrierRecordPacket (Execution.deviceAt devices (Execution.ifaceAt ifaces entry).owner)
        (Execution.ifaceAt ifaces entry) "" none carrier) tracking networkBytes independent).mp holds))

end TDN.MultiProtocolExecution
