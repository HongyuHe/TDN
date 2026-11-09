import TDN.Models.MultiProtocolBoundaryDecryption
import TDN.Models.TableDrivenMultiProtocolDataPlane

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def ignoresTracking : PacketPolicy.MatchCondition → Bool
  | .connectionStates _ | .networkBytesRange _ _ | .ethernetHeaderBytes _ | .ipsecUDPFraming | .ipsecUDPFramingWithOptions | .ipsecUDPReplyFramingWithOptions => false
  | _ => true

lemma atom_holds_ignores_tracking (atom : PacketPolicy.MatchCondition) (packet : PacketPolicy.Packet)
    (tracking : String) (networkBytes : Option Nat) (independent : ignoresTracking atom = true) :
    atom.matchesPacket { packet with connectionState := tracking, networkBytes := networkBytes } ↔ atom.matchesPacket packet := by
  cases atom <;> simp_all only [ignoresTracking, Bool.false_eq_true, PacketPolicy.MatchCondition.matchesPacket, PacketPolicy.Packet.MKAFraming]

def carrierRecordPacket (device : DataPlaneForwarding.DeviceData) (entry : DataPlaneForwarding.IfaceData)
    (tracking : String) (networkBytes : Option Nat) (iface : CarrierIface) : PacketPolicy.Packet :=
  { carrierReceiveHeader iface with
    ingress := entry.name, egress := entry.name,
    matchedInboundPolicyIds := [],
    matchedOutboundPolicyIds := (DataPlaneForwarding.lookupSpdPolicies device.egressPolicies
      (carrierReceiveHeader iface)).map DataPlaneForwarding.IpsecPolicy.id,
    connectionState := tracking, networkBytes := networkBytes }

def TableDrivenCarrierInputChecks (devices : List DataPlaneForwarding.DeviceData)
    (ifaces : List DataPlaneForwarding.IfaceData) (carriers : List CarrierIface) (tag : Nat) : Prop :=
  ∀ carrier ∈ carriers, ∀ entry ∈ ({} : DataPlaneForwarding.IfaceData) :: ifaces,
    entry.owner = (DataPlaneForwarding.ifaceAt ifaces carrier.routingIface).owner →
    tag ∈ entry.stack →
    tag ∈ (DataPlaneForwarding.ifaceAt ifaces carrier.virtualIface).stack ∨
    ((DataPlaneForwarding.deviceAt devices entry.owner).inputFallback = .deny ∧
      ∀ rule ∈ (DataPlaneForwarding.deviceAt devices entry.owner).inputRules,
        rule.verdict = .allow → ∃ atom ∈ rule.atoms, ignoresTracking atom = true ∧
          ¬ atom.matchesPacket (carrierRecordPacket (DataPlaneForwarding.deviceAt devices entry.owner)
            entry "" none carrier))

instance (devices : List DataPlaneForwarding.DeviceData) (ifaces : List DataPlaneForwarding.IfaceData)
    (carriers : List CarrierIface) (tag : Nat) :
    Decidable (TableDrivenCarrierInputChecks devices ifaces carriers tag) := by
  unfold TableDrivenCarrierInputChecks
  infer_instance

theorem table_driven_carrier_input_checks_sound (devices : List DataPlaneForwarding.DeviceData)
    (ifaces : List DataPlaneForwarding.IfaceData) (routes : List DataPlaneForwarding.FibRoute)
    (links bridges : List (Nat × Nat)) (macIfaces : List MACIface) (carriers : List CarrierIface)
    (tag : Nat) (checked : TableDrivenCarrierInputChecks devices ifaces carriers tag) :
    CarrierInputCheck (dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers)
      (DataPlaneForwarding.expectedEncapStackFromRecords ifaces) tag := by
  intro carrier configured entry tracking networkBytes owner outside accepted
  rcases checked carrier configured (DataPlaneForwarding.ifaceAt ifaces entry)
      (DataPlaneForwarding.iface_at_member_or_default ifaces entry) owner outside with inside | ⟨fallback, rules⟩
  · exact inside
  · change DataPlaneForwarding.accepts (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).inputRules
      (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).inputFallback
      (carrierRecordPacket (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner)
        (DataPlaneForwarding.ifaceAt ifaces entry) tracking networkBytes carrier) at accepted
    rw [fallback] at accepted
    obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
    obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
    obtain ⟨atom, atomMember, independent, rejected⟩ := rules rule inRules allow
    have holds := PacketPolicy.matching_atom matched atomMember
    exact False.elim (rejected ((atom_holds_ignores_tracking atom
      (carrierRecordPacket (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner)
        (DataPlaneForwarding.ifaceAt ifaces entry) "" none carrier) tracking networkBytes independent).mp holds))

end TDN.MultiProtocolForwarding
