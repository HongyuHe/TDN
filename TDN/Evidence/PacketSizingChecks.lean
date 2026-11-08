import TDN.Evidence.PacketSizingRecords

namespace TDN.Imported.PacketSizingRecords
open Compliance Targets OuterGrayNativeModel MultiProtocolExecution


def RouteProgramCheck (records : Records) (roles : List SizingRole)
    (output : Bool) (route : Execution.Route) : Prop :=
  let configuration := records.configuration
  (requiredSizing roles route.egress = true ∨ configuration.ip.outbound route.egress ≠ []) →
    (if output then configuration.ip.outputFallback else configuration.ip.forwardFallback) route.egress = .deny ∧
    Execution.SizedProgramChecks []
      ((if output then configuration.ip.outputRules else configuration.ip.forwardRules) route.egress) route
      (configuration.ip.interfaceName route.ingress) (configuration.ip.interfaceName route.egress)
      (requiredSizing roles route.egress) (sourceMtu roles route.egress)
      (configuration.ip.outbound route.egress) authenticationLimit plaintextLimit

instance (records : Records) (roles : List SizingRole) (output : Bool) (route : Execution.Route) :
    Decidable (RouteProgramCheck records roles output route) := by
  unfold RouteProgramCheck
  infer_instance


def SizeRecordChecks (records : Records) (installations : List PublicSARecord) (roles : List SizingRole) : Prop :=
  (∀ route ∈ records.routes, route.high < 2^32) ∧
  (∀ record ∈ installations, record.installation.association.sender < 2^32 ∧
    record.installation.association.receiver < 2^32 ∧ record.installation.association.wireIdentity < 2^32) ∧
  (∀ device ∈ records.nativeDevices, ∀ policy ∈ device.outbound,
    PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ 65535) ∧
  (∀ device ∈ records.nativeDevices, ∀ policy ∈ device.inbound,
    plaintextLimit policy.tag ≤ authenticationLimit policy.id) ∧
  (∀ edge ∈ records.bridges, requiredSizing roles edge.2 = false) ∧
  (∀ route ∈ records.routes, RouteProgramCheck records roles false route) ∧
  (∀ route ∈ records.routes, RouteProgramCheck records roles true route) ∧
  (∀ route ∈ records.routes, ∀ policy ∈ records.configuration.ip.outbound route.ingress,
    route.low ≤ policy.receiver → policy.receiver ≤ route.high → requiredSizing roles route.egress = true →
      PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ sourceMtu roles route.egress) ∧
  (∀ edge ∈ records.links, sourceMtu roles edge.1 ≤ sourceMtu roles edge.2) ∧
  (∀ edge ∈ records.bridges, sourceMtu roles edge.1 ≤ sourceMtu roles edge.2)

instance (records : Records) (installations : List PublicSARecord) (roles : List SizingRole) :
    Decidable (SizeRecordChecks records installations roles) := by
  unfold SizeRecordChecks
  infer_instance

lemma raw_device_member (devices : List Execution.DeviceData) (owner : Nat)
    (policy : Execution.Association) (outbound : Bool)
    (member : policy ∈ (if outbound then (Execution.deviceAt devices owner).outbound
      else (Execution.deviceAt devices owner).inbound)) :
    ∃ device ∈ devices, policy ∈ (if outbound then device.outbound else device.inbound) := by
  cases selected : devices[owner]? with
  | none =>
    cases outbound <;> simp [Execution.deviceAt, selected] at member
  | some device =>
    refine ⟨device, List.mem_of_getElem? selected, ?_⟩
    simpa only [Execution.deviceAt, selected, Option.getD_some] using member


theorem size_checks_from_captured_records {Key : Type} (records : Records)
    (installations : List PublicSARecord) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (codec : IPsecFrameEncoding.Codec Key)
    (checked : SizeRecordChecks records installations roles) :
    SizeChecks (completeConfiguration records installations policies codec)
      (requiredSizing roles) (sourceMtu roles) plaintextLimit authenticationLimit ∧
    EthernetMTUChecks (completeConfiguration records installations policies codec) (sourceMtu roles) := by
  obtain ⟨routeBound, stateBounds, outboundBounds, inboundBounds, bridges, forward, output,
    outerRoutes, physicalMtu, bridgeMtu⟩ := checked
  refine ⟨⟨rfl, rfl, fun _ _ => rfl, routeBound, ?_, ?_, ?_, ?_, forward, output, ?_⟩,
    ⟨fun first last member => physicalMtu (first,last) member,
      fun first last member => bridgeMtu (first,last) member⟩⟩
  · intro iface policy association configured installed bound
    obtain ⟨record, member, owner, direction, same⟩ :=
      (directional_state_member installations _ .outbound association).mp installed
    have bounds := stateBounds record member
    rw [same] at bounds
    exact bounds
  · intro iface policy member
    obtain ⟨device, deviceMember, policyMember⟩ := raw_device_member records.nativeDevices
      ((Execution.ifaceAt records.nativeIfaces iface).owner) policy true member
    exact outboundBounds device deviceMember policy policyMember
  · intro iface policy member
    obtain ⟨device, deviceMember, policyMember⟩ := raw_device_member records.nativeDevices
      ((Execution.ifaceAt records.nativeIfaces iface).owner) policy false member
    exact inboundBounds device deviceMember policy policyMember
  · intro first last member
    exact bridges (first,last) member
  · intro iface policy member route routeMember entry lower upper needed
    subst iface
    exact outerRoutes route routeMember policy member lower upper needed

end TDN.Imported.PacketSizingRecords
