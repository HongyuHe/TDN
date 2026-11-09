import TDN.Deployments.MtuSizing_Records

namespace TDN.Deployments.MtuSizing_Records
open Compliance Requirements OuterToGray_DeviceModel MultiProtocolForwarding


def RouteProgramCheck (records : Records) (roles : List SizingRole)
    (output : Bool) (route : DataPlaneForwarding.FibRoute) : Prop :=
  let configuration := records.configuration
  (requiredSizing roles route.egress = true ∨ configuration.ip.egressPolicies route.egress ≠ []) →
    (if output then configuration.ip.outputFallback else configuration.ip.forwardFallback) route.egress = .deny ∧
    DataPlaneForwarding.SizedProgramChecks []
      ((if output then configuration.ip.outputRules else configuration.ip.forwardRules) route.egress) route
      (configuration.ip.interfaceName route.ingress) (configuration.ip.interfaceName route.egress)
      (requiredSizing roles route.egress) (sourceMtu roles route.egress)
      (configuration.ip.egressPolicies route.egress) authenticationLimit plaintextLimit

instance (records : Records) (roles : List SizingRole) (output : Bool) (route : DataPlaneForwarding.FibRoute) :
    Decidable (RouteProgramCheck records roles output route) := by
  unfold RouteProgramCheck
  infer_instance


def SizeRecordChecks (records : Records) (installations : List PublicSARecord) (roles : List SizingRole) : Prop :=
  (∀ route ∈ records.routes, route.destPrefixHigh < 2^32) ∧
  (∀ record ∈ installations, record.installation.association.sender < 2^32 ∧
    record.installation.association.receiver < 2^32 ∧ record.installation.association.spi < 2^32) ∧
  (∀ device ∈ records.nativeDevices, ∀ policy ∈ device.egressPolicies,
    PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ 65535) ∧
  (∀ device ∈ records.nativeDevices, ∀ policy ∈ device.ingressPolicies,
    plaintextLimit policy.tag ≤ authenticationLimit policy.id) ∧
  (∀ edge ∈ records.bridges, requiredSizing roles edge.2 = false) ∧
  (∀ route ∈ records.routes, RouteProgramCheck records roles false route) ∧
  (∀ route ∈ records.routes, RouteProgramCheck records roles true route) ∧
  (∀ route ∈ records.routes, ∀ policy ∈ records.configuration.ip.egressPolicies route.ingress,
    route.destPrefixLow ≤ policy.receiver → policy.receiver ≤ route.destPrefixHigh → requiredSizing roles route.egress = true →
      PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ sourceMtu roles route.egress) ∧
  (∀ edge ∈ records.links, sourceMtu roles edge.1 ≤ sourceMtu roles edge.2) ∧
  (∀ edge ∈ records.bridges, sourceMtu roles edge.1 ≤ sourceMtu roles edge.2)

instance (records : Records) (installations : List PublicSARecord) (roles : List SizingRole) :
    Decidable (SizeRecordChecks records installations roles) := by
  unfold SizeRecordChecks
  infer_instance

lemma raw_device_member (devices : List DataPlaneForwarding.DeviceData) (owner : Nat)
    (policy : DataPlaneForwarding.IpsecPolicy) (outbound : Bool)
    (member : policy ∈ (if outbound then (DataPlaneForwarding.deviceAt devices owner).egressPolicies
      else (DataPlaneForwarding.deviceAt devices owner).ingressPolicies)) :
    ∃ device ∈ devices, policy ∈ (if outbound then device.egressPolicies else device.ingressPolicies) := by
  cases selected : devices[owner]? with
  | none =>
    cases outbound <;> simp [DataPlaneForwarding.deviceAt, selected] at member
  | some device =>
    refine ⟨device, List.mem_of_getElem? selected, ?_⟩
    simpa only [DataPlaneForwarding.deviceAt, selected, Option.getD_some] using member


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
      ((DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner) policy true member
    exact outboundBounds device deviceMember policy policyMember
  · intro iface policy member
    obtain ⟨device, deviceMember, policyMember⟩ := raw_device_member records.nativeDevices
      ((DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner) policy false member
    exact inboundBounds device deviceMember policy policyMember
  · intro first last member
    exact bridges (first,last) member
  · intro iface policy member route routeMember entry lower upper needed
    subst iface
    exact outerRoutes route routeMember policy member lower upper needed

end TDN.Deployments.MtuSizing_Records
