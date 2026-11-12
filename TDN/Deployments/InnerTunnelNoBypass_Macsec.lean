import TDN.Requirements.MACsecLayerBoundaryChecks
import TDN.Deployments.MacsecProtection_TrafficExamples
import Mathlib.Tactic.IntervalCases

namespace TDN.Deployments.InnerTunnelNoBypass_Macsec
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame
open MacsecProtection

abbrev records := MacsecProtection.direct
abbrev deployment := records.deployment
abbrev forwarding := records.model

def receiveTarget (_ : PayloadId) (iface : String) : Option String :=
  if iface = records.ifaceName 1 then some (records.componentName 0)
  else if iface = records.ifaceName 3 then some (records.componentName 1) else none

def components : List EncryptionComponentConfiguration :=
  records.devices.map (fun device =>
    { id := device.id, mechanism := .macsec, espTunnelMode := false, associatedIPTunnel := false,
      outboundMACPolicy := false, inboundMACPolicy := false })

lemma source_ifaces (iface : Nat) (network : String)
    (entry : forwarding.native.sourceEntry iface = some network) : iface = 0 ∨ iface = 2 := by
  by_cases first : iface = 0
  · exact Or.inl first
  by_cases second : iface = 2
  · exact Or.inr second
  have missing : forwarding.native.sourceEntry iface = none := by
    change records.sourceEntry iface = none
    simp [ProfileRecords.sourceEntry, records, direct, first, second]
  rw [missing] at entry
  cases entry

lemma initial_frames (state : MultiProtocolForwarding.State)
    (initial : forwarding.native.SourceInitial deployment state) :
    MACsecOutputProtected forwarding.native.configuration state ∧
      PhysicalMACsecFrames forwarding.native.configuration state := by
  have origin := initial.2.2.2
  change state.datapathStage = .received ∧ forwarding.native.sourceEntry state.iface = some _ ∧ _ at origin
  have separation : ∀ source ∈ ([0, 2] : List Nat), ∀ mac ∈ records.macIfaces,
      source ≠ mac.physicalIface := by native_decide
  refine ⟨by simp [MACsecOutputProtected, origin.1], ?_⟩
  intro mac configured same
  have source := source_ifaces state.iface _ origin.2.1
  apply False.elim
  apply separation state.iface (by simpa using source) mac configured
  exact same

lemma gate_checks : MACsecIngressGateChecks forwarding.native deployment .inner receiveTarget := by
  refine ⟨profile_wire_checks records (Or.inl rfl), ?_, ?_, ?_, ?_, initial_frames, ?_⟩
  · change ∀ first last, ¬ ((first, last) ∈ ([] : List (Nat × Nat)))
    simp
  · change ∀ iface ∈ records.macIfaces, iface.validateStrict = true
    native_decide
  · intro payload iface network entry
    rcases source_ifaces iface network entry with rfl | rfl <;> rfl
  · intro payload iface component selected
    change receiveTarget payload (records.ifaceName iface) = some component at selected
    by_cases present : iface < 4
    · interval_cases iface
      all_goals
        first
        | exact ⟨records.macIfaces[0], by native_decide, rfl⟩
        | exact ⟨records.macIfaces[1], by native_decide, rfl⟩
        | simp [receiveTarget, ProfileRecords.ifaceName, DataPlaneForwarding.ifaceAt, records, direct] at selected
    · have missing : records.ifaceData[iface]? = none := by
        apply List.getElem?_eq_none
        simpa [records, direct] using (show 4 ≤ iface by omega)
      have emptyName : records.ifaceName iface = "" := by
        change (records.ifaceData[iface]?.getD {}).name = ""
        rw [missing]
        rfl
      rw [emptyName] at selected
      have impossible : receiveTarget payload "" = none := rfl
      rw [impossible] at selected
      cases selected
  · intro payload iface component sender transmitted receiver association selected senderMember installed
      receiverMember physical associationMember wire
    subst iface
    have checked : ∀ sender ∈ records.macIfaces, ∀ transmitted ∈ sender.transmitAssociation.toList,
        ∀ receiver ∈ records.macIfaces, ∀ association ∈ receiver.receiveAssociations,
        SameMACWireIdentity transmitted association →
        ∃ tunnel ∈ deployment.tunnels, tunnel.id = forwarding.native.macsecTunnel transmitted ∧
          tunnel.layer = .inner ∧ receiveTarget ⟨0, 0⟩ (records.ifaceName receiver.physicalIface) = some tunnel.receiver := by
      native_decide
    obtain ⟨tunnel, member, name, layer, target⟩ :=
      checked sender senderMember transmitted (by simp [installed]) receiver receiverMember association associationMember wire
    exact ⟨tunnel, member, name, layer, Option.some.inj (target.symm.trans selected)⟩

lemma outbound_checks : MACsecLayerBoundaryChecks forwarding.native deployment .inner := by
  refine ⟨profile_wire_checks records (Or.inl rfl), fun state initial => (initial_frames state initial).1, ?_, ?_⟩
  · intro first last linked
    change (first, last) ∈ records.links at linked
    have checked : ∀ edge ∈ records.links, ∀ interface ∈ deployment.interfaces,
        interface.id = records.ifaceName edge.2 → deployment.IsLayer interface.device .inner →
        interface.zone ≠ InternalZone .inner := by
      unfold Deployment.IsLayer
      native_decide
    exact checked (first, last) linked
  · intro first last linked interface stored name layer
    change (first, last) ∈ records.links at linked
    have checked : ∀ edge ∈ records.links, ∀ interface ∈ deployment.interfaces,
        interface.id = records.ifaceName edge.1 → deployment.IsLayer interface.device .inner →
        interface.zone ≠ InternalZone .inner ∧ ∃ mac ∈ records.macIfaces,
          edge.1 = mac.physicalIface ∧ ∀ association ∈ mac.transmitAssociation.toList,
          ∃ tunnel ∈ deployment.tunnels, tunnel.layer = .inner ∧ tunnel.sender = interface.device ∧
            tunnel.id = forwarding.native.macsecTunnel association := by
      unfold Deployment.IsLayer
      native_decide
    obtain ⟨outside, mac, member, physical, tunnels⟩ := checked (first,last) linked interface stored name layer
    exact ⟨outside, mac, member, physical, fun association installed => tunnels association (by simp [installed])⟩

lemma target_binding : InboundGateReceiversBound deployment forwarding.GenuineControl .inner receiveTarget := by
  have checked : ∀ interface ∈ deployment.interfaces, deployment.IsLayer interface.device .inner →
      interface.zone = ExternalZone .inner → receiveTarget ⟨0,0⟩ interface.id = some interface.device := by
    unfold Deployment.IsLayer
    native_decide
  intro payload data interface stored layer external
  exact checked interface stored layer external

lemma component_coverage : ComponentConfigurationCoverage deployment .inner components := by
  unfold ComponentConfigurationCoverage Deployment.Relevant
  native_decide
lemma component_parameters : ∀ component ∈ components, deployment.Relevant component.id →
    (component.mechanism = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
    (false = true → component.outboundMACPolicy = true) ∧
    (false = true → component.inboundMACPolicy = true) := by
  unfold Deployment.Relevant
  native_decide
theorem snapshot_RG029_macsec_inner_tunnel_no_bypass :
    msc_inner_tunnel_no_bypass deployment forwarding components false false := by
  have covered := profile_deployment_is_covered records (Or.inl rfl)
  exact inner_tunnel_no_bypass_from_outbound_and_inbound_checks deployment forwarding components false false receiveTarget
    covered (macsecLayerOutboundChecks forwarding deployment .inner covered outbound_checks)
    (macsecIngressDeviceGate forwarding.native deployment .inner receiveTarget gate_checks)
    target_binding component_coverage component_parameters

theorem snapshot_RG029_macsec_nonempty_payload_delivered :
    ∃ start actions finish, forwarding.initial start ∧ forwarding.system.MTr start actions finish ∧
      (forwarding.native.state finish).datapathStage = .delivered ∧
      (forwarding.native.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (forwarding.native.state finish).frame.body = records.trafficDatagram.body :=
  profile_nonempty_payload_is_delivered records (Or.inl rfl)

end TDN.Deployments.InnerTunnelNoBypass_Macsec
