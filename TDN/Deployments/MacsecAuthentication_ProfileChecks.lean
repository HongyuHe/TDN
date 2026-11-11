import TDN.Deployments.MacsecAuthentication_ProfileData

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 2000000

lemma profile_processing_coherent (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.deployment.ProcessingCoherent := by
  apply processing_coherence_from_record_checks capture.deployment capture.profile.inventory rfl
  · apply decide_eq_true
    rcases supported with rfl | rfl <;> decide
  · rfl
  · rfl

lemma profile_processing_bound (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.prototype.ProcessingBound capture.deployment := by
  refine ⟨profile_processing_coherent capture supported, ?_, capture.profile.inventory,
    rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_⟩
  · simp [Deployment.UDPBindingsCoherent, CaptureData.deployment, MacsecProtection.ProfileRecords.deployment]
  · simp [CaptureData.deployment, MacsecProtection.ProfileRecords.deployment]
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · simp [MacsecProtection.ProfileRecords.inventory]

lemma profile_interface_links (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.deployment.InterfaceLinksWellFormed := by
  have checked : ∀ edge ∈ capture.profile.links,
      (∃ interface ∈ capture.profile.interfaces, interface.id = capture.profile.ifaceName edge.1) ∧
      (∃ interface ∈ capture.profile.interfaces, interface.id = capture.profile.ifaceName edge.2) := by
    rcases supported with rfl | rfl <;> decide
  intro first second connected
  obtain ⟨edge, member, firstName, secondName⟩ := connected
  simpa only [CaptureData.deployment, MacsecProtection.ProfileRecords.deployment, firstName, secondName] using checked edge member

lemma profile_link_policies (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.deployment.LinkPoliciesComplete := by
  refine ⟨capture.profile.inventory, rfl, ?_, ?_, ?_⟩
  · have checked : ∀ iface ∈ capture.profile.inventory.ifaces,
        capture.deployment.LinkPath capture.profile.inventory iface →
        (LinkAdmission.lookup capture.profile.configuration.linkPolicies iface).isSome = true := by
      rcases supported with rfl | rfl <;>
        simp [Deployment.LinkPath, MacsecProtection.ProfileRecords.inventory, MacsecProtection.ProfileRecords.configuration,
          dataPlaneModelFromRecords, forward, reverse, LinkAdmission.lookup]
    intro iface member path
    have present := checked iface member path
    cases found : LinkAdmission.lookup capture.profile.configuration.linkPolicies iface with
    | none => simp [found] at present
    | some policy => exact ⟨policy, found⟩
  · rcases supported with rfl | rfl <;>
      simp [Deployment.LinkPath, MacsecProtection.ProfileRecords.inventory, MacsecProtection.ProfileRecords.configuration,
        dataPlaneModelFromRecords, forward, reverse]
  · rcases supported with rfl | rfl <;> decide

lemma profile_iface_conditions (capture : CaptureData) (supported : SupportedCapture capture) :
    IfaceConditions capture.profile.configuration (List.range capture.profile.ifaceData.length) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · rcases supported with rfl | rfl <;> decide
  · intro first second connected
    change (first, second) ∈ capture.profile.links at connected
    have checked : ∀ edge ∈ capture.profile.links,
        edge.1 ∈ List.range capture.profile.ifaceData.length ∧ edge.2 ∈ List.range capture.profile.ifaceData.length := by
      rcases supported with rfl | rfl <;> decide
    exact checked _ connected
  · simp [MacsecProtection.ProfileRecords.configuration, dataPlaneModelFromRecords]
  · rcases supported with rfl | rfl <;> decide
  · simp [MacsecProtection.ProfileRecords.configuration, dataPlaneModelFromRecords]

lemma profile_output_checks (capture : CaptureData) (supported : SupportedCapture capture) :
    MACsecOutputChecks capture.profile.configuration := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · simp [MacsecProtection.ProfileRecords.configuration, dataPlaneModelFromRecords]

lemma profile_wire_checks (capture : CaptureData) (supported : SupportedCapture capture) :
    MACsecWireChecks capture.profile.configuration := by
  refine ⟨profile_output_checks capture supported, ?_, ?_, rfl⟩
  · rcases supported with rfl | rfl <;> decide
  · intro first second connected receiver member same
    change (first, second) ∈ capture.profile.links at connected
    have checked : ∀ edge ∈ capture.profile.links, ∀ peer ∈ capture.profile.macIfaces,
        peer.physicalIface = edge.2 → ∃ sender ∈ capture.profile.macIfaces, sender.physicalIface = edge.1 := by
      rcases supported with rfl | rfl <;> decide
    exact checked _ connected receiver member same

lemma profile_link_encoding (capture : CaptureData) (supported : SupportedCapture capture)
    (state : MultiProtocolForwarding.State) (framed : PhysicalMACsecFrames capture.profile.configuration state) :
    capture.profile.configuration.LinkEncodingComplete state := by
  intro path
  rcases path with ⟨mac, configured, physical⟩ | ⟨next, bridge⟩ | ⟨carrier, configured, virtual⟩
  · obtain ⟨sender, member, association, body, installed, shape⟩ := framed mac configured physical.symm
    have checked : ∀ sender ∈ capture.profile.macIfaces, ∀ association ∈ sender.transmitAssociation.toList,
        ∃ encoded ∈ capture.profile.macFrames,
          encoded.1 = association ∧
          (capture.profile.macFrames.find? (fun entry => entry.1 == association)).map Prod.snd = some encoded.2 ∧
          encoded.2.DescribesBody (.macsec association body) := by
      dsimp only [LinkAdmission.Frame.DescribesBody]
      rcases supported with rfl | rfl <;> decide
    obtain ⟨encoded, member, same, found, describes⟩ := checked sender member association (by simp [installed])
    refine ⟨encoded.2, ?_, ?_⟩
    · simpa [MacsecProtection.ProfileRecords.configuration, shape] using found
    · simp only [LinkAdmission.Frame.Describes, Frame.visibleHeader, shape, Body.visibleHeader]
      exact ⟨describes, by simp⟩
  · simp [MacsecProtection.ProfileRecords.configuration, dataPlaneModelFromRecords] at bridge
  · simp [MacsecProtection.ProfileRecords.configuration, dataPlaneModelFromRecords] at configured

lemma profile_source_iface (capture : CaptureData) (supported : SupportedCapture capture)
    (request : PacketSource.Request)
    (allowed : (binding capture.prototype (List.range capture.profile.ifaceData.length)).SourceRequestAllowed
      capture.deployment request) : request.iface ∈ capture.profile.sourceIfaces := by
  obtain ⟨body, payload, origin⟩ := allowed
  change capture.profile.sourceEntry request.iface = some _ ∧ _ at origin
  have indexed : ∀ index ∈ [0, 1],
      (capture.profile.sourceIfaces[index]?.getD 0) ∈ capture.profile.sourceIfaces := by
    rcases supported with rfl | rfl <;> decide
  have atSource := origin.1
  unfold MacsecProtection.ProfileRecords.sourceEntry at atSource
  split at atSource
  next first =>
    rw [first]
    exact indexed 0 (by decide)
  next absent =>
    split at atSource
    next second =>
      rw [second]
      exact indexed 1 (by decide)
    next absent => cases atSource

lemma profile_initial_wire_safe (capture : CaptureData) (supported : SupportedCapture capture)
    (state : StandardDataPlaneBridge.State (List.range capture.profile.ifaceData.length))
    (initial : capture.model.initial state) :
    MACsecOutputProtected capture.profile.configuration state.native ∧ PhysicalMACsecFrames capture.profile.configuration state.native := by
  obtain ⟨sourceInitial, request, datagrams, datagram, source, allowed, emitted, member, same⟩ := initial
  have sourceIface := profile_source_iface capture supported request allowed
  have physicalSeparation : ∀ source ∈ capture.profile.sourceIfaces, ∀ mac ∈ capture.profile.macIfaces,
      source ≠ mac.physicalIface := by
    rcases supported with rfl | rfl <;> decide
  rw [same]
  refine ⟨?_, ?_⟩
  · simp [MACsecOutputProtected, DeviceExecutionBinding.SourceState, binding,
      DeviceExecutionBinding.withProjection, CaptureData.prototype, MacsecProtection.ProfileRecords.prototype]
  · intro mac configured sameIface
    exact False.elim (physicalSeparation request.iface sourceIface mac configured sameIface)

end TDN.Deployments.MacsecAuthentication
