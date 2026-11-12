import TDN.Deployments.MacsecProtection_ProfileData

namespace TDN.Deployments.MacsecProtection
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

def SupportedProfile (records : ProfileRecords) : Prop := records = direct ∨ records = routed

lemma profile_processing_coherent (records : ProfileRecords) (supported : SupportedProfile records) :
    records.deployment.ProcessingCoherent := by
  apply processing_coherence_from_record_checks records.deployment records.inventory rfl
  · apply decide_eq_true
    rcases supported with rfl | rfl <;> native_decide
  · rfl
  · rfl

lemma profile_processing_bound (records : ProfileRecords) (supported : SupportedProfile records) :
    records.prototype.ProcessingBound records.deployment := by
  refine ⟨profile_processing_coherent records supported, ?_, records.inventory,
    rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_⟩
  · simp [Deployment.UDPBindingsCoherent, ProfileRecords.deployment]
  · simp [ProfileRecords.deployment]
  · rcases supported with rfl | rfl <;> native_decide
  · rcases supported with rfl | rfl <;> native_decide
  · simp [ProfileRecords.inventory]

lemma profile_interface_links (records : ProfileRecords) (supported : SupportedProfile records) :
    records.deployment.InterfaceLinksWellFormed := by
  have checked : ∀ edge ∈ records.links,
      (∃ interface ∈ records.interfaces, interface.id = records.ifaceName edge.1) ∧
      (∃ interface ∈ records.interfaces, interface.id = records.ifaceName edge.2) := by
    rcases supported with rfl | rfl <;> native_decide
  intro first second connected
  obtain ⟨edge, member, firstName, secondName⟩ := connected
  simpa only [ProfileRecords.deployment, firstName, secondName] using checked edge member

lemma profile_link_policies (records : ProfileRecords) (supported : SupportedProfile records) :
    records.deployment.LinkPoliciesComplete := by
  refine ⟨records.inventory, rfl, ?_, ?_, ?_⟩
  · have checked : ∀ iface ∈ records.inventory.ifaces,
        records.deployment.LinkPath records.inventory iface →
        (LinkAdmission.lookup records.configuration.linkPolicies iface).isSome = true := by
      rcases supported with rfl | rfl <;>
        simp [Deployment.LinkPath, ProfileRecords.inventory, ProfileRecords.configuration,
          dataPlaneModelFromRecords, direct, routed, LinkAdmission.lookup]
    intro iface member path
    have present := checked iface member path
    cases found : LinkAdmission.lookup records.configuration.linkPolicies iface with
    | none => simp [found] at present
    | some policy => exact ⟨policy, found⟩
  · rcases supported with rfl | rfl <;>
      simp [Deployment.LinkPath, ProfileRecords.inventory, ProfileRecords.configuration,
        dataPlaneModelFromRecords, direct, routed]
  · rcases supported with rfl | rfl <;> native_decide

lemma profile_iface_conditions (records : ProfileRecords) (supported : SupportedProfile records) :
    IfaceConditions records.configuration (List.range records.ifaceData.length) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · rcases supported with rfl | rfl <;> native_decide
  · intro first second connected
    change (first, second) ∈ records.links at connected
    have checked : ∀ edge ∈ records.links,
        edge.1 ∈ List.range records.ifaceData.length ∧ edge.2 ∈ List.range records.ifaceData.length := by
      rcases supported with rfl | rfl <;> native_decide
    exact checked _ connected
  · simp [ProfileRecords.configuration, dataPlaneModelFromRecords]
  · rcases supported with rfl | rfl <;> native_decide
  · simp [ProfileRecords.configuration, dataPlaneModelFromRecords]

lemma profile_output_checks (records : ProfileRecords) (supported : SupportedProfile records) :
    MACsecOutputChecks records.configuration := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · rcases supported with rfl | rfl <;> native_decide
  · rcases supported with rfl | rfl <;> native_decide
  · rcases supported with rfl | rfl <;> native_decide
  · simp [ProfileRecords.configuration, dataPlaneModelFromRecords]

lemma profile_wire_checks (records : ProfileRecords) (supported : SupportedProfile records) :
    MACsecWireChecks records.configuration := by
  refine ⟨profile_output_checks records supported, ?_, ?_, rfl⟩
  · rcases supported with rfl | rfl <;> native_decide
  · intro first second connected receiver member same
    change (first, second) ∈ records.links at connected
    have checked : ∀ edge ∈ records.links, ∀ peer ∈ records.macIfaces,
        peer.physicalIface = edge.2 → ∃ sender ∈ records.macIfaces, sender.physicalIface = edge.1 := by
      rcases supported with rfl | rfl <;> native_decide
    exact checked _ connected receiver member same

lemma profile_link_encoding (records : ProfileRecords) (supported : SupportedProfile records)
    (state : MultiProtocolForwarding.State) (framed : PhysicalMACsecFrames records.configuration state) :
    records.configuration.LinkEncodingComplete state := by
  intro path
  rcases path with ⟨mac, configured, physical⟩ | ⟨next, bridge⟩ | ⟨carrier, configured, virtual⟩
  · obtain ⟨sender, member, association, body, installed, shape⟩ := framed mac configured physical.symm
    have checked : ∀ sender ∈ records.macIfaces, ∀ association ∈ sender.transmitAssociation.toList,
        ∃ encoded ∈ records.macFrames,
          encoded.1 = association ∧
          (records.macFrames.find? (fun entry => entry.1 == association)).map Prod.snd = some encoded.2 ∧
          encoded.2.DescribesBody (.macsec association body) := by
      dsimp only [LinkAdmission.Frame.DescribesBody]
      rcases supported with rfl | rfl <;> native_decide
    obtain ⟨encoded, member, same, found, describes⟩ := checked sender member association (by simp [installed])
    refine ⟨encoded.2, ?_, ?_⟩
    · simpa [ProfileRecords.configuration, shape] using found
    · simp only [LinkAdmission.Frame.Describes, Frame.visibleHeader, shape, Body.visibleHeader]
      exact ⟨describes, by simp⟩
  · simp [ProfileRecords.configuration, dataPlaneModelFromRecords] at bridge
  · simp [ProfileRecords.configuration, dataPlaneModelFromRecords] at configured

lemma profile_source_iface (records : ProfileRecords) (supported : SupportedProfile records)
    (request : PacketSource.Request)
    (allowed : (binding records.prototype (List.range records.ifaceData.length)).SourceRequestAllowed
      records.deployment request) : request.iface ∈ records.sourceIfaces := by
  obtain ⟨body, payload, origin⟩ := allowed
  change records.sourceEntry request.iface = some _ ∧ _ at origin
  have atSource := origin.1
  unfold ProfileRecords.sourceEntry at atSource
  split at atSource
  · rcases supported with rfl | rfl <;> simp_all [direct, routed]
  · split at atSource
    · rcases supported with rfl | rfl <;> simp_all [direct, routed]
    · cases atSource

lemma profile_initial_wire_safe (records : ProfileRecords) (supported : SupportedProfile records)
    (state : StandardDataPlaneBridge.State (List.range records.ifaceData.length))
    (initial : records.model.initial state) :
    MACsecOutputProtected records.configuration state.native ∧ PhysicalMACsecFrames records.configuration state.native := by
  obtain ⟨sourceInitial, request, datagrams, datagram, source, allowed, emitted, member, same⟩ := initial
  have sourceIface := profile_source_iface records supported request allowed
  have physicalSeparation : ∀ source ∈ records.sourceIfaces, ∀ mac ∈ records.macIfaces,
      source ≠ mac.physicalIface := by
    rcases supported with rfl | rfl <;> native_decide
  rw [same]
  refine ⟨?_, ?_⟩
  · simp [MACsecOutputProtected, DeviceExecutionBinding.SourceState, binding,
      DeviceExecutionBinding.withProjection, ProfileRecords.prototype]
  · intro mac configured sameIface
    exact False.elim (physicalSeparation request.iface sourceIface mac configured sameIface)

end TDN.Deployments.MacsecProtection
