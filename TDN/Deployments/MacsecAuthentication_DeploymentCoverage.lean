import TDN.Deployments.MacsecAuthentication_ProfileChecks
import TDN.Requirements.ObservedHistoryChecks
import TDN.Deployments.MacsecAuthentication_AuthenticationChecks
import Mathlib.Tactic.IntervalCases

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 2000000

lemma profile_source_entries (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ iface network, capture.prototype.sourceEntry iface = some network ↔
      ∃ interface ∈ capture.deployment.interfaces, interface.id = capture.prototype.ifaceName iface ∧
        interface.zone = .red ∧ interface.managementNetwork = false ∧
        ∃ red ∈ capture.deployment.networks, red.id = network ∧ interface.device ∈ red.innerComponents := by
  intro iface network
  change capture.profile.sourceEntry iface = some network ↔
    ∃ interface ∈ capture.profile.interfaces, interface.id = capture.profile.ifaceName iface ∧
      interface.zone = .red ∧ interface.managementNetwork = false ∧
      ∃ red ∈ capture.profile.networks, red.id = network ∧ interface.device ∈ red.innerComponents
  rcases supported with rfl | rfl
  · by_cases present : iface < 6
    · interval_cases iface <;>
        simp [CaptureData.prototype, MacsecProtection.ProfileRecords.prototype, MacsecProtection.ProfileRecords.sourceEntry, CaptureData.deployment, MacsecProtection.ProfileRecords.deployment,
          MacsecProtection.ProfileRecords.ifaceName, DataPlaneForwarding.ifaceAt, forward]
    · have outside : 6 ≤ iface := by omega
      have missing : forward.profile.ifaceData[iface]? = none := by
        apply List.getElem?_eq_none
        simpa [forward] using outside
      have nameEmpty : forward.profile.ifaceName iface = "" := by
        change (forward.profile.ifaceData[iface]?.getD {}).name = ""
        rw [missing]
        rfl
      have notFirst : iface ≠ 0 := by omega
      have notSecond : iface ≠ 2 := by omega
      rw [nameEmpty]
      simp [MacsecProtection.ProfileRecords.sourceEntry, notFirst, notSecond, forward]
  · by_cases present : iface < 9
    · interval_cases iface <;>
        simp [CaptureData.prototype, MacsecProtection.ProfileRecords.prototype, MacsecProtection.ProfileRecords.sourceEntry, CaptureData.deployment, MacsecProtection.ProfileRecords.deployment,
          MacsecProtection.ProfileRecords.ifaceName, DataPlaneForwarding.ifaceAt, reverse]
    · have outside : 9 ≤ iface := by omega
      have missing : reverse.profile.ifaceData[iface]? = none := by
        apply List.getElem?_eq_none
        simpa [reverse] using outside
      have nameEmpty : reverse.profile.ifaceName iface = "" := by
        change (reverse.profile.ifaceData[iface]?.getD {}).name = ""
        rw [missing]
        rfl
      have notFirst : iface ≠ 0 := by omega
      have notSecond : iface ≠ 3 := by omega
      rw [nameEmpty]
      simp [MacsecProtection.ProfileRecords.sourceEntry, notFirst, notSecond, reverse]

lemma profile_static_bindings (capture : CaptureData) (supported : SupportedCapture capture) :
    DeviceDeploymentBindings capture.prototype (List.range capture.profile.ifaceData.length) capture.deployment := by
  refine ⟨profile_processing_bound capture supported,
    profile_interface_links capture supported, profile_link_policies capture supported,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    profile_source_entries capture supported, ?_, ?_⟩
  · exact ⟨capture.profile.inventory, rfl, ⟨fun _ => 64, fun _ => 64⟩, rfl, fun _ _ => by change 0 < 64 ∧ 64 ≤ 255 ∧ 0 < 64 ∧ 64 ≤ 255; decide⟩
  · intro iface member association installed
    refine ⟨capture.material, rfl, Or.inr ?_⟩
    rcases supported with rfl | rfl <;> decide
  · simp [DeviceExecutionBinding.IPsecKeyInventory, CaptureData.prototype, MacsecProtection.ProfileRecords.prototype, MacsecProtection.ProfileRecords.configuration]
  · rcases supported with rfl | rfl <;> decide
  · intro tunnel member
    exact ⟨tunnel, member, rfl, rfl⟩
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · have checked : ∀ interface ∈ capture.profile.interfaces,
        ∃ iface ∈ List.range capture.profile.ifaceData.length,
          capture.profile.ifaceName iface = interface.id ∧
          capture.profile.componentName (capture.profile.configuration.ip.owner iface) = interface.device := by
      rcases supported with rfl | rfl <;> decide
    intro interface member
    obtain ⟨iface, present, same, owner⟩ := checked interface member
    exact ⟨iface, same, owner⟩
  · rcases supported with rfl | rfl <;> decide
  · intro first last connected
    exact ⟨(first, last), connected, rfl, rfl⟩
  · have checked : ∀ iface ∈ capture.profile.macIfaces,
        ∀ association ∈ iface.transmitAssociation.toList,
        ∃ tunnel ∈ capture.profile.tunnels,
          tunnel.id = capture.profile.macsecTunnel association ∧ tunnel.mechanism = .macsec ∧
          tunnel.keyContext = capture.prototype.keyName association.keyGeneration ∧
          tunnel.sender = capture.profile.componentName (capture.profile.configuration.ip.owner iface.physicalIface) ∧
          ∀ peer ∈ capture.profile.macIfaces,
            (∃ installed ∈ peer.receiveAssociations, SameMACWireIdentity association installed) →
            tunnel.receiver = capture.profile.componentName (capture.profile.configuration.ip.owner peer.physicalIface) := by
      rcases supported with rfl | rfl <;> decide
    intro iface member association installed
    exact checked iface member association (by simp [installed])
  · simp [CaptureData.prototype, MacsecProtection.ProfileRecords.prototype, MacsecProtection.ProfileRecords.configuration]

def CaptureData.sampleRequest (capture : CaptureData) (index : Nat) : PacketSource.Request :=
  { iface := capture.profile.sourceIfaces[index]?.getD 0, originDomain := index
    body := .ethernet ⟨1, 2, 34997, []⟩
    application := [7, 8], networkHeaderBytes := 14, transportHeaderBytes := 0
    mode := .datagram false }

def sampleDatagram : PacketSource.Datagram :=
  (PacketSource.encodeSourceEthernet ⟨1, 2, 34997, []⟩ [7, 8]).asWhole

lemma profile_network_sources (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ network ∈ capture.deployment.networks, ∃ request datagrams,
      (binding capture.prototype (List.range capture.profile.ifaceData.length)).SourceRequestAllowed
        capture.deployment request ∧ request.application ≠ [] ∧
      capture.prototype.origin request.originDomain = .red network.id ∧
      capture.prototype.sourceProcessing.process request = .emitted datagrams := by
  have checked : ∀ network ∈ capture.profile.networks, ∃ index ∈ [0, 1],
      capture.profile.sourceEntry (capture.sampleRequest index).iface = some network.id ∧
      capture.prototype.origin index = .red network.id ∧
      capture.prototype.sourceProcessing.process (capture.sampleRequest index) = .emitted [sampleDatagram] := by
    rcases supported with rfl | rfl
    all_goals
      intro network member
      simp only [forward, reverse, List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl
      · exact ⟨0, by decide, rfl, rfl, rfl⟩
      · exact ⟨1, by decide, rfl, rfl, rfl⟩
  intro network member
  obtain ⟨index, chosen, entry, origin, emitted⟩ := checked network member
  refine ⟨capture.sampleRequest index, [sampleDatagram], ?_, by simp [CaptureData.sampleRequest], origin, emitted⟩
  refine ⟨Or.inr ⟨⟨1, 2, 34997, []⟩, rfl⟩, True.intro, ?_⟩
  change capture.profile.sourceEntry (capture.sampleRequest index).iface = some _ ∧ _
  have name : (if index = 0 then "red-0" else "red-1") = network.id := PayloadOrigin.red.inj origin
  change capture.profile.sourceEntry (capture.sampleRequest index).iface = some (if index = 0 then "red-0" else "red-1") ∧
    ∃ red ∈ capture.deployment.networks, red.id = (if index = 0 then "red-0" else "red-1")
  rw [name]
  exact ⟨entry, network, member, rfl⟩

theorem profile_empty_history_model_is_covered (capture : CaptureData) (supported : SupportedCapture capture) :
    (StandardDataPlaneBridge.model capture.prototype (List.range capture.profile.ifaceData.length)
      capture.deployment {}).CoversDeployment capture.deployment := by
  apply macsec_model_covers_deployment capture.prototype (List.range capture.profile.ifaceData.length)
    capture.deployment (profile_static_bindings capture supported)
    (profile_iface_conditions capture supported) (profile_wire_checks capture supported)
    ⟨fun _ => 64, fun _ => 64⟩ rfl (fun _ => by change 64 ≤ 255 ∧ 64 ≤ 255; decide)
    (profile_initial_wire_safe capture supported) (profile_link_encoding capture supported)
    (fun _ => 1500) rfl (fun _ => by change 1280 ≤ 1500; decide) rfl
  · intro request allowed
    have member := profile_source_iface capture supported request allowed
    have checked : ∀ source ∈ capture.profile.sourceIfaces, source ∈ List.range capture.profile.ifaceData.length := by
      rcases supported with rfl | rfl <;> decide
    exact checked request.iface member
  · exact profile_network_sources capture supported

theorem profile_deployment_is_covered (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.model.CoversDeployment capture.deployment := by
  exact deployment_coverage_with_history (profile_empty_history_model_is_covered capture supported)
    capture.history (profile_history_valid capture supported)
    (capture.setupRecords.map MACsecSetupRecord.installation)
    (fun reference => if reference = capture.sak then some capture.material else none)

end TDN.Deployments.MacsecAuthentication
