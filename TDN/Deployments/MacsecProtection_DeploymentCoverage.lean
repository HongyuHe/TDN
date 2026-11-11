import TDN.Deployments.MacsecProtection_ProfileChecks
import Mathlib.Tactic.IntervalCases

namespace TDN.Deployments.MacsecProtection
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

lemma profile_source_entries (records : ProfileRecords) (supported : SupportedProfile records) :
    ∀ iface network, records.prototype.sourceEntry iface = some network ↔
      ∃ interface ∈ records.deployment.interfaces, interface.id = records.prototype.ifaceName iface ∧
        interface.zone = .red ∧ interface.managementNetwork = false ∧
        ∃ red ∈ records.deployment.networks, red.id = network ∧ interface.device ∈ red.innerComponents := by
  intro iface network
  change records.sourceEntry iface = some network ↔
    ∃ interface ∈ records.interfaces, interface.id = records.ifaceName iface ∧
      interface.zone = .red ∧ interface.managementNetwork = false ∧
      ∃ red ∈ records.networks, red.id = network ∧ interface.device ∈ red.innerComponents
  rcases supported with rfl | rfl
  · by_cases present : iface < 4
    · interval_cases iface <;>
        simp [ProfileRecords.prototype, ProfileRecords.sourceEntry, ProfileRecords.deployment,
          ProfileRecords.ifaceName, DataPlaneForwarding.ifaceAt, direct]
    · have outside : 4 ≤ iface := by omega
      have missing : direct.ifaceData[iface]? = none := by
        apply List.getElem?_eq_none
        simpa [direct] using outside
      have nameEmpty : direct.ifaceName iface = "" := by
        change (direct.ifaceData[iface]?.getD {}).name = ""
        rw [missing]
        rfl
      have notFirst : iface ≠ 0 := by omega
      have notSecond : iface ≠ 2 := by omega
      rw [nameEmpty]
      simp [ProfileRecords.sourceEntry, notFirst, notSecond, direct]
  · by_cases present : iface < 7
    · interval_cases iface <;>
        simp [ProfileRecords.prototype, ProfileRecords.sourceEntry, ProfileRecords.deployment,
          ProfileRecords.ifaceName, DataPlaneForwarding.ifaceAt, routed]
    · have outside : 7 ≤ iface := by omega
      have missing : routed.ifaceData[iface]? = none := by
        apply List.getElem?_eq_none
        simpa [routed] using outside
      have nameEmpty : routed.ifaceName iface = "" := by
        change (routed.ifaceData[iface]?.getD {}).name = ""
        rw [missing]
        rfl
      have notFirst : iface ≠ 0 := by omega
      have notSecond : iface ≠ 3 := by omega
      rw [nameEmpty]
      simp [ProfileRecords.sourceEntry, notFirst, notSecond, routed]

lemma profile_static_bindings (records : ProfileRecords) (supported : SupportedProfile records) :
    DeviceDeploymentBindings records.prototype (List.range records.ifaceData.length) records.deployment := by
  refine ⟨profile_processing_bound records supported,
    profile_interface_links records supported, profile_link_policies records supported,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    profile_source_entries records supported, ?_, ?_⟩
  · exact ⟨records.inventory, rfl, ⟨fun _ => 64, fun _ => 64⟩, rfl, fun _ _ => by change 0 < 64 ∧ 64 ≤ 255 ∧ 0 < 64 ∧ 64 ≤ 255; decide⟩
  · intro iface member association installed
    exact ⟨List.replicate 16 (UInt8.ofNat association.keyGeneration), rfl, Or.inl (by simp)⟩
  · simp [DeviceExecutionBinding.IPsecKeyInventory, ProfileRecords.prototype, ProfileRecords.configuration]
  · rcases supported with rfl | rfl <;> decide
  · intro tunnel member
    exact ⟨tunnel, member, rfl, rfl⟩
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · rcases supported with rfl | rfl <;> decide
  · have checked : ∀ interface ∈ records.interfaces,
        ∃ iface ∈ List.range records.ifaceData.length,
          records.ifaceName iface = interface.id ∧
          records.componentName (records.configuration.ip.owner iface) = interface.device := by
      rcases supported with rfl | rfl <;> decide
    intro interface member
    obtain ⟨iface, present, same, owner⟩ := checked interface member
    exact ⟨iface, same, owner⟩
  · rcases supported with rfl | rfl <;> decide
  · intro first last connected
    exact ⟨(first, last), connected, rfl, rfl⟩
  · have checked : ∀ iface ∈ records.macIfaces,
        ∀ association ∈ iface.transmitAssociation.toList,
        ∃ tunnel ∈ records.tunnels,
          tunnel.id = records.macsecTunnel association ∧ tunnel.mechanism = .macsec ∧
          tunnel.keyContext = records.prototype.keyName association.keyGeneration ∧
          tunnel.sender = records.componentName (records.configuration.ip.owner iface.physicalIface) ∧
          ∀ peer ∈ records.macIfaces,
            (∃ installed ∈ peer.receiveAssociations, SameMACWireIdentity association installed) →
            tunnel.receiver = records.componentName (records.configuration.ip.owner peer.physicalIface) := by
      rcases supported with rfl | rfl <;> decide
    intro iface member association installed
    exact checked iface member association (by simp [installed])
  · simp [ProfileRecords.prototype, ProfileRecords.configuration]

def ProfileRecords.sampleRequest (records : ProfileRecords) (index : Nat) : PacketSource.Request :=
  { iface := records.sourceIfaces[index]?.getD 0, originDomain := index
    body := .ethernet ⟨1, 2, 34997, []⟩
    application := [7, 8], networkHeaderBytes := 14, transportHeaderBytes := 0
    mode := .datagram false }

def sampleDatagram : PacketSource.Datagram :=
  (PacketSource.encodeSourceEthernet ⟨1, 2, 34997, []⟩ [7, 8]).asWhole

lemma profile_network_sources (records : ProfileRecords) (supported : SupportedProfile records) :
    ∀ network ∈ records.deployment.networks, ∃ request datagrams,
      (binding records.prototype (List.range records.ifaceData.length)).SourceRequestAllowed
        records.deployment request ∧ request.application ≠ [] ∧
      records.prototype.origin request.originDomain = .red network.id ∧
      records.prototype.sourceProcessing.process request = .emitted datagrams := by
  have checked : ∀ network ∈ records.networks, ∃ index ∈ [0, 1],
      records.sourceEntry (records.sampleRequest index).iface = some network.id ∧
      records.prototype.origin index = .red network.id ∧
      records.prototype.sourceProcessing.process (records.sampleRequest index) = .emitted [sampleDatagram] := by
    rcases supported with rfl | rfl
    all_goals
      intro network member
      simp only [direct, routed, List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl
      · exact ⟨0, by decide, rfl, rfl, rfl⟩
      · exact ⟨1, by decide, rfl, rfl, rfl⟩
  intro network member
  obtain ⟨index, chosen, entry, origin, emitted⟩ := checked network member
  refine ⟨records.sampleRequest index, [sampleDatagram], ?_, by simp [ProfileRecords.sampleRequest], origin, emitted⟩
  refine ⟨Or.inr ⟨⟨1, 2, 34997, []⟩, rfl⟩, True.intro, ?_⟩
  change records.sourceEntry (records.sampleRequest index).iface = some _ ∧ _
  have name : (if index = 0 then "red-0" else "red-1") = network.id := PayloadOrigin.red.inj origin
  change records.sourceEntry (records.sampleRequest index).iface = some (if index = 0 then "red-0" else "red-1") ∧
    ∃ red ∈ records.deployment.networks, red.id = (if index = 0 then "red-0" else "red-1")
  rw [name]
  exact ⟨entry, network, member, rfl⟩

theorem profile_deployment_is_covered (records : ProfileRecords) (supported : SupportedProfile records) :
    records.model.CoversDeployment records.deployment := by
  apply macsec_model_covers_deployment records.prototype (List.range records.ifaceData.length)
    records.deployment (profile_static_bindings records supported)
    (profile_iface_conditions records supported) (profile_wire_checks records supported)
    ⟨fun _ => 64, fun _ => 64⟩ rfl (fun _ => by change 64 ≤ 255 ∧ 64 ≤ 255; decide)
    (profile_initial_wire_safe records supported) (profile_link_encoding records supported)
    (fun _ => 1500) rfl (fun _ => by change 1280 ≤ 1500; decide) rfl
  · intro request allowed
    have member := profile_source_iface records supported request allowed
    have checked : ∀ source ∈ records.sourceIfaces, source ∈ List.range records.ifaceData.length := by
      rcases supported with rfl | rfl <;> decide
    exact checked request.iface member
  · exact profile_network_sources records supported

end TDN.Deployments.MacsecProtection
