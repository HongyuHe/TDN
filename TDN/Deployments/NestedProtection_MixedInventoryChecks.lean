import TDN.Deployments.NestedProtection_MixedData

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 2048

lemma processing_coherent : deployment.ProcessingCoherent := by
  apply processing_coherence_from_record_checks deployment records.inventory rfl
  · decide
  · rfl
  · rfl

lemma public_sa_inventory_checks : PublicSAInventoryChecks configuration records.epoch records.installations := by decide

lemma ipsec_material_valid : ∀ record ∈ records.installations,
    (records.ipsecMaterial record.materialReference).Valid := by
  intro record member
  simp [Records.ipsecMaterial, IPsecKeyMaterial.Valid, capturedTransform]

lemma processing_bound : deviceBinding.ProcessingBound deployment := by
  refine ⟨processing_coherent, ?_, records.inventory, rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_⟩
  · simp [Deployment.UDPBindingsCoherent, Records.deployment]
  · simp [Records.deployment]
  · decide
  · decide
  · intro size sizeMember installation installed direction owner bound
    obtain ⟨record, member, rfl⟩ := List.mem_map.mp installed
    refine ⟨records.ipsecMaterial record.materialReference,
      public_key_material_lookup records.installations records.ipsecMaterial public_sa_inventory_checks.1 record member,
      rfl, rfl, rfl, rfl, rfl⟩

lemma iface_conditions : IfaceConditions configuration ifaces := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · decide
  · intro first last linked
    change (first,last) ∈ records.links at linked
    have checked : ∀ edge ∈ records.links, edge.1 ∈ ifaces ∧ edge.2 ∈ ifaces := by decide
    exact checked _ linked
  · intro first last linked
    change (first,last) ∈ records.bridges at linked
    have checked : ∀ edge ∈ records.bridges, edge.1 ∈ ifaces ∧ edge.2 ∈ ifaces := by decide
    exact checked _ linked
  · decide
  · simp [Records.configuration, dataPlaneModelFromRecords]

lemma interface_links : deployment.InterfaceLinksWellFormed := by
  have checked : ∀ edge ∈ records.links,
      (∃ interface ∈ records.interfaces, interface.id = records.ifaceName edge.1) ∧
      (∃ interface ∈ records.interfaces, interface.id = records.ifaceName edge.2) := by decide
  intro first last connected
  obtain ⟨edge, member, firstName, lastName⟩ := connected
  simpa only [Records.deployment, firstName, lastName] using checked edge member

lemma link_policies : deployment.LinkPoliciesComplete := by
  refine ⟨records.inventory, rfl, ?_, ?_, ?_⟩
  · have checked : ∀ iface ∈ ifaces, deployment.LinkPath records.inventory iface →
        (LinkAdmission.lookup configuration.linkPolicies iface).isSome = true := by
      unfold Deployment.LinkPath
      dsimp only [Records.inventory, Records.configuration, dataPlaneModelFromRecords]
      decide
    intro iface member path
    exact Option.isSome_iff_exists.mp (checked iface member path)
  · unfold Deployment.LinkPath
    dsimp only [Records.inventory, Records.configuration, dataPlaneModelFromRecords]
    decide
  · decide

lemma recorded_source_bindings :
    (∀ entry ∈ records.entries, entry.iface ∈ ifaces ∧ ∃ network ∈ records.networks, network.id = entry.network) ∧
    ∀ iface ∈ List.range records.ifaceData.length, ∀ network ∈ records.networks,
      sourceEntry records.entries iface = some network.id ↔
      ∃ interface ∈ records.interfaces, interface.id = records.ifaceName iface ∧ interface.zone = .red ∧
        interface.managementNetwork = false ∧ interface.device ∈ network.innerComponents := by decide

lemma named_iface_is_recorded (interface : Interface) (member : interface ∈ records.interfaces)
    (iface : Nat) (name : interface.id = records.ifaceName iface) : iface < records.ifaceData.length := by
  by_contra absent
  have sameLength : records.ifaceNames.length = records.ifaceData.length := by decide
  have missing : records.ifaceNames[iface]? = none := List.getElem?_eq_none (by omega)
  have nonempty : ∀ interface ∈ records.interfaces, interface.id ≠ "unlisted-iface" := by decide
  exact nonempty interface member (name.trans (by simp only [Records.ifaceName, missing, Option.getD_none]))

lemma source_entries : ∀ iface network, deviceBinding.sourceEntry iface = some network ↔
      ∃ interface ∈ deployment.interfaces, interface.id = deviceBinding.ifaceName iface ∧
        interface.zone = .red ∧ interface.managementNetwork = false ∧ ∃ red ∈ deployment.networks,
          red.id = network ∧ interface.device ∈ red.innerComponents := by
  intro iface network
  constructor
  · intro chosen
    obtain ⟨entry, member, sameIface, sameNetwork⟩ := source_entry_is_recorded records.entries iface network chosen
    obtain ⟨present, red, listed, redName⟩ := recorded_source_bindings.1 entry member
    have bound : iface ∈ List.range records.ifaceData.length := by
      rw [← sameIface]
      exact (List.mem_filter.mp present).1
    obtain ⟨interface, interfaceMember, name, zone, management, inner⟩ :=
      (recorded_source_bindings.2 iface bound red listed).mp (by rw [redName, sameNetwork]; exact chosen)
    exact ⟨interface, interfaceMember, name, zone, management, red, listed, redName.trans sameNetwork, inner⟩
  · rintro ⟨interface, member, name, zone, management, red, listed, redName, inner⟩
    have bound := named_iface_is_recorded interface member iface name
    rw [← redName]
    exact (recorded_source_bindings.2 iface (List.mem_range.mpr bound) red listed).mpr
      ⟨interface, member, name, zone, management, inner⟩

lemma macsec_key_inventory : deviceBinding.MACsecKeyInventory := by
  have checked : ∀ iface ∈ records.macIfaces,
      ∀ association ∈ iface.transmitAssociation.toList ++ iface.receiveAssociations,
      ∃ reference ∈ records.macMaterials, reference.1 = association ∧
        records.macsecMaterial association = some (List.replicate 32
          (UInt8.ofNat ((records.macMaterials.map Prod.snd).idxOf reference.2 + 1))) := by decide
  intro iface member association installed
  have present : association ∈ iface.transmitAssociation.toList ++ iface.receiveAssociations := by
    rcases installed with sent | received
    · simp [sent]
    · exact List.mem_append_right _ received
  obtain ⟨reference, listed, same, lookup⟩ := checked iface member association present
  exact ⟨_, lookup, Or.inr (by simp)⟩

lemma ipsec_key_inventory : deviceBinding.IPsecKeyInventory :=
  public_SA_inventory_sound deviceBinding records.installations records.epoch records.ipsecMaterial
    rfl rfl (fun _ => rfl) (fun _ => rfl) rfl public_sa_inventory_checks ipsec_material_valid

lemma static_bindings : DeviceDeploymentBindings deviceBinding ifaces deployment := by
  refine ⟨processing_bound, interface_links, link_policies, ?_, macsec_key_inventory,
    ipsec_key_inventory, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, source_entries, ?_, ?_⟩
  · exact ⟨records.inventory, rfl, ⟨fun _ => 64, fun _ => 64⟩, rfl,
      fun _ _ => by change 0 < 64 ∧ 64 ≤ 255 ∧ 0 < 64 ∧ 64 ≤ 255; decide⟩
  · decide
  · intro tunnel member
    exact ⟨tunnel, member, rfl, rfl⟩
  · decide
  · decide
  · decide
  · have checked : ∀ interface ∈ records.interfaces, ∃ iface ∈ ifaces,
        records.ifaceName iface = interface.id ∧ records.componentName (configuration.ip.owner iface) = interface.device := by decide
    intro interface member
    obtain ⟨iface, present, name, owner⟩ := checked interface member
    exact ⟨iface, name, owner⟩
  · decide
  · intro first last linked
    exact ⟨(first,last), linked, rfl, rfl⟩
  · have checked : ∀ iface ∈ records.macIfaces,
        ∀ association ∈ iface.transmitAssociation.toList, ∃ tunnel ∈ records.tunnels,
        tunnel.id = records.macsecTunnel association ∧ tunnel.mechanism = .macsec ∧
        tunnel.keyContext = records.macsecKeyName association.keyGeneration ∧
        tunnel.sender = records.componentName (configuration.ip.owner iface.physicalIface) ∧
        ∀ peer ∈ records.macIfaces,
          (∃ installed ∈ peer.receiveAssociations, SameMACWireIdentity association installed) →
          tunnel.receiver = records.componentName (configuration.ip.owner peer.physicalIface) := by decide
    intro iface member association installed
    exact checked iface member association (by simp [installed])
  · have checked : ∀ record ∈ records.installations, ∀ policy ∈
        (match record.installation.direction with
        | .outbound => (DataPlaneForwarding.deviceAt records.deviceData record.installation.device).egressPolicies
        | .inbound => (DataPlaneForwarding.deviceAt records.deviceData record.installation.device).ingressPolicies),
        DataPlaneForwarding.saMatchesPolicy record.installation.association policy →
        ∃ tunnel ∈ records.tunnels, tunnel.id = records.ipsecTunnel (policy.seal record.installation.association) ∧
        tunnel.mechanism = .ipsec ∧
        deployment.AddressOwner record.installation.association.sender = some tunnel.sender ∧
        deployment.AddressOwner record.installation.association.receiver = some tunnel.receiver := by decide
    intro iface association policy installed bound
    rcases installed with ⟨stateMember, policyMember⟩ | ⟨stateMember, policyMember⟩
    · obtain ⟨record, member, owner, direction, same⟩ := (directional_state_member ..).mp stateMember
      subst association
      have selected : policy ∈ (DataPlaneForwarding.deviceAt records.deviceData record.installation.device).egressPolicies := by
        rw [owner]
        exact policyMember
      exact checked record member policy (by simpa only [direction] using selected) bound
    · obtain ⟨record, member, owner, direction, same⟩ := (directional_state_member ..).mp stateMember
      subst association
      have selected : policy ∈ (DataPlaneForwarding.deviceAt records.deviceData record.installation.device).ingressPolicies := by
        rw [owner]
        exact policyMember
      exact checked record member policy (by simpa only [direction] using selected) bound

end TDN.Deployments.NestedProtection_Mixed
