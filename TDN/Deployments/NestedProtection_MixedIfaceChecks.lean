import TDN.Deployments.NestedProtection_MixedInventoryChecks
import TDN.Deployments.NestedProtection_MixedFlowChecks

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma recorded_iface_zones : ∀ edge ∈ records.links, ∀ iface ∈ [edge.1, edge.2],
    ∀ interface ∈ records.interfaces, records.ifaceName iface = interface.id →
      (interface.zone = .gray → expectedEncapStack iface = [1]) ∧
      (interface.zone = .black → expectedEncapStack iface = [2,1]) := by native_decide

lemma recorded_sources_are_red : ∀ entry ∈ records.entries, ∀ interface ∈ records.interfaces,
    records.ifaceName entry.iface = interface.id → interface.zone ≠ .black := by native_decide

lemma recorded_recipient_addresses : ∀ selected ∈ contexts, ∀ iface ∈ ifaces,
    configuration.ip.ifaceSecurityDomain iface ≠ none →
    ∀ interface ∈ records.interfaces, interface.device = records.componentName (configuration.ip.owner iface) →
    ∀ address ∈ interface.address.toList ++ interface.namespaceAddresses,
    selected.remoteLow ≤ address → address ≤ selected.remoteHigh →
      (configuration.ip.ifaceSecurityDomain iface).map records.redNetwork = some selected.flow.destinationNetwork := by native_decide

lemma recipient_iface_is_recorded (iface domain : Nat)
    (recipient : configuration.ip.ifaceSecurityDomain iface = some domain) : iface ∈ ifaces := by
  by_contra absent
  have outside : iface = 0 ∨ records.ifaceData.length ≤ iface := by
    have fact : ¬ (iface < records.ifaceData.length ∧ iface ≠ 0) := by
      intro present
      apply absent
      simpa only [Records.ifaces, List.mem_filter, List.mem_range, bne_iff_ne] using present
    omega
  have ownerZero : configuration.ip.owner iface = 0 := by
    rcases outside with rfl | bound
    · rfl
    · have missing : records.ifaceData[iface]? = none := List.getElem?_eq_none bound
      change (DataPlaneForwarding.ifaceAt records.ifaceData iface).owner = 0
      simp only [DataPlaneForwarding.ifaceAt, missing, Option.getD_none]
  change (DataPlaneForwarding.deviceAt records.deviceData (configuration.ip.owner iface)).ifaceSecurityDomain = some domain at recipient
  have empty : (DataPlaneForwarding.deviceAt records.deviceData 0).ifaceSecurityDomain = none := by native_decide
  rw [ownerZero, empty] at recipient
  cases recipient

lemma flow_iface_checks (selected : MixedFlowEndpoints) (member : selected ∈ contexts) :
    MixedFlowIfaceChecks deviceBinding deployment selected expectedEncapStack := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro iface interface listed name connected gray
    obtain ⟨peer, forward | reverse⟩ := connected
    · exact (recorded_iface_zones (iface,peer) forward iface (by simp) interface listed name).1 gray
    · exact (recorded_iface_zones (peer,iface) reverse iface (by simp) interface listed name).1 gray
  · intro iface interface listed name connected black
    obtain ⟨peer, forward | reverse⟩ := connected
    · exact (recorded_iface_zones (iface,peer) forward iface (by simp) interface listed name).2 black
    · exact (recorded_iface_zones (peer,iface) reverse iface (by simp) interface listed name).2 black
  · intro iface network source interface listed name
    obtain ⟨entry, stored, same, _⟩ := source_entry_is_recorded records.entries iface network source
    rw [← same] at name
    exact recorded_sources_are_red entry stored interface listed name
  · intro iface header domain recipient localAddress plain remote
    change configuration.ip.ifaceSecurityDomain iface = some domain at recipient
    have present := recipient_iface_is_recorded iface domain recipient
    obtain ⟨interface, listed, owner, address⟩ := localAddress
    have known : header.destination ∈ interface.address.toList ++ interface.namespaceAddresses := by
      rcases address with same | stored
      · exact List.mem_append_left _ (by simp [same])
      · exact List.mem_append_right _ stored
    have found := recorded_recipient_addresses selected member iface present (by rw [recipient]; simp)
      interface listed owner header.destination known remote.1 remote.2
    change records.redNetwork domain = selected.flow.destinationNetwork
    simpa only [recipient, Option.map_some, Option.some.injEq] using found

end TDN.Deployments.NestedProtection_Mixed
