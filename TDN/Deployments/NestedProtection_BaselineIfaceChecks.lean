import TDN.Deployments.NestedProtection_BaselineIfaceData
import TDN.Deployments.NestedProtection_BaselineFlowChecks
import TDN.Deployments.NestedProtection_BaselineArchitecture

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records LayeredFrame MultiProtocolForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma named_iface_is_recorded (iface : Nat) (interface : Interface)
    (listed : interface ∈ records.interfaces) (name : records.ifaceName iface = interface.id) :
    iface ∈ records.inventory.ifaces := by
  have lengths : records.ifaceNames.length = records.nativeIfaces.length := by decide
  have names : ∀ interface ∈ records.interfaces, interface.id ≠ "unlisted-port" := by decide
  by_contra absent
  have bound : records.nativeIfaces.length ≤ iface := Nat.le_of_not_gt (fun present => absent (List.mem_range.mpr present))
  have missing : records.ifaceNames[iface]? = none := List.getElem?_eq_none (by omega)
  have fallback : records.ifaceName iface = "unlisted-port" := by simp [OuterToGray_DeviceModel.Records.ifaceName, missing]
  exact names interface listed (name.symm.trans fallback)

lemma recipient_iface_is_recorded (iface domain : Nat)
    (recipient : capturedConfiguration.ip.ifaceSecurityDomain iface = some domain) : iface ∈ records.inventory.ifaces := by
  by_contra absent
  have bound : records.nativeIfaces.length ≤ iface := Nat.le_of_not_gt (fun present => absent (List.mem_range.mpr present))
  have missing : records.nativeIfaces[iface]? = none := List.getElem?_eq_none bound
  change (DataPlaneForwarding.deviceAt records.nativeDevices
    (DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner).ifaceSecurityDomain = some domain at recipient
  have empty : (DataPlaneForwarding.deviceAt records.nativeDevices 0).ifaceSecurityDomain = none := by decide
  simp only [DataPlaneForwarding.ifaceAt, missing, Option.getD_none] at recipient
  rw [empty] at recipient
  cases recipient

lemma flow_iface_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (selected : IPsecFlowEndpoints) (member : selected ∈ contexts) :
    IPsecFlowIfaceChecks (deviceBinding primitive) (authenticationDeployment primitive) selected expectedEncapStack := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro iface interface listed name gray
    exact (recorded_iface_zones iface (named_iface_is_recorded iface interface listed name) interface listed name).1 gray
  · intro iface interface listed name black
    exact (recorded_iface_zones iface (named_iface_is_recorded iface interface listed name) interface listed name).2 black
  · intro iface network source interface listed name
    obtain ⟨entry, stored, same, _⟩ := source_entry_is_recorded entries iface network source
    rw [← same] at name
    exact recorded_sources_are_red entry stored interface listed name
  · intro iface header domain recipient localAddress plain remote
    change capturedConfiguration.ip.ifaceSecurityDomain iface = some domain at recipient
    have present := recipient_iface_is_recorded iface domain recipient
    obtain ⟨interface, listed, owner, address⟩ := localAddress
    have known : header.destination ∈ interface.address.toList ++ interface.namespaceAddresses := by
      rcases address with same | stored
      · exact List.mem_append_left _ (by simp [same])
      · exact List.mem_append_right _ stored
    have found := recorded_recipient_addresses selected member iface present (by rw [recipient]; simp)
      interface listed owner header.destination known remote.1 remote.2
    change OuterTunnelNoBypass_Baseline.redNetwork domain = selected.flow.destinationNetwork
    simpa only [recipient, Option.map_some, Option.some.injEq] using found

end TDN.Deployments.NestedProtection_Baseline
