import TDN.Deployments.InnerTunnelNoBypass_IPsecRedSources
import TDN.Requirements.IPsecTunnelInterpretationView
import TDN.Requirements.IPsecLayerBoundaryChecks

namespace TDN.Deployments.InnerTunnelNoBypass_IPsec
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

def interpretedDeployment (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  deploymentWithAssociatedIPTunnels (deployment primitive)

def interpretedForwarding (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :=
  StandardDataPlaneBridge.model (deviceBinding primitive) records.inventory.ifaces (interpretedDeployment primitive) {}

lemma interpreted_forwarding_same (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    interpretedForwarding primitive = redForwarding primitive := by rfl

theorem interpreted_deployment_covered (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    (interpretedForwarding primitive).CoversDeployment (interpretedDeployment primitive) :=
  coverage_with_associated_ip_tunnels (redForwarding primitive) (deployment primitive) (deployment_covered primitive)

def capturedConfiguration := directionalConfiguration records installations

def innerOwners : List Nat := [8, 9, 10, 11]
def grayIfaces : List Nat := [57, 63, 69, 75]
def innerOwner (owner : Nat) : Prop := owner ∈ innerOwners

instance (owner : Nat) : Decidable (innerOwner owner) := by unfold innerOwner; infer_instance

def innerDevice (name : String) : Prop :=
  ∃ device ∈ records.components, device.id = name ∧ device.layer = some .inner

instance (name : String) : Decidable (innerDevice name) := by unfold innerDevice; infer_instance

def declaredTunnels := records.tunnels.map associatedIPTunnelView

def receiveTarget (_ : PayloadId) (name : String) : Option String :=
  ((grayIfaces.find? (fun iface => records.ifaceName iface == name)).map
    (fun iface => records.componentName (capturedConfiguration.ip.owner iface)))

lemma selected_receive_target (payload : PayloadId) (name component : String)
    (selected : receiveTarget payload name = some component) :
    ∃ iface ∈ grayIfaces, records.ifaceName iface = name ∧
      records.componentName (capturedConfiguration.ip.owner iface) = component := by
  unfold receiveTarget at selected
  cases found : grayIfaces.find? (fun iface => records.ifaceName iface == name) with
  | none => simp [found] at selected
  | some iface =>
    refine ⟨iface, List.mem_of_find?_eq_some found, ?_, ?_⟩
    · exact beq_iff_eq.mp (List.find?_some (p := fun iface => records.ifaceName iface == name) found)
    · simpa only [found, Option.map_some, Option.some.injEq] using selected

lemma iface_name_forces_index (known : Nat) (member : known ∈ records.inventory.ifaces)
    (iface : Nat) (same : records.ifaceName iface = records.ifaceName known) : iface = known := by
  have length : records.ifaceNames.length = records.nativeIfaces.length := by decide
  have unique : records.ifaceNames.Nodup := by decide
  have listed : ∀ index ∈ records.inventory.ifaces, records.ifaceName index ≠ "unlisted-port" := by decide
  by_cases present : iface < records.nativeIfaces.length
  · exact indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length length unique
      iface (List.mem_range.mpr present) known member same
  · have missing : records.ifaceNames[iface]? = none := List.getElem?_eq_none (by omega)
    have absent : records.ifaceName iface = "unlisted-port" := by simp [Records.ifaceName, missing]
    exact False.elim (listed known member (same.symm.trans absent))

lemma gray_iface_present : ∀ iface ∈ grayIfaces, iface ∈ records.inventory.ifaces := by decide

lemma receive_target_index (payload : PayloadId) (iface : Nat) (component : String)
    (selected : receiveTarget payload (records.ifaceName iface) = some component) :
    iface ∈ grayIfaces ∧ records.componentName (capturedConfiguration.ip.owner iface) = component := by
  obtain ⟨known, member, name, owner⟩ := selected_receive_target payload _ component selected
  have same := iface_name_forces_index known (gray_iface_present known member) iface name.symm
  subst iface
  exact ⟨member, owner⟩

lemma inner_owner_name_forces_index (known : Nat) (member : known ∈ innerOwners)
    (owner : Nat) (same : records.componentName owner = records.componentName known) : owner = known := by
  have checked : ∀ first ∈ List.range records.ownerNames.length, ∀ second ∈ innerOwners,
      records.componentName first = records.componentName second → first = second := by decide
  have listed : ∀ second ∈ innerOwners, records.componentName second ≠ "unlisted-device" := by decide
  by_cases present : owner < records.ownerNames.length
  · exact checked owner (List.mem_range.mpr present) known member same
  · have missing : records.ownerNames[owner]? = none := List.getElem?_eq_none (by omega)
    have absent : records.componentName owner = "unlisted-device" := by simp [Records.componentName, missing]
    exact False.elim (listed known member (same.symm.trans absent))

lemma gray_iface_owner : ∀ iface ∈ grayIfaces, innerOwner (capturedConfiguration.ip.owner iface) ∧
    capturedConfiguration.ip.interfaceName iface = "gray" := by decide

lemma protected_forward_chains : ∀ owner ∈ innerOwners,
    (DataPlaneForwarding.deviceAt records.nativeDevices owner).forwardFallback = .deny ∧
    ∀ rule ∈ (DataPlaneForwarding.deviceAt records.nativeDevices owner).forwardRules,
      rule.verdict = .allow → PacketPolicy.RequiresIpsecPolicyMatch rule "red" "gray" := by decide

lemma inner_forward_chain (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) (iface : Nat)
    (owner : innerOwner ((configuration primitive).ip.owner iface)) :
    ForwardChainRequiresIPsec (configuration primitive) iface "red" "gray" := by
  exact protected_forward_chains _ owner

lemma source_layouts : ∀ iface network, sourceEntry entries iface = some network → expectedStack iface = [] := by
  have checked : ∀ entry ∈ entries, expectedStack entry.iface = [] := by decide
  intro iface network selected
  obtain ⟨entry, member, same, _⟩ := source_entry_is_recorded entries iface network selected
  rw [← same]
  exact checked entry member

lemma source_receive_components : ∀ payload iface network, sourceEntry entries iface = some network →
    receiveTarget payload (records.ifaceName iface) = none := by
  have checked : ∀ entry ∈ entries, receiveTarget ⟨0,0⟩ (records.ifaceName entry.iface) = none := by decide
  intro payload iface network selected
  obtain ⟨entry, member, same, _⟩ := source_entry_is_recorded entries iface network selected
  rw [← same]
  exact checked entry member

lemma interface_owner_alignment : ∀ iface ∈ records.inventory.ifaces, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName iface → innerDevice interface.device → innerOwner (capturedConfiguration.ip.owner iface) := by decide

lemma interface_is_listed (interface : Interface) (member : interface ∈ records.interfaces)
    (iface : Nat) (same : interface.id = records.ifaceName iface) : iface ∈ records.inventory.ifaces := by
  apply interface_name_forces_iface records interface (by decide) _ iface same
  have checked : ∀ interface ∈ records.interfaces, interface.id ≠ "unlisted-port" := by decide
  exact checked interface member

lemma inner_physical_input_stacks : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName edge.2 → innerDevice interface.device → interface.zone = .red →
    expectedStack edge.2 = [] := by decide

lemma inner_physical_output_stacks : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName edge.1 → innerDevice interface.device → interface.zone = .red →
    expectedStack edge.1 = [] := by decide

lemma inner_external_outputs : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName edge.1 → innerDevice interface.device → interface.zone ≠ .red →
    capturedConfiguration.ip.interfaceName edge.1 = "gray" ∧ innerOwner (capturedConfiguration.ip.owner edge.1) := by decide

lemma bridge_outputs_outside_inner : ∀ edge ∈ records.bridges, ¬ innerOwner (capturedConfiguration.ip.owner edge.2) := by decide

lemma bridge_receive_components : ∀ edge ∈ records.bridges,
    receiveTarget ⟨0,0⟩ (records.ifaceName edge.1) = none := by decide

lemma inbound_tunnel_bindings : ∀ iface ∈ grayIfaces,
    ∀ policy ∈ capturedConfiguration.ip.ingressPolicies iface,
    ∀ association ∈ capturedConfiguration.ip.ingressSAs iface,
    DataPlaneForwarding.saMatchesPolicy association policy →
    ∃ tunnel ∈ declaredTunnels, tunnel.id = ipsecTunnel records (policy.seal association) ∧
      tunnel.layer = .inner ∧ tunnel.receiver = records.componentName (capturedConfiguration.ip.owner iface) := by decide

lemma outbound_tunnel_bindings : ∀ route ∈ records.routes,
    ∀ policy ∈ capturedConfiguration.ip.egressPolicies route.egress,
    ∀ association ∈ capturedConfiguration.ip.egressSAs route.egress,
    DataPlaneForwarding.saMatchesPolicy association policy →
    route.destPrefixLow ≤ association.receiver → association.receiver ≤ route.destPrefixHigh →
    ∀ interface ∈ records.interfaces, interface.id = records.ifaceName route.egress → innerDevice interface.device →
      ∃ tunnel ∈ declaredTunnels, tunnel.layer = .inner ∧ tunnel.sender = interface.device ∧
        tunnel.id = ipsecTunnel records (policy.seal association) := by decide

lemma external_receive_components : ∀ interface ∈ records.interfaces, innerDevice interface.device →
    interface.zone = .gray → receiveTarget ⟨0,0⟩ interface.id = some interface.device := by decide

end TDN.Deployments.InnerTunnelNoBypass_IPsec
