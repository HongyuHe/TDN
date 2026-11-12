import TDN.Deployments.OuterTunnelNoBypass_BaselineRedSources
import TDN.Requirements.IPsecTunnelInterpretationView
import TDN.Requirements.OuterGrayReceiveChecks

namespace TDN.Deployments.OuterTunnelNoBypass_Baseline
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

def outerOwners : List Nat := [16, 17, 18, 19]
def externalIfaces : List Nat := [104, 110, 116, 122]
def OuterOwner (owner : Nat) : Prop := owner ∈ outerOwners

instance (owner : Nat) : Decidable (OuterOwner owner) := by unfold OuterOwner; infer_instance

def OuterDevice (name : String) : Prop :=
  ∃ device ∈ records.components, device.id = name ∧ device.layer = some .outer

instance (name : String) : Decidable (OuterDevice name) := by unfold OuterDevice; infer_instance

def declaredTunnels := records.tunnels.map associatedIPTunnelView

def receiveComponent (_ : PayloadId) (name : String) : Option String :=
  ((externalIfaces.find? (fun iface => records.ifaceName iface == name)).map
    (fun iface => records.componentName (capturedConfiguration.ip.owner iface)))

lemma selected_receive_component (payload : PayloadId) (name component : String)
    (selected : receiveComponent payload name = some component) :
    ∃ iface ∈ externalIfaces, records.ifaceName iface = name ∧
      records.componentName (capturedConfiguration.ip.owner iface) = component := by
  unfold receiveComponent at selected
  cases found : externalIfaces.find? (fun iface => records.ifaceName iface == name) with
  | none => simp [found] at selected
  | some iface =>
    refine ⟨iface, List.mem_of_find?_eq_some found, ?_, ?_⟩
    · exact beq_iff_eq.mp (List.find?_some (p := fun iface => records.ifaceName iface == name) found)
    · simpa only [found, Option.map_some, Option.some.injEq] using selected

lemma iface_name_forces_index (known : Nat) (member : known ∈ records.inventory.ifaces)
    (iface : Nat) (same : records.ifaceName iface = records.ifaceName known) : iface = known := by
  have length : records.ifaceNames.length = records.nativeIfaces.length := by native_decide
  have unique : records.ifaceNames.Nodup := by native_decide
  have listed : ∀ index ∈ records.inventory.ifaces, records.ifaceName index ≠ "unlisted-port" := by native_decide
  by_cases present : iface < records.nativeIfaces.length
  · exact indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length length unique
      iface (List.mem_range.mpr present) known member same
  · have missing : records.ifaceNames[iface]? = none := List.getElem?_eq_none (by omega)
    have absent : records.ifaceName iface = "unlisted-port" := by simp [Records.ifaceName, missing]
    exact False.elim (listed known member (same.symm.trans absent))

lemma external_iface_present : ∀ iface ∈ externalIfaces, iface ∈ records.inventory.ifaces := by native_decide

lemma receive_component_iface (payload : PayloadId) (iface : Nat) (component : String)
    (selected : receiveComponent payload (records.ifaceName iface) = some component) :
    iface ∈ externalIfaces ∧ records.componentName (capturedConfiguration.ip.owner iface) = component := by
  obtain ⟨known, member, name, owner⟩ := selected_receive_component payload _ component selected
  have same := iface_name_forces_index known (external_iface_present known member) iface name.symm
  subst iface
  exact ⟨member, owner⟩

lemma outer_owner_name_forces_index (known : Nat) (member : known ∈ outerOwners)
    (owner : Nat) (same : records.componentName owner = records.componentName known) : owner = known := by
  have checked : ∀ first ∈ List.range records.ownerNames.length, ∀ second ∈ outerOwners,
      records.componentName first = records.componentName second → first = second := by native_decide
  have listed : ∀ second ∈ outerOwners, records.componentName second ≠ "unlisted-device" := by native_decide
  by_cases present : owner < records.ownerNames.length
  · exact checked owner (List.mem_range.mpr present) known member same
  · have missing : records.ownerNames[owner]? = none := List.getElem?_eq_none (by omega)
    have absent : records.componentName owner = "unlisted-device" := by simp [Records.componentName, missing]
    exact False.elim (listed known member (same.symm.trans absent))

lemma external_iface_owner : ∀ iface ∈ externalIfaces, OuterOwner (capturedConfiguration.ip.owner iface) ∧
    capturedConfiguration.ip.interfaceName iface = "black" := by native_decide

lemma protected_forward_chains : ∀ owner ∈ outerOwners,
    (DataPlaneForwarding.deviceAt records.nativeDevices owner).forwardFallback = .deny ∧
    ∀ rule ∈ (DataPlaneForwarding.deviceAt records.nativeDevices owner).forwardRules,
      rule.verdict = .allow → ∃ inside ∈ ["gray", "gray2", "gray3", "gray4"],
        inside ≠ "black" ∧ PacketPolicy.RequiresIpsecPolicyMatch rule inside "black" := by native_decide

lemma outer_forward_chain (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) (iface : Nat)
    (owner : OuterOwner ((configuration primitive).ip.owner iface)) :
    ForwardChainRequiresIPsecAcross (configuration primitive) iface "black" := by
  have checked := protected_forward_chains _ owner
  refine ⟨checked.1, ?_⟩
  intro rule member allow
  obtain ⟨inside, listed, different, guarded⟩ := checked.2 rule member allow
  exact ⟨inside, different, guarded⟩

lemma source_encap_stacks : ∀ iface network, sourceEntry entries iface = some network → expectedEncapStack iface = [] := by
  have checked : ∀ entry ∈ entries, expectedEncapStack entry.iface = [] := by native_decide
  intro iface network selected
  obtain ⟨entry, member, same, _⟩ := source_entry_is_recorded entries iface network selected
  rw [← same]
  exact checked entry member

lemma source_receive_components : ∀ payload iface network, sourceEntry entries iface = some network →
    receiveComponent payload (records.ifaceName iface) = none := by
  have checked : ∀ entry ∈ entries, receiveComponent ⟨0,0⟩ (records.ifaceName entry.iface) = none := by native_decide
  intro payload iface network selected
  obtain ⟨entry, member, same, _⟩ := source_entry_is_recorded entries iface network selected
  rw [← same]
  exact checked entry member

lemma interface_owner_alignment : ∀ iface ∈ records.inventory.ifaces, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName iface → OuterDevice interface.device → OuterOwner (capturedConfiguration.ip.owner iface) := by native_decide

lemma interface_is_listed (interface : Interface) (member : interface ∈ records.interfaces)
    (iface : Nat) (same : interface.id = records.ifaceName iface) : iface ∈ records.inventory.ifaces := by
  apply interface_name_forces_iface records interface (by native_decide) _ iface same
  have checked : ∀ interface ∈ records.interfaces, interface.id ≠ "unlisted-port" := by native_decide
  exact checked interface member

lemma outer_physical_input_stacks : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName edge.2 → OuterDevice interface.device → interface.zone = .gray →
    expectedEncapStack edge.2 = [1] := by native_decide

lemma outer_physical_output_stacks : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName edge.1 → OuterDevice interface.device → interface.zone = .gray →
    expectedEncapStack edge.1 = [1] := by native_decide

lemma outer_external_outputs : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
    interface.id = records.ifaceName edge.1 → OuterDevice interface.device → interface.zone ≠ .gray →
    capturedConfiguration.ip.interfaceName edge.1 = "black" ∧ OuterOwner (capturedConfiguration.ip.owner edge.1) := by native_decide

lemma bridge_outputs_outside_outer : ∀ edge ∈ records.bridges, ¬ OuterOwner (capturedConfiguration.ip.owner edge.2) := by native_decide

lemma bridge_receive_components : ∀ edge ∈ records.bridges,
    receiveComponent ⟨0,0⟩ (records.ifaceName edge.1) = none := by native_decide

lemma inbound_tunnel_bindings : ∀ iface ∈ externalIfaces,
    ∀ policy ∈ capturedConfiguration.ip.ingressPolicies iface,
    ∀ association ∈ capturedConfiguration.ip.ingressSAs iface,
    DataPlaneForwarding.saMatchesPolicy association policy →
    ∃ tunnel ∈ declaredTunnels, tunnel.id = ipsecTunnel records (policy.seal association) ∧
      tunnel.layer = .outer ∧ tunnel.receiver = records.componentName (capturedConfiguration.ip.owner iface) := by native_decide

lemma outbound_tunnel_bindings : ∀ route ∈ records.routes,
    ∀ policy ∈ capturedConfiguration.ip.egressPolicies route.egress,
    ∀ association ∈ capturedConfiguration.ip.egressSAs route.egress,
    DataPlaneForwarding.saMatchesPolicy association policy →
    route.destPrefixLow ≤ association.receiver → association.receiver ≤ route.destPrefixHigh →
    ∀ interface ∈ records.interfaces, interface.id = records.ifaceName route.egress → OuterDevice interface.device →
      ∃ tunnel ∈ declaredTunnels, tunnel.layer = .outer ∧ tunnel.sender = interface.device ∧
        tunnel.id = ipsecTunnel records (policy.seal association) := by native_decide

lemma external_receive_components : ∀ interface ∈ records.interfaces, OuterDevice interface.device →
    interface.zone = .black → receiveComponent ⟨0,0⟩ interface.id = some interface.device := by native_decide

lemma source_not_outer_gray : ∀ iface network, sourceEntry entries iface = some network →
    ∀ interface ∈ records.interfaces, interface.id = records.ifaceName iface →
      OuterDevice interface.device → interface.zone ≠ .gray := by
  have checked : ∀ entry ∈ entries, ∀ interface ∈ records.interfaces,
      interface.id = records.ifaceName entry.iface → OuterDevice interface.device → interface.zone ≠ .gray := by native_decide
  intro iface network selected interface member name outer
  obtain ⟨entry, stored, same, _⟩ := source_entry_is_recorded entries iface network selected
  rw [← same] at name
  exact checked entry stored interface member name outer

lemma configured_layer_bindings : ∀ device ∈ records.nativeDevices, ∀ policy ∈ device.egressPolicies,
    ∀ record ∈ installations, record.installation.direction = .outbound →
    DataPlaneForwarding.saMatchesPolicy record.installation.association policy →
    ∃ tunnel ∈ declaredTunnels, tunnel.id = ipsecTunnel records (policy.seal record.installation.association) ∧
      protectionLayerTag tunnel.layer = policy.tag := by native_decide

lemma tunnel_layer_names_unique : ∀ first ∈ declaredTunnels, ∀ second ∈ declaredTunnels,
    first.id = second.id → first.layer = second.layer := by native_decide

end TDN.Deployments.OuterTunnelNoBypass_Baseline
