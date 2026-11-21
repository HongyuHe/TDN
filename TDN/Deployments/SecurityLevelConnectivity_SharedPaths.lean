import TDN.Deployments.SecurityLevelConnectivity_Records
import TDN.Deployments.OuterTunnelNoBypass_SharedSampleTrace

namespace TDN.Deployments.SecurityLevelConnectivity_Shared
open Compliance Requirements Requirements.Msc Requirements.StandardDataPlaneBridge
  OuterTunnelNoBypass_Shared MtuSizing_Records SecurityLevelConnectivity NestedProtection

set_option maxRecDepth 1000000

load_network_records assignments : List RedLabelAssignment from "../../data/evidence/securityLevelConnectivity/Shared.json" ["assignments"]
load_network_records installedChildren : List InstalledChild from "../../data/evidence/securityLevelConnectivity/Shared.json" ["established"]
load_network_records requiredPairs : List (String × String) from "../../data/evidence/securityLevelConnectivity/Shared.json" ["requiredPairs"]
load_network_records deliveries : List (DeliveryPlan DeliveryMove) from "../../data/evidence/securityLevelConnectivity/Shared.json" ["plans"]
load_network_records authentication : List PublicAuthenticationBinding from "../../data/evidence/nestedProtection/SharedIPsec.json" ["authenticationBindings"]

load_network_records innerOuterUses : List (String × String) from "../../data/evidence/nestedProtection/SharedIPsec.json" ["innerOuterUses"]

def labelDeployment (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) : Deployment :=
  deploymentWithPeerRecords (interpretedDeployment primitive) assignments
    authentication innerOuterUses

def redNetworks := networks.map (labeledNetwork assignments)
def devices := records.components.map (labeledComponent assignments)

def authenticated := observedInnerPairs devices (authentication.map fun row => (row.device, row.peerDevice))
def installed := observedInnerPairs devices (installedChildren.map fun row => (row.device, row.peer))

lemma checked_peer_inventory :
    (∀ device ∈ devices, device.layer = some .inner →
      (∃ row ∈ authentication, row.device = device.id ∧ row.certificateAuthenticated = true) ∧
      ∃ child ∈ installedChildren, child.device = device.id) ∧
    (∀ row ∈ authentication, ∃ device ∈ devices, device.id = row.device) ∧
    (∀ row ∈ installedChildren, row.ike ≠ "" ∧ row.child ≠ "" ∧ row.observation ≠ "" ∧ row.capture ≠ "") ∧
    (∀ pair ∈ authenticated ++ installed, ∃ first ∈ devices, ∃ last ∈ devices,
      first.id = pair.1 ∧ last.id = pair.2 ∧ first.layer = some .inner ∧
      last.layer = some .inner ∧ first.level = last.level) := by native_decide

lemma checked_dedicated_networks : DedicatedInnerAssignments redNetworks ∧
    (∀ network ∈ redNetworks, ∀ inner ∈ network.innerComponents,
      ∃ device ∈ devices, device.id = inner ∧ device.layer = some .inner ∧ device.level = network.level) := by
  unfold DedicatedInnerAssignments
  native_decide

lemma checked_positive_demands :
    requiredPairs.toFinset = (intendedNetworkPairs redNetworks).toFinset ∧
    (∀ pair ∈ requiredPairs, ∃ delivery ∈ deliveries, redNetwork delivery.path.flow.domain = pair.1 ∧
      redNetwork delivery.recipient = pair.2) := by native_decide

lemma checked_delivery_plans : ∀ delivery ∈ deliveries,
    DeliveryPathChecks delivery.path.start delivery.moves ∧
    delivery.path.SourceChecks records entries roles networks ∧
    (deliveryFinish delivery.path.start delivery.moves).datapathStage = .delivered ∧
    records.configuration.ip.ifaceSecurityDomain (deliveryFinish delivery.path.start delivery.moves).iface =
      some delivery.recipient := by native_decide

theorem required_pairs_have_forwarding_traces (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    ∀ pair ∈ requiredPairs, ∃ start actions finish payload, (interpretedForwarding primitive).initial start ∧
      (interpretedForwarding primitive).ForwardsAlongTrace start actions finish ∧
      Before ((interpretedForwarding primitive).TraceEvents actions)
        (.inject payload pair.1) (.deliver payload pair.2 []) := by
  intro pair member
  obtain ⟨delivery, listed, sourceName, recipientName⟩ := checked_positive_demands.2 pair member
  obtain ⟨checked, sourceChecks, done, recipient⟩ := checked_delivery_plans delivery listed
  obtain ⟨network, known, entry, origin⟩ := sourceChecks.1
  have name := red_network_of_recorded_origin delivery.path.flow.domain network.id origin
  rw [← sourceName, ← recipientName]
  apply recorded_red_delivery_has_trace (deviceBinding primitive) records.inventory.ifaces
    (interpretedDeployment primitive) delivery.path redNetwork delivery.recipient
    (interpreted_deployment_covered primitive) (fun _ => rfl) rfl
    (entry.trans (congrArg some name.symm)) ⟨network, known, name.symm⟩ sourceChecks.2
  intro start initialized same
  obtain ⟨actions, last, run, finish, _⟩ := delivery_path_reaches primitive delivery.moves start start []
    initialized Cslib.LTS.MTr.refl (by rw [same]; exact checked)
  rw [same] at finish
  exact ⟨actions, last, run, finish ▸ done, finish ▸ recipient⟩

theorem labeled_forwarding_coverage (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    (interpretedForwarding primitive).CoversDeployment (labelDeployment primitive) :=
  red_label_assignment_preserves_coverage (interpretedForwarding primitive) (interpretedDeployment primitive) assignments redNetwork (fun _ => rfl) rfl
    (interpreted_deployment_covered primitive)

end TDN.Deployments.SecurityLevelConnectivity_Shared
