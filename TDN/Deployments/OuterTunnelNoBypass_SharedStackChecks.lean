import TDN.Deployments.OuterTunnelNoBypass_SharedNetworkData
import TDN.Models.HeaderAwareEncapPreservation
import TDN.Models.RouteAwareAclChecks

namespace TDN.Deployments.OuterTunnelNoBypass_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

abbrev records := OuterTunnelNoBypass_SharedNetwork.records
abbrev installations := OuterTunnelNoBypass_SharedNetwork.installations
abbrev linkPolicies := OuterTunnelNoBypass_SharedNetwork.linkPolicies

def expectedEncapStack := DataPlaneForwarding.expectedEncapStackFromRecords records.nativeIfaces

lemma route_owners : ∀ route ∈ records.routes,
    (DataPlaneForwarding.ifaceAt records.nativeIfaces route.egress).owner =
      (DataPlaneForwarding.ifaceAt records.nativeIfaces route.ingress).owner := by decide

lemma physical_stacks : ∀ edge ∈ records.links,
    expectedEncapStack edge.1 = expectedEncapStack edge.2 := by decide

lemma bridge_stacks : ∀ edge ∈ records.bridges,
    expectedEncapStack edge.1 = expectedEncapStack edge.2 := by decide

lemma forward_defaults : ∀ device ∈ ({} : DataPlaneForwarding.DeviceData) :: records.nativeDevices,
    device.forwardFallback = .deny := by decide

lemma forward_rules : DataPlaneForwarding.TableDrivenRoutedForwardChecks records.nativeDevices records.nativeIfaces records.routes := by
  unfold DataPlaneForwarding.TableDrivenRoutedForwardChecks
  decide

lemma output_rules : DataPlaneForwarding.TableDrivenOutputChecks records.nativeDevices records.nativeIfaces := by
  unfold DataPlaneForwarding.TableDrivenOutputChecks
  decide

lemma outer_routes : DataPlaneForwarding.TableDrivenOuterRoutes records.nativeDevices records.nativeIfaces records.routes := by
  unfold DataPlaneForwarding.TableDrivenOuterRoutes
  decide

lemma table_stack_conditions : DataPlaneForwarding.PerHopEncapConditions
    (DataPlaneForwarding.dataPlaneModelFromRecords records.nativeDevices records.nativeIfaces records.routes records.links [])
    expectedEncapStack :=
  DataPlaneForwarding.local_stack_conditions_of_routed_finite_checks records.nativeDevices records.nativeIfaces
    records.routes records.links [] route_owners physical_stacks (by simp) forward_defaults forward_rules output_rules outer_routes

lemma headered_stack_conditions {Key : Type} (codec : IPsecFrameEncoding.Codec Key) :
    HeaderedLocalConditions (completeConfiguration records installations linkPolicies codec) expectedEncapStack := by
  refine ⟨rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨table_stack_conditions.routeOwner, table_stack_conditions.link, table_stack_conditions.bridge,
      table_stack_conditions.forward, table_stack_conditions.output, table_stack_conditions.routeOuterPacket⟩
  · intro first last linked
    exact physical_stacks (first,last) linked
  · intro first last connected
    exact bridge_stacks (first,last) connected
  all_goals simp [withoutHeaderProcessing, completeConfiguration, directionalConfiguration, Records.configuration,
    dataPlaneModelFromRecords]

end TDN.Deployments.OuterTunnelNoBypass_Shared
