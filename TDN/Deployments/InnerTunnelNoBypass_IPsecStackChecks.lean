import TDN.Deployments.OuterTunnelNoBypass_BaselineNetworkData
import TDN.Models.HeaderAwareEncapPreservation
import TDN.Models.RouteAwareAclChecks

namespace TDN.Deployments.InnerTunnelNoBypass_IPsec
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

abbrev records := OuterTunnelNoBypass_BaselineNetwork.records
abbrev installations := MtuSizing_Baseline.installations
abbrev linkPolicies := MtuSizing_Baseline.linkPolicies

def expectedStack := DataPlaneForwarding.expectedEncapStackFromRecords records.nativeIfaces

lemma route_owners : ∀ route ∈ records.routes,
    (DataPlaneForwarding.ifaceAt records.nativeIfaces route.egress).owner =
      (DataPlaneForwarding.ifaceAt records.nativeIfaces route.ingress).owner := by native_decide

lemma physical_stacks : ∀ edge ∈ records.links,
    expectedStack edge.1 = expectedStack edge.2 := by native_decide

lemma bridge_stacks : ∀ edge ∈ records.bridges,
    expectedStack edge.1 = expectedStack edge.2 := by native_decide

lemma forward_defaults : ∀ device ∈ ({} : DataPlaneForwarding.DeviceData) :: records.nativeDevices,
    device.forwardFallback = .deny := by native_decide

lemma forward_rules : DataPlaneForwarding.TableDrivenRoutedForwardChecks records.nativeDevices records.nativeIfaces records.routes := by
  unfold DataPlaneForwarding.TableDrivenRoutedForwardChecks
  native_decide
lemma output_rules : DataPlaneForwarding.TableDrivenOutputChecks records.nativeDevices records.nativeIfaces := by
  unfold DataPlaneForwarding.TableDrivenOutputChecks
  native_decide
lemma outer_routes : DataPlaneForwarding.TableDrivenOuterRoutes records.nativeDevices records.nativeIfaces records.routes := by
  unfold DataPlaneForwarding.TableDrivenOuterRoutes
  native_decide
lemma table_stack_conditions : DataPlaneForwarding.PerHopEncapConditions
    (DataPlaneForwarding.dataPlaneModelFromRecords records.nativeDevices records.nativeIfaces records.routes records.links [])
    expectedStack :=
  DataPlaneForwarding.local_stack_conditions_of_routed_finite_checks records.nativeDevices records.nativeIfaces
    records.routes records.links [] route_owners physical_stacks (by simp) forward_defaults forward_rules output_rules outer_routes

lemma headered_stack_conditions {Key : Type} (codec : IPsecFrameEncoding.Codec Key) :
    HeaderedLocalConditions (completeConfiguration records installations linkPolicies codec) expectedStack := by
  refine ⟨rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · refine ⟨table_stack_conditions.routeOwner, table_stack_conditions.link, table_stack_conditions.bridge,
      table_stack_conditions.forward, table_stack_conditions.output, table_stack_conditions.routeOuterPacket⟩
  · intro first last linked
    exact physical_stacks (first,last) linked
  · intro first last connected
    exact bridge_stacks (first,last) connected
  all_goals simp [withoutHeaderProcessing, completeConfiguration, directionalConfiguration, Records.configuration,
    dataPlaneModelFromRecords]

end TDN.Deployments.InnerTunnelNoBypass_IPsec
