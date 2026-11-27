import TDN.Import.SnapshotLoader
import TDN.Requirements.MultiProtocolPacketDefinitions
import TDN.Models.TableDrivenMultiProtocolDataPlane
import TDN.Models.TunnelSaOriginAttribution
import TDN.Models.IpHeaderAclGuards

/-! Fresh snapshot applications of the existing data-plane theory. Failed local
checks block the global theorem. No packet witnesses or fault descriptions are inputs. -/
namespace TDN.BlindSnapshot
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records devices : List DeviceData from "input.json" ["devices"]
load_network_records ifaces : List IfaceData from "input.json" ["ports"]
load_network_records routes : List FibRoute from "input.json" ["routes"]
load_network_records links : List (Nat × Nat) from "input.json" ["links"]
load_network_records switches : List (Nat × Nat) from "input.json" ["bridges"]
load_network_records redSources : List Nat from "input.json" ["redSources"]
load_network_records blackIfaces : List Nat from "input.json" ["blackIfaces"]
load_network_records grayIfaces : List Nat from "input.json" ["grayIfaces"]

def config : DataPlaneModel := dataPlaneModelFromRecords devices ifaces routes links []

def tunnelConfig := MultiProtocolForwarding.dataPlaneModelFromRecords devices ifaces routes links switches [] []
def expectedEncapStack : Nat → List Nat := expectedEncapStackFromRecords ifaces

lemma forward_checks : TableDrivenForwardChecks devices ifaces := by native_decide
lemma peer_tag_checks : TableDrivenPeerTagAgreement devices := by native_decide
lemma route_owner_checks : ∀ r ∈ routes, (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner := by native_decide
lemma link_checks : ∀ edge ∈ links, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack := by native_decide
lemma switch_checks : ∀ edge ∈ switches, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧ (deviceAt devices (ifaceAt ifaces edge.1).owner).ingressPolicies = [] := by native_decide
lemma forward_default_checks : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny := by native_decide
lemma output_checks : TableDrivenOutputChecks devices ifaces := by native_decide
lemma outer_route_checks : TableDrivenOuterRoutes devices ifaces routes := by native_decide

lemma local_stack_conditions : PerHopEncapConditions config expectedEncapStack :=
  local_stack_conditions_of_finite_checks devices ifaces routes links []
    route_owner_checks link_checks (by simp) forward_default_checks forward_checks output_checks outer_route_checks
lemma sources_checked : ∀ p ∈ redSources, expectedEncapStack p = [] ∧ config.canOriginateTraffic p := by
  unfold config dataPlaneModelFromRecords
  native_decide
lemma black_ifaces_checked : ∀ p ∈ blackIfaces, expectedEncapStack p = [2, 1] := by native_decide
lemma gray_ifaces_checked : grayIfaces ≠ [] ∧ ∀ p ∈ grayIfaces, expectedEncapStack p = [1] := by native_decide

lemma tunnel_conditions : MultiProtocolForwarding.LocalConditions tunnelConfig expectedEncapStack := by
  apply MultiProtocolForwarding.local_conditions_from_finite_checks
  · exact local_stack_conditions
  · exact link_checks
  · exact fun e member => (switch_checks e member).1
  all_goals simp [MultiProtocolForwarding.CarrierRouteChecks]

lemma red_egress_stack {start finish : MultiProtocolForwarding.TunnelForwardingState}
    {actions : List MultiProtocolForwarding.TunnelForwardingAction}
    (origin : Requirements.MultiProtocolRedOrigin redSources start)
    (run : MultiProtocolForwarding.ForwardsAlongTrace tunnelConfig start actions finish)
    (ready : finish.datapathStage = .egressReady) :
    finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
  have initial := Requirements.multi_protocol_red_initial_invariant tunnelConfig expectedEncapStack redSources sources_checked origin
  have preserved := MultiProtocolForwarding.all_traces_preserve_stack tunnelConfig expectedEncapStack tunnel_conditions run initial
  simpa only [ready] using preserved.2

theorem red_origin_has_inner_layer_at_gray_egress
    {start finish : MultiProtocolForwarding.TunnelForwardingState} {actions : List MultiProtocolForwarding.TunnelForwardingAction}
    (origin : Requirements.MultiProtocolRedOrigin redSources start)
    (run : MultiProtocolForwarding.ForwardsAlongTrace tunnelConfig start actions finish)
    (ready : finish.datapathStage = .egressReady) (gray : finish.iface ∈ grayIfaces) :
    finish.frame.body.protectionLayers = [1] :=
  (red_egress_stack origin run ready).trans (gray_ifaces_checked.2 _ gray)

theorem snapshot_RG007_packet_stack
    {start finish : MultiProtocolForwarding.TunnelForwardingState} {actions : List MultiProtocolForwarding.TunnelForwardingAction}
    (origin : Requirements.MultiProtocolRedOrigin redSources start)
    (run : MultiProtocolForwarding.ForwardsAlongTrace tunnelConfig start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    finish.frame.body.protectionLayers = [2, 1] :=
  (red_egress_stack origin run ready).trans (black_ifaces_checked _ black)

end TDN.BlindSnapshot
