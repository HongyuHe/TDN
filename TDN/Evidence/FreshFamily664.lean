import TDN.Import.Command
import TDN.Targets.PacketExecution
import TDN.Semantics.FiniteRoutedExecution
import TDN.Semantics.ExecutionProvenance

namespace TDN.Imported.Family664

open Execution

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data devices : List DeviceData from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.devices"]

tdn_data ifaces : List IfaceData from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.ifaces"]

tdn_data routes : List Route from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.links"]

tdn_data switches : List (Nat × Nat) from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.switches"]

def config : Environment := dataPlaneConfigFromRecords devices ifaces routes links switches
def expectedEncapStack : Nat → List Nat := expectedEncapStackFromRecords ifaces

lemma forward_checks : FiniteRoutedForwardChecks devices ifaces routes := by
  unfold FiniteRoutedForwardChecks devices ifaces routes
  decide

lemma peer_tag_checks : FinitePeerTagAgreement devices := by
  unfold FinitePeerTagAgreement devices StateBindsPolicy SameWireAssociation
  decide

lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  finite_peer_tag_agreement_sound devices ifaces routes links switches peer_tag_checks

lemma route_owner_checks : ∀ r ∈ routes,
    (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner := by
  unfold routes ifaces
  decide

lemma link_checks : ∀ edge ∈ links,
    (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack := by
  unfold links ifaces
  decide

lemma switch_checks : ∀ edge ∈ switches,
    (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧
    (deviceAt devices (ifaceAt ifaces edge.1).owner).inbound = [] := by
  unfold switches ifaces devices
  decide

lemma forward_default_checks : ∀ device ∈ ({} : DeviceData) :: devices,
    device.forwardFallback = .deny := by
  unfold devices
  decide

lemma output_checks : FiniteOutputChecks devices ifaces := by
  unfold FiniteOutputChecks devices ifaces
  decide

lemma outer_route_checks : FiniteOuterRoutes devices ifaces routes := by
  unfold FiniteOuterRoutes devices ifaces routes
  decide

lemma local_stack_conditions : LocalStackConditions config expectedEncapStack :=
  local_stack_conditions_of_routed_finite_checks devices ifaces routes links switches
    route_owner_checks link_checks switch_checks forward_default_checks forward_checks
    output_checks outer_route_checks

theorem every_transmission_has_iface_stack {start finish : Execution.State} {actions : List Action}
    (run : (lts config).MTr start actions finish) (initial : StackInvariant config expectedEncapStack start)
    (ready : finish.datapathStage = .ready) : finish.frame.tags = expectedEncapStack finish.iface :=
  transmitted_stack config expectedEncapStack local_stack_conditions run initial ready

tdn_data redSources : List Nat from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.redSources"]

tdn_data blackIfaces : List Nat from "../../data/evidence/FreshFamily664.json" ["TDN.Imported.Family664.blackIfaces"]

lemma sources_checked : ∀ p ∈ redSources, expectedEncapStack p = [] ∧ config.payloadOrigin p := by
  unfold redSources expectedEncapStack config expectedEncapStackFromRecords dataPlaneConfigFromRecords ifaces; decide
lemma black_ifaces_checked : ∀ p ∈ blackIfaces, expectedEncapStack p = [2, 1] := by
  unfold blackIfaces expectedEncapStack expectedEncapStackFromRecords ifaces; decide
theorem snapshot_IPv4_IPv6_ESP_packet_stack :
    Targets.msc_protected_red_payload_stack config redSources blackIfaces :=
  Targets.protected_red_stack_from_local_checks config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked

end TDN.Imported.Family664
