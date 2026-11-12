import TDN.Import.SnapshotLoader
import TDN.Requirements.DoubleEncryptionOnBlackLinks
import TDN.Models.TunnelSaOriginAttribution

namespace TDN.Deployments.ProfileShared_DataPlane

open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records devices : List DeviceData from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.devices"]

load_network_records ifaces : List IfaceData from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.ifaces"]

load_network_records routes : List FibRoute from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.routes"]

load_network_records links : List (Nat × Nat) from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.links"]

load_network_records switches : List (Nat × Nat) from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.switches"]

def config : DataPlaneModel := dataPlaneModelFromRecords devices ifaces routes links switches
def expectedEncapStack : Nat → List Nat := expectedEncapStackFromRecords ifaces

lemma forward_checks : TableDrivenForwardChecks devices ifaces := by
  unfold TableDrivenForwardChecks devices ifaces
  native_decide
lemma peer_tag_checks : TableDrivenPeerTagAgreement devices := by
  unfold TableDrivenPeerTagAgreement devices saMatchesPolicy SameWireAssociation; native_decide
lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  table_driven_peer_tag_agreement_sound devices ifaces routes links switches peer_tag_checks

lemma route_owner_checks : ∀ r ∈ routes, (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner := by
  unfold routes ifaces; native_decide
lemma link_checks : ∀ edge ∈ links, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; native_decide
lemma switch_checks : ∀ edge ∈ switches, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧ (deviceAt devices (ifaceAt ifaces edge.1).owner).ingressPolicies = [] := by
  unfold switches ifaces devices; native_decide
lemma forward_default_checks : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny := by
  unfold devices; native_decide
lemma output_checks : TableDrivenOutputChecks devices ifaces := by
  unfold TableDrivenOutputChecks devices ifaces; native_decide
lemma outer_route_checks : TableDrivenOuterRoutes devices ifaces routes := by
  unfold TableDrivenOuterRoutes devices ifaces routes; native_decide

lemma local_stack_conditions : PerHopEncapConditions config expectedEncapStack :=
  local_stack_conditions_of_finite_checks devices ifaces routes links switches
    route_owner_checks link_checks switch_checks forward_default_checks forward_checks output_checks outer_route_checks

theorem every_transmission_has_iface_stack {start finish : DataPlaneForwarding.State} {actions : List Action}
    (run : (lts config).MTr start actions finish) (initial : EncapStackConsistent config expectedEncapStack start)
    (ready : finish.datapathStage = .egressReady) : finish.frame.encapLayerIds = expectedEncapStack finish.iface :=
  egress_packet_has_expected_encap_stack config expectedEncapStack local_stack_conditions run initial ready

load_network_records redSources : List Nat from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.redSources"]

load_network_records blackIfaces : List Nat from "../../data/evidence/ProfileShared_DataPlane.json" ["TDN.Deployments.ProfileShared_DataPlane.blackIfaces"]

lemma sources_checked : ∀ p ∈ redSources, expectedEncapStack p = [] ∧ config.canOriginateTraffic p := by
  unfold redSources expectedEncapStack config expectedEncapStackFromRecords dataPlaneModelFromRecords ifaces; native_decide
lemma black_ifaces_checked : ∀ p ∈ blackIfaces, expectedEncapStack p = [2, 1] := by
  unfold blackIfaces expectedEncapStack expectedEncapStackFromRecords ifaces; native_decide
theorem snapshot_RG007_IPv4_ESP_packet_stack : Requirements.red_traffic_is_doubly_encrypted_on_black_links config redSources blackIfaces :=
  Requirements.protected_red_stack_from_local_checks config expectedEncapStack redSources blackIfaces
    local_stack_conditions sources_checked black_ifaces_checked

end TDN.Deployments.ProfileShared_DataPlane
