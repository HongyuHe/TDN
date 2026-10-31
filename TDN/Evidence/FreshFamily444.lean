import TDN.Import.Command
import TDN.Targets.PacketExecution
import TDN.Semantics.FiniteRoutedExecution
import TDN.Semantics.ExecutionProvenance

namespace TDN.Imported.Family444

open Execution

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data devices : List DeviceData from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.devices"]

tdn_data ports : List PortData from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.ports"]

tdn_data routes : List Route from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.routes"]

tdn_data links : List (Nat × Nat) from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.links"]

tdn_data switches : List (Nat × Nat) from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.switches"]

def config : Config := finiteConfig devices ports routes links switches
def layout : Nat → List Nat := finiteLayout ports

lemma forward_checks : FiniteRoutedForwardChecks devices ports routes := by
  unfold FiniteRoutedForwardChecks devices ports routes
  decide

lemma peer_tag_checks : FinitePeerTagAgreement devices := by
  unfold FinitePeerTagAgreement devices StateBindsPolicy SameWireAssociation
  decide

lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  finite_peer_tag_agreement_sound devices ports routes links switches peer_tag_checks

lemma route_owner_checks : ∀ r ∈ routes,
    (portAt ports r.egress).owner = (portAt ports r.ingress).owner := by
  unfold routes ports
  decide

lemma link_checks : ∀ edge ∈ links,
    (portAt ports edge.1).stack = (portAt ports edge.2).stack := by
  unfold links ports
  decide

lemma switch_checks : ∀ edge ∈ switches,
    (portAt ports edge.1).stack = (portAt ports edge.2).stack ∧
    (deviceAt devices (portAt ports edge.1).owner).inbound = [] := by
  unfold switches ports devices
  decide

lemma forward_default_checks : ∀ device ∈ ({} : DeviceData) :: devices,
    device.forwardFallback = .deny := by
  unfold devices
  decide

lemma output_checks : FiniteOutputChecks devices ports := by
  unfold FiniteOutputChecks devices ports
  decide

lemma outer_route_checks : FiniteOuterRoutes devices ports routes := by
  unfold FiniteOuterRoutes devices ports routes
  decide

lemma local_stack_conditions : LocalStackConditions config layout :=
  local_stack_conditions_of_routed_finite_checks devices ports routes links switches
    route_owner_checks link_checks switch_checks forward_default_checks forward_checks
    output_checks outer_route_checks

theorem every_transmission_has_port_stack {start finish : Execution.State} {actions : List Action}
    (run : (lts config).MTr start actions finish) (initial : StackInvariant config layout start)
    (ready : finish.phase = .ready) : finish.frame.tags = layout finish.port :=
  transmitted_stack config layout local_stack_conditions run initial ready

tdn_data redSources : List Nat from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.redSources"]

tdn_data blackPorts : List Nat from "../../data/evidence/FreshFamily444.json" ["TDN.Imported.Family444.blackPorts"]

lemma sources_checked : ∀ p ∈ redSources, layout p = [] ∧ config.payloadOrigin p := by
  unfold redSources layout config finiteLayout finiteConfig ports; decide
lemma black_ports_checked : ∀ p ∈ blackPorts, layout p = [2, 1] := by
  unfold blackPorts layout finiteLayout ports; decide
theorem snapshot_IPv4_IPv6_ESP_packet_stack :
    Targets.msc_protected_red_payload_stack config redSources blackPorts :=
  Targets.protected_red_stack_from_local_checks config layout redSources blackPorts
    local_stack_conditions sources_checked black_ports_checked

end TDN.Imported.Family444
