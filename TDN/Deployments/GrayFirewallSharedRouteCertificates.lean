import TDN.Deployments.GrayFirewallSharedData
import TDN.Models.FibRouteCertificates

namespace TDN.Deployments.GrayFirewallShared
open Certificates DataPlaneForwarding OuterToGray_DeviceModel

set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

load_network_records routeTree : WitnessTree FibRoute from "../../data/evidence/certificates/GrayFirewallSharedRoutes.json" ["routes"]
load_network_records routeCertificates : List RouteCertificate from "../../data/evidence/certificates/GrayFirewallSharedRoutes.json" ["certificates"]

lemma route_tree_matches_capture : routeTree.values = records.routes := by decide

lemma route_certificates_checked :
    ∀ certificate ∈ routeCertificates, certificate.check routeTree = true := by decide

def certificateFor (address : Nat) : Option RouteCertificate :=
  routeCertificates.find? (fun certificate => certificate.destination == address)

def selectedRoutes (address : Nat) : List FibRoute :=
  ((certificateFor address).map (fun certificate => certificate.retained.values)).getD []

lemma selected_routes_exact (address : Nat) (certificate : RouteCertificate)
    (found : certificateFor address = some certificate) (route : FibRoute) (packet : PacketPolicy.Packet)
    (destination : packet.destination = address) :
    SelectedFibRoute records.routes route packet ↔ route ∈ certificate.retained.values := by
  have member := List.mem_of_find?_eq_some found
  have same : certificate.destination = address := by
    simpa using List.find?_some found
  rw [← route_tree_matches_capture]
  exact table_driven_route_certificate_sound routeTree certificate
    (route_certificates_checked certificate member) route packet (destination.trans same.symm)


def reachableSourceFromSelected (interface : String) (address : Nat) : Prop :=
  ∃ iface ∈ records.inventory.ifaces, records.ifaceName iface = interface ∧
    ∃ route ∈ selectedRoutes address, route.ingress = iface ∧ route.egress = iface

instance (interface : String) (address : Nat) :
    Decidable (reachableSourceFromSelected interface address) := by
  unfold reachableSourceFromSelected
  infer_instance

lemma reachable_source_from_selected_iff (interface : String) (address : Nat)
    (certificate : RouteCertificate) (found : certificateFor address = some certificate) :
    reachableSourceFromSelected interface address ↔ records.reachableSource interface address := by
  unfold reachableSourceFromSelected Records.reachableSource
  simp only [selectedRoutes, found, Option.map_some, Option.getD_some]
  constructor
  · rintro ⟨iface, member, name, route, retained, ingress, egress⟩
    have chosen := (selected_routes_exact address certificate found route (MultiProtocolForwarding.addressPoint address address) rfl).mpr retained
    exact ⟨iface, member, name, route, chosen.1, ingress, egress, chosen⟩
  · rintro ⟨iface, member, name, route, _, ingress, egress, chosen⟩
    exact ⟨iface, member, name, route,
      (selected_routes_exact address certificate found route _ rfl).mp chosen, ingress, egress⟩

lemma peer_destinations_have_certificates :
    ∀ record ∈ records.pairs, (certificateFor record.endpoints.destinationAddress).isSome = true := by decide

lemma peer_selected_routes_covered :
    ∀ record ∈ records.pairs, ∀ route,
      SelectedFibRoute records.inventory.configuration.ip.routes route
        (MultiProtocolForwarding.addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
      route ∈ selectedRoutes record.endpoints.destinationAddress := by
  intro record member route selected
  obtain ⟨certificate, found⟩ := Option.isSome_iff_exists.mp (peer_destinations_have_certificates record member)
  simp only [selectedRoutes, found, Option.map_some, Option.getD_some]
  exact (selected_routes_exact _ certificate found route _ rfl).mp selected

end TDN.Deployments.GrayFirewallShared
