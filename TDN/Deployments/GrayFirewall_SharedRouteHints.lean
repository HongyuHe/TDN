import TDN.Deployments.GrayFirewall_SharedData
import TDN.Models.FibRouteLookupHints

namespace TDN.Deployments.GrayFirewall_Shared
open LookupHints DataPlaneForwarding OuterToGray_DeviceModel

set_option maxRecDepth 100000

load_network_records routeTree : LookupTree FibRoute from "../../data/evidence/lookup-hints/GrayFirewallSharedRoutes.json" ["routes"]
load_network_records routeHints : List FibRouteLookupHint from "../../data/evidence/lookup-hints/GrayFirewallSharedRoutes.json" ["hints"]

lemma route_tree_matches_capture : routeTree.values = records.routes := by native_decide

lemma route_hints_checked :
    ∀ hint ∈ routeHints, hint.check routeTree = true := by native_decide

def routeHintFor (address : Nat) : Option FibRouteLookupHint :=
  routeHints.find? (fun hint => hint.destination == address)

def selectedRoutes (address : Nat) : List FibRoute :=
  ((routeHintFor address).map (fun hint => hint.retained.values)).getD []

lemma selected_routes_exact (address : Nat) (hint : FibRouteLookupHint)
    (found : routeHintFor address = some hint) (route : FibRoute) (packet : PacketPolicy.Packet)
    (destination : packet.destination = address) :
    SelectedFibRoute records.routes route packet ↔ route ∈ hint.retained.values := by
  have member := List.mem_of_find?_eq_some found
  have same : hint.destination = address := by
    simpa using List.find?_some found
  rw [← route_tree_matches_capture]
  exact checked_route_hint_selects_exact_routes routeTree hint
    (route_hints_checked hint member) route packet (destination.trans same.symm)


def reachableSourceFromSelected (interface : String) (address : Nat) : Prop :=
  ∃ iface ∈ records.inventory.ifaces, records.ifaceName iface = interface ∧
    ∃ route ∈ selectedRoutes address, route.ingress = iface ∧ route.egress = iface

instance (interface : String) (address : Nat) :
    Decidable (reachableSourceFromSelected interface address) := by
  unfold reachableSourceFromSelected
  infer_instance

lemma reachable_source_from_selected_iff (interface : String) (address : Nat)
    (hint : FibRouteLookupHint) (found : routeHintFor address = some hint) :
    reachableSourceFromSelected interface address ↔ records.reachableSource interface address := by
  unfold reachableSourceFromSelected Records.reachableSource
  simp only [selectedRoutes, found, Option.map_some, Option.getD_some]
  constructor
  · rintro ⟨iface, member, name, route, retained, ingress, egress⟩
    have chosen := (selected_routes_exact address hint found route (MultiProtocolForwarding.addressPoint address address) rfl).mpr retained
    exact ⟨iface, member, name, route, chosen.1, ingress, egress, chosen⟩
  · rintro ⟨iface, member, name, route, _, ingress, egress, chosen⟩
    exact ⟨iface, member, name, route,
      (selected_routes_exact address hint found route _ rfl).mp chosen, ingress, egress⟩

lemma peer_destinations_have_route_hints :
    ∀ record ∈ records.pairs, (routeHintFor record.endpoints.destinationAddress).isSome = true := by native_decide

lemma peer_selected_routes_covered :
    ∀ record ∈ records.pairs, ∀ route,
      SelectedFibRoute records.inventory.configuration.ip.routes route
        (MultiProtocolForwarding.addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
      route ∈ selectedRoutes record.endpoints.destinationAddress := by
  intro record member route selected
  obtain ⟨hint, found⟩ := Option.isSome_iff_exists.mp (peer_destinations_have_route_hints record member)
  simp only [selectedRoutes, found, Option.map_some, Option.getD_some]
  exact (selected_routes_exact _ hint found route _ rfl).mp selected

end TDN.Deployments.GrayFirewall_Shared
