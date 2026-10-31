import TDN.Semantics.ProcessServices

namespace TDN.Targets

inductive ObservedNetworkService where
  | waiting | ike | routingProtocol
  deriving DecidableEq, Repr

/-- OR8's routing-protocol clause for every Outer in an explicitly complete
selected inventory. Tunnel-terminal forwarding is a separate p24 clause. -/
def outer_routing_protocols_disabled (outers : List String)
    (inventory : String → List (ProcessServices.Process ObservedNetworkService)) : Prop :=
  ∀ outer ∈ outers, ¬ ProcessServices.Runs (inventory outer) .routingProtocol

theorem outer_routing_protocols_from_process_inventory (outers : List String)
    (inventory : String → List (ProcessServices.Process ObservedNetworkService))
    (checked : ∀ outer ∈ outers, ∀ process ∈ inventory outer,
      ObservedNetworkService.routingProtocol ∉ process.services) :
    outer_routing_protocols_disabled outers inventory := by
  intro outer member
  exact ProcessServices.service_absent_from_process_checks
    (inventory outer) .routingProtocol (checked outer member)

end TDN.Targets
