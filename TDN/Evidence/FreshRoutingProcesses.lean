import TDN.Targets.RoutingProcesses

namespace TDN.Imported.FreshRoutingProcesses
open Targets

def outerDevices : List String := ["NB_O_A1", "NB_O_A2", "NB_O_B1", "NB_O_B2", "NF_O_A1", "NF_O_B1"]

def inventory (device : String) : List (ProcessServices.Process ObservedNetworkService) :=
  if device = "NB_O_A1" then [⟨790481, [.waiting]⟩, ⟨799203, [.ike]⟩] else
  if device = "NB_O_A2" then [⟨791546, [.waiting]⟩, ⟨799262, [.ike]⟩] else
  if device = "NB_O_B1" then [⟨792275, [.waiting]⟩, ⟨799321, [.ike]⟩] else
  if device = "NB_O_B2" then [⟨792618, [.waiting]⟩, ⟨799381, [.ike]⟩] else
  if device = "NF_O_A1" then [⟨850467, [.waiting]⟩, ⟨875150, [.ike]⟩] else
  if device = "NF_O_B1" then [⟨853940, [.waiting]⟩, ⟨875271, [.ike]⟩] else
  []

lemma complete_outer_count : outerDevices.length = 6 := by decide
lemma process_capabilities_checked : ∀ device ∈ outerDevices, ∀ process ∈ inventory device,
    ObservedNetworkService.routingProtocol ∉ process.services := by
  simp [outerDevices, inventory]

/-- Fixed captured process state under complete enumeration and program correspondence.
The result does not assert future-launch prevention or binary attestation. -/
theorem captured_outers_have_no_routing_protocol_service :
    outer_routing_protocols_disabled outerDevices inventory :=
  outer_routing_protocols_from_process_inventory outerDevices inventory process_capabilities_checked

end TDN.Imported.FreshRoutingProcesses
