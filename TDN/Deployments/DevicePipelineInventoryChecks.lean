import TDN.Requirements.BuildDevicePipelineInventory

namespace TDN.Deployments.DevicePipelineInventoryChecks
open Compliance Requirements

def interfaces : List Interface :=
  [{ id := "in", device := "router", zone := .gray, address := some 10,
      physical := true, managementNetwork := false, mtu := some 1400 },
   { id := "out", device := "router", zone := .black, address := some 20,
      physical := true, managementNetwork := false, mtu := some 1500 }]

def name (iface : Nat) : String := if iface = 0 then "in" else "out"

def rules : List PacketPolicy.Rule :=
  [⟨[.protocol "esp", .sourceRange 0 100, .destinationRange 0 100], .allow⟩]

def policies : List InterfacePolicy :=
  interfaces.flatMap fun interface =>
    [⟨interface.id, .inbound, rules, .deny, .input⟩,
     ⟨interface.id, .outbound, rules, .deny, .output⟩,
     ⟨interface.id, .inbound, rules, .deny, .forward⟩,
     ⟨interface.id, .outbound, rules, .deny, .forward⟩]

def inventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { base with
    ifaces := [0, 1], ifaceName := name, componentName := fun _ => "router",
    mkaPeers := [], ipsecSizes := [],
    configuration := { base.configuration with
      ip := { base.configuration.ip with
        routes := [⟨0, 1, 0, 100, 0, 0, 0⟩],
        owner := fun _ => 0, interfaceName := name,
        localAddress := fun _ address =>
          ∃ interface ∈ interfaces, interface.address = some address,
        forwardRules := fun _ => rules, inputRules := fun _ => rules,
        outputRules := fun _ => rules, forwardFallback := fun _ => .deny,
        inputFallback := fun _ => .deny, outputFallback := fun _ => .deny,
        egressPolicies := fun _ => [], ingressPolicies := fun _ => [] },
      macIfaces := [], carriers := [], bridge := fun _ _ => False, linkPolicies := [],
      networkBytes := fun body _ => body.visibleHeader.bind PacketPolicy.Packet.networkBytes } }

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { base with
    interfaces := interfaces, policies := policies, tunnels := [],
    processing := some (inventory processing), udpBindings := [] }

lemma record_checks (base : Deployment) (processing : PacketProcessing.Inventory) :
    processingInventoryChecked (deployment base processing) (inventory processing) = true := by
  rfl

theorem configured_processing_is_coherent (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).ProcessingCoherent := by
  apply processing_coherence_from_record_checks
    (deployment base processing) (inventory processing) rfl (record_checks base processing)
  · rfl
  · funext iface address
    simp [inventory, nativeLocalAddress, deployment, interfaces, Interface.HasLocalAddress]

lemma missing_mtu_is_rejected (base : Deployment) (processing : PacketProcessing.Inventory) :
    processingInventoryChecked
      { deployment base processing with
        interfaces := interfaces.map fun interface => { interface with mtu := none } }
      (inventory processing) = false := by
  rfl

lemma wrong_owner_is_rejected (base : Deployment) (processing : PacketProcessing.Inventory) :
    processingInventoryChecked (deployment base processing)
      { inventory processing with componentName := fun _ => "unbound-owner" } = false := by
  rfl

lemma missing_policy_iface_is_rejected (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    processingInventoryChecked (deployment base processing)
      { inventory processing with ifaces := [0] } = false := by
  rfl

lemma wrong_native_hook_is_rejected (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    processingInventoryChecked (deployment base processing)
      { inventory processing with configuration :=
        { (inventory processing).configuration with ip :=
          { (inventory processing).configuration.ip with inputRules := fun _ => [] } } } = false := by
  rfl

lemma nonempty_route_and_interfaces (processing : PacketProcessing.Inventory) :
    (inventory processing).configuration.ip.routes ≠ [] ∧ interfaces ≠ [] := by
  simp [inventory, interfaces]

end TDN.Deployments.DevicePipelineInventoryChecks
