import TDN.Targets.InventoryDerivation

namespace TDN.Targets
open Compliance

instance (hook : PacketProcessing.Hook) (atom : PacketPolicy.Atom) :
    Decidable (AtomAtHook hook atom) := by
  cases atom <;> unfold AtomAtHook <;> infer_instance

def PolicyNativeProjection (inventory : PacketProcessing.Inventory)
    (policy : InterfacePolicy) (port : Nat) : Prop :=
  match policy.hook with
  | .input =>
      policy.rules = inventory.configuration.ip.inputRules port ∧
      policy.defaultVerdict = inventory.configuration.ip.inputFallback port
  | .output =>
      policy.rules = inventory.configuration.ip.outputRules port ∧
      policy.defaultVerdict = inventory.configuration.ip.outputFallback port
  | .forward =>
      policy.rules = inventory.configuration.ip.forwardRules port ∧
      policy.defaultVerdict = inventory.configuration.ip.forwardFallback port
  | .link => False

instance (inventory : PacketProcessing.Inventory) (policy : InterfacePolicy) (port : Nat) :
    Decidable (PolicyNativeProjection inventory policy port) := by
  unfold PolicyNativeProjection
  cases policy.hook <;> infer_instance

def InterfaceMtuCheck (interface : Interface) : Prop :=
  ∃ mtu, interface.mtu = some mtu ∧ 0 < mtu

instance (interface : Interface) : Decidable (InterfaceMtuCheck interface) := by
  unfold InterfaceMtuCheck
  cases value : interface.mtu with
  | none => exact isFalse (by simp)
  | some mtu => exact decidable_of_iff (0 < mtu) (by simp)

def ProcessingInventoryChecks (d : Deployment) (inventory : PacketProcessing.Inventory) : Prop :=
  (∀ endpoint ∈ inventory.mkaPeers,
    endpoint.sourcePort ∈ inventory.ports ∧ endpoint.destinationPort ∈ inventory.ports ∧
    (∃ mac ∈ inventory.configuration.macPorts, mac.physicalPort = endpoint.sourcePort) ∧
    (∃ mac ∈ inventory.configuration.macPorts, mac.physicalPort = endpoint.destinationPort) ∧
    ∃ interface ∈ d.interfaces, interface.id = inventory.portName endpoint.sourcePort ∧
      interface.linkAddress = some (endpoint.actorSCI / 65536)) ∧
  (∀ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec →
    ∃ endpoint ∈ inventory.mkaPeers, endpoint.tunnel = tunnel.id ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.sourcePort) = tunnel.sender ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.destinationPort) = tunnel.receiver) ∧
  (∀ port ∈ inventory.ports, ∃ interface ∈ d.interfaces,
    interface.id = inventory.portName port ∧
    interface.device = inventory.componentName (inventory.configuration.ip.owner port)) ∧
  (∀ interface ∈ d.interfaces, ∃ port ∈ inventory.ports,
    inventory.portName port = interface.id ∧
    inventory.componentName (inventory.configuration.ip.owner port) = interface.device) ∧
  (∀ first ∈ inventory.ports, ∀ second ∈ inventory.ports,
    inventory.portName first = inventory.portName second → first = second) ∧
  (∀ interface ∈ d.interfaces, InterfaceMtuCheck interface) ∧
  (∀ port ∈ inventory.ports, ∀ policy ∈ inventory.configuration.ip.outbound port,
    ∃ size ∈ inventory.ipsecSizes, size.port = port ∧ size.policy = policy) ∧
  (∀ size ∈ inventory.ipsecSizes, size.Valid ∧ size.port ∈ inventory.ports ∧
    size.policy ∈ inventory.configuration.ip.outbound size.port) ∧
  (∀ route ∈ inventory.configuration.ip.routes,
    route.ingress ∈ inventory.ports ∧ route.egress ∈ inventory.ports ∧
    inventory.configuration.ip.owner route.ingress = inventory.configuration.ip.owner route.egress) ∧
  (∀ first ∈ inventory.ports, ∀ second ∈ inventory.ports,
    inventory.configuration.ip.owner first = inventory.configuration.ip.owner second →
    inventory.configuration.ip.forwardRules first = inventory.configuration.ip.forwardRules second ∧
    inventory.configuration.ip.forwardFallback first = inventory.configuration.ip.forwardFallback second) ∧
  (∀ policy ∈ d.policies, ∃ interface ∈ d.interfaces, ∃ port ∈ inventory.ports,
    interface.id = policy.interface ∧ inventory.portName port = interface.id ∧
    interface.HookApplies policy.hook policy.direction ∧
    (∀ rule ∈ policy.rules, ∀ atom ∈ rule.atoms, AtomAtHook policy.hook atom) ∧
    PolicyNativeProjection inventory policy port)

instance (d : Deployment) (inventory : PacketProcessing.Inventory) :
    Decidable (ProcessingInventoryChecks d inventory) := by
  unfold ProcessingInventoryChecks
  exact instDecidableAnd

def processingInventoryChecked (d : Deployment) (inventory : PacketProcessing.Inventory) : Bool :=
  decide (ProcessingInventoryChecks d inventory)

def nativeLocalAddress (d : Deployment) (inventory : PacketProcessing.Inventory)
    (port address : Nat) : Prop :=
  ∃ interface ∈ d.interfaces,
    interface.device = inventory.componentName (inventory.configuration.ip.owner port) ∧
    interface.address = some address

theorem processing_coherence_from_record_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (checked : processingInventoryChecked d inventory = true)
    (lengthDefinition : (fun packet payload =>
      inventory.configuration.networkBytes (.datagram packet) payload) =
        (fun packet _ => packet.networkBytes))
    (localAddressDefinition : inventory.configuration.ip.localAddress = nativeLocalAddress d inventory) :
    d.ProcessingCoherent := by
  obtain ⟨mkaPeers, macsecTunnels, portBindings, interfaceBindings, names,
    mtus, sizeCoverage, sizes, routes, forwardRules, policies⟩ :
      ProcessingInventoryChecks d inventory := of_decide_eq_true checked
  refine ⟨inventory, present, mkaPeers, macsecTunnels, portBindings, interfaceBindings,
    names, ?_, mtus, sizeCoverage, sizes, routes, ?_, forwardRules, policies⟩
  · intro packet payload
    exact congrFun (congrFun lengthDefinition packet) payload
  · intro port _ address
    rw [localAddressDefinition]
    rfl

instance (d : Deployment) : Decidable d.UDPBindingsCoherent := by
  unfold Deployment.UDPBindingsCoherent
  infer_instance

def udpBindingsChecked (d : Deployment) : Bool := decide d.UDPBindingsCoherent

lemma udp_bindings_coherent_from_check (d : Deployment)
    (checked : udpBindingsChecked d = true) : d.UDPBindingsCoherent :=
  of_decide_eq_true checked

end TDN.Targets
