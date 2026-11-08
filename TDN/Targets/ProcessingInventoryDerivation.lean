import TDN.Targets.InventoryDerivation

namespace TDN.Targets
open Compliance

instance (hook : PacketProcessing.Hook) (atom : PacketPolicy.Atom) :
    Decidable (AtomAtHook hook atom) := by
  cases atom <;> unfold AtomAtHook <;> infer_instance

def PolicyNativeProjection (inventory : PacketProcessing.Inventory)
    (policy : InterfacePolicy) (iface : Nat) : Prop :=
  match policy.hook with
  | .input =>
      policy.rules = inventory.configuration.ip.inputRules iface ∧
      policy.defaultVerdict = inventory.configuration.ip.inputFallback iface
  | .output =>
      policy.rules = inventory.configuration.ip.outputRules iface ∧
      policy.defaultVerdict = inventory.configuration.ip.outputFallback iface
  | .forward =>
      policy.rules = inventory.configuration.ip.forwardRules iface ∧
      policy.defaultVerdict = inventory.configuration.ip.forwardFallback iface
  | .link => False

instance (inventory : PacketProcessing.Inventory) (policy : InterfacePolicy) (iface : Nat) :
    Decidable (PolicyNativeProjection inventory policy iface) := by
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
    endpoint.sourceIface ∈ inventory.ifaces ∧ endpoint.destinationIface ∈ inventory.ifaces ∧
    (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.sourceIface) ∧
    (∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = endpoint.destinationIface) ∧
    ∃ interface ∈ d.interfaces, interface.id = inventory.ifaceName endpoint.sourceIface ∧
      interface.linkAddress = some (endpoint.actorSCI / 65536)) ∧
  (∀ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec →
    ∃ endpoint ∈ inventory.mkaPeers, endpoint.tunnel = tunnel.id ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = tunnel.sender ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = tunnel.receiver) ∧
  (∀ iface ∈ inventory.ifaces, ∃ interface ∈ d.interfaces,
    interface.id = inventory.ifaceName iface ∧
    interface.device = inventory.componentName (inventory.configuration.ip.owner iface)) ∧
  (∀ interface ∈ d.interfaces, ∃ iface ∈ inventory.ifaces,
    inventory.ifaceName iface = interface.id ∧
    inventory.componentName (inventory.configuration.ip.owner iface) = interface.device) ∧
  (∀ first ∈ inventory.ifaces, ∀ second ∈ inventory.ifaces,
    inventory.ifaceName first = inventory.ifaceName second → first = second) ∧
  (∀ interface ∈ d.interfaces, InterfaceMtuCheck interface) ∧
  (∀ iface ∈ inventory.ifaces, ∀ policy ∈ inventory.configuration.ip.outbound iface,
    ∃ size ∈ inventory.ipsecSizes, size.iface = iface ∧ size.policy = policy) ∧
  (∀ size ∈ inventory.ipsecSizes, size.Valid ∧ size.iface ∈ inventory.ifaces ∧
    size.policy ∈ inventory.configuration.ip.outbound size.iface) ∧
  (∀ route ∈ inventory.configuration.ip.routes,
    route.ingress ∈ inventory.ifaces ∧ route.egress ∈ inventory.ifaces ∧
    inventory.configuration.ip.owner route.ingress = inventory.configuration.ip.owner route.egress) ∧
  (∀ first ∈ inventory.ifaces, ∀ second ∈ inventory.ifaces,
    inventory.configuration.ip.owner first = inventory.configuration.ip.owner second →
    inventory.configuration.ip.forwardRules first = inventory.configuration.ip.forwardRules second ∧
    inventory.configuration.ip.forwardFallback first = inventory.configuration.ip.forwardFallback second) ∧
  (∀ policy ∈ d.policies, ∃ interface ∈ d.interfaces, ∃ iface ∈ inventory.ifaces,
    interface.id = policy.interface ∧ inventory.ifaceName iface = interface.id ∧
    interface.HookApplies policy.hook policy.direction ∧
    (∀ rule ∈ policy.rules, ∀ atom ∈ rule.atoms, AtomAtHook policy.hook atom) ∧
    PolicyNativeProjection inventory policy iface)

instance (d : Deployment) (inventory : PacketProcessing.Inventory) :
    Decidable (ProcessingInventoryChecks d inventory) := by
  unfold ProcessingInventoryChecks
  exact instDecidableAnd

def processingInventoryChecked (d : Deployment) (inventory : PacketProcessing.Inventory) : Bool :=
  decide (ProcessingInventoryChecks d inventory)

def nativeLocalAddress (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface address : Nat) : Prop :=
  ∃ interface ∈ d.interfaces,
    interface.device = inventory.componentName (inventory.configuration.ip.owner iface) ∧
    interface.HasLocalAddress address

theorem processing_coherence_from_record_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (checked : processingInventoryChecked d inventory = true)
    (lengthDefinition : (fun packet payload =>
      inventory.configuration.networkBytes (.datagram packet) payload) =
        (fun packet _ => packet.networkBytes))
    (localAddressDefinition : inventory.configuration.ip.localAddress = nativeLocalAddress d inventory) :
    d.ProcessingCoherent := by
  obtain ⟨mkaPeers, macsecTunnels, ifaceBindings, interfaceBindings, names,
    mtus, sizeCoverage, sizes, routes, forwardRules, policies⟩ :
      ProcessingInventoryChecks d inventory := of_decide_eq_true checked
  refine ⟨inventory, present, mkaPeers, macsecTunnels, ifaceBindings, interfaceBindings,
    names, ?_, mtus, sizeCoverage, sizes, routes, ?_, forwardRules, policies⟩
  · intro packet payload
    exact congrFun (congrFun lengthDefinition packet) payload
  · intro iface _ address
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
