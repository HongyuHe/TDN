import TDN.Requirements.DeviceProtocolAllowlistProof
import TDN.Requirements.DeviceTunnelPeerAclProof
import TDN.Requirements.OuterFirewallControlAcl

namespace TDN.Requirements.Msc
open Compliance

def BoundaryProtocolChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (interface : Interface) : Prop :=
  ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
    ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
        DeviceProtocolRule (inventory.configuration.ip.interfaceName iface) policy.direction rule

def BoundaryPeerChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (interface : Interface) (peers : List BoundaryPeer) : Prop :=
  ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
    ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny ∧ (policy.direction = .outbound →
        ∀ rule ∈ policy.rules, rule.verdict = .allow →
          OutboundPeerRule interface.device (inventory.configuration.ip.interfaceName iface) peers rule)

def BoundaryRedChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (interface : Interface) (endpoints : List RedServiceEndpoint) : Prop :=
  ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
    ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
        RedBoundaryRule interface.device (inventory.configuration.ip.interfaceName iface)
          policy.direction endpoints rule

def BoundaryFirewallChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (controls : List BoundaryControlFlow)
    (interface : Interface) (outer : String) (internal : Bool) : Prop :=
  ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
    ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
        FirewallControlBoundaryRule d controls interface.device outer internal
          (inventory.configuration.ip.interfaceName iface) policy.direction policy.hook rule

def BoundaryInterfaceChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (required : Bool) (internal : String → Bool) (localOuter : String → String)
    (endpoints : List RedServiceEndpoint) (peers : List BoundaryPeer) (controls : List BoundaryControlFlow)
    (interface : Interface) (device : Device) : Prop :=
  (CryptographicBoundary device interface → BoundaryProtocolChecks d inventory interface) ∧
  ((device.layer = some .outer ∧ interface.zone = .black) →
    BoundaryPeerChecks d inventory interface peers) ∧
  ((device.layer = some .inner ∧ interface.zone = .red) →
    BoundaryRedChecks d inventory interface endpoints) ∧
  ((device.kind = .outerFirewall ∧ required = true) →
    d.IsLayer (localOuter device.id) .outer ∧
      BoundaryFirewallChecks d inventory controls interface (localOuter device.id) (internal interface.id))

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (interface : Interface) :
    Decidable (BoundaryProtocolChecks d inventory interface) := by
  unfold BoundaryProtocolChecks
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (interface : Interface)
    (peers : List BoundaryPeer) : Decidable (BoundaryPeerChecks d inventory interface peers) := by
  unfold BoundaryPeerChecks
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (interface : Interface)
    (endpoints : List RedServiceEndpoint) : Decidable (BoundaryRedChecks d inventory interface endpoints) := by
  unfold BoundaryRedChecks
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (interface : Interface)
    (controls : List BoundaryControlFlow) (outer : String) (internal : Bool) :
    Decidable (BoundaryFirewallChecks d inventory controls interface outer internal) := by
  unfold BoundaryFirewallChecks
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (required : Bool)
    (internal : String → Bool) (localOuter : String → String)
    (endpoints : List RedServiceEndpoint) (peers : List BoundaryPeer) (controls : List BoundaryControlFlow)
    (interface : Interface) (device : Device) :
    Decidable (BoundaryInterfaceChecks d inventory required internal localOuter endpoints peers controls interface device) := by
  letI : DecidablePred (fun component => d.IsLayer component .outer) := fun component => by
    unfold Deployment.IsLayer
    infer_instance
  unfold BoundaryInterfaceChecks
  infer_instance

end TDN.Requirements.Msc
