import TDN.Deployments.Perimeter_DeviceModel
import TDN.Requirements.GrayFirewallDevicePolicyBridge
import TDN.Requirements.AuthorizedGrayControlFlows

namespace TDN.Deployments.GrayFirewallIptablesChecks
open Compliance Requirements Requirements.Msc Requirements.DeriveEndpointInputOutputRules OuterToGray_DeviceModel Perimeter_DeviceModel

deriving instance DecidableEq for Device

instance instDecidableGrayFirewallRole (d : Deployment) (component : String) :
    Decidable (d.IsDevice component .grayFirewall) := by
  unfold Deployment.IsDevice
  infer_instance

instance instDecidableRoutedGrayIface (inventory : PacketProcessing.Inventory) (iface : Nat)
    [DecidableRel inventory.configuration.bridge] :
    Decidable (DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface) := by
  unfold DeriveDataPlaneFromDeviceRecords.RoutedIface
  infer_instance

instance instDecidableBoundGrayPeer (record : InnerIPsecPair) (d : Deployment)
    [DecidableRel d.intendedPeer] : Decidable (record.Bound d) := by
  unfold InnerIPsecPair.Bound SameLevelComponents
  infer_instance

instance instDecidableRegisteredGrayReachableSource
    (records : Records) (services : List ServiceRegistration)
    (endpoints : List RedServiceEndpoint) (base : Deployment)
    (controls : List BoundaryControlFlow) (interface : String) :
    DecidablePred ((registeredDeployment records services endpoints base controls).reachableSource interface) := by
  change DecidablePred (records.reachableSource interface)
  infer_instance

def GrayCoreChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (pairs : List InnerIPsecPair) (controls : List BoundaryControlFlow) : Prop :=
  (∀ record ∈ pairs, record.Bound d) ∧
  (∀ first ∈ d.devices, ∀ second ∈ d.devices, first.id = second.id → first = second) ∧
  GrayIPsecObservationChecks d ∧ GrayRevocationServiceAbsent d ∧
  (∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec) ∧
  InnerIPsecAddressCoverage d pairs ∧ DeviceNamesUniqueByComponent inventory ∧
  (∀ record ∈ pairs, 0 < record.endpoints.sourceAddress ∧
    record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32) ∧
  GrayControlInventoryDisjoint d controls

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (controls : List BoundaryControlFlow) [DecidableRel d.intendedPeer] :
    Decidable (GrayCoreChecks d inventory pairs controls) := by
  unfold GrayCoreChecks
  infer_instance

def GrayInterfaceChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (pairs : List InnerIPsecPair) (interface : Interface) : Prop :=
  d.IsDevice interface.device .grayFirewall →
    (∀ device ∈ d.devices, device.id = interface.device →
      device.kind = .grayFirewall ∧ device.layer = none) ∧
    (∀ iface ∈ inventory.ifaces,
      inventory.componentName (inventory.configuration.ip.owner iface) = interface.device →
      inventory.configuration.ip.ingressPolicies iface = []) ∧
    PeerEndpointSeparation d pairs interface ∧
    (∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface) ∧
    InterfaceMtuBound d interface (interface.mtu.getD 0) ∧
    (∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          GrayIPsecRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
            policy.direction pairs rule)

set_option synthInstance.maxSize 2048 in
instance (d : Deployment) (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (interface : Interface) [DecidableRel inventory.configuration.bridge]
    [DecidablePred (d.reachableSource interface.id)] :
    Decidable (GrayInterfaceChecks d inventory pairs interface) := by
  unfold GrayInterfaceChecks
  infer_instance

def GrayPermitChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (pairs : List InnerIPsecPair) (interface : Interface) : Prop :=
  d.IsDevice interface.device .grayFirewall →
    ∀ direction ∈ [Direction.inbound, .outbound], GrayForwardChecks d inventory pairs interface direction

set_option synthInstance.maxSize 2048 in
instance (d : Deployment) (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (interface : Interface) [∀ name, DecidablePred (d.reachableSource name)] :
    Decidable (GrayPermitChecks d inventory pairs interface) := by
  unfold GrayPermitChecks
  infer_instance

end TDN.Deployments.GrayFirewallIptablesChecks
