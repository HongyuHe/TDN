import TDN.Requirements.OuterToGrayDevicePolicyBridge
import TDN.Requirements.DeviceRoutingAndFirewallRecords
import TDN.Requirements.BuildDevicePipelineInventory
import TDN.Models.TableDrivenMultiProtocolDataPlane
import TDN.Models.RawIkeAndUdpEspByteOffsets
import TDN.Import.SnapshotLoader

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

structure OwnerMask where
  owner : Nat
  device : String
  packet : PacketPolicy.AclFlowSelector

structure Records where
  components : List Device
  interfaces : List Interface
  ifaceNames : List String
  ownerNames : List String
  policies : List InterfacePolicy
  tunnels : List Tunnel
  pairs : List InnerIPsecPair
  masks : List OwnerMask
  ipsecSizes : List PacketProcessing.IPsecSizeBinding
  nativeDevices : List DataPlaneForwarding.DeviceData
  nativeIfaces : List DataPlaneForwarding.IfaceData
  routes : List DataPlaneForwarding.FibRoute
  links : List (Nat × Nat)
  bridges : List (Nat × Nat)

def Records.ifaceName (records : Records) (iface : Nat) : String :=
  records.ifaceNames[iface]?.getD "unlisted-port"

def Records.componentName (records : Records) (owner : Nat) : String :=
  records.ownerNames[owner]?.getD "unlisted-device"

def Records.configuration (records : Records) : MultiProtocolForwarding.Config :=
  let native := MultiProtocolForwarding.dataPlaneModelFromRecords records.nativeDevices records.nativeIfaces
    records.routes records.links records.bridges [] []
  { native with
    headerProcessing := some ⟨fun _ => 64, fun _ => 64⟩
    ip := { native.ip with
      localAddress := fun iface address => ∃ interface ∈ records.interfaces,
        interface.device = records.componentName (native.ip.owner iface) ∧
          interface.HasLocalAddress address } }

def Records.inventory (records : Records) : PacketProcessing.Inventory :=
  { ifaces := List.range records.nativeIfaces.length
    configuration := records.configuration
    ifaceName := records.ifaceName
    componentName := records.componentName
    mkaPeers := []
    ipsecSizes := records.ipsecSizes
    macsecTunnel := fun _ => "unlisted-MACsec-tunnel" }

def Records.reachableSource (records : Records) (interface : String) (address : Nat) : Prop :=
  ∃ iface ∈ records.inventory.ifaces, records.ifaceName iface = interface ∧
    ∃ route ∈ records.routes, route.ingress = iface ∧ route.egress = iface ∧
      DataPlaneForwarding.SelectedFibRoute records.routes route
        { source := address, destination := address, protocol := "esp", ingress := "", egress := "",
          sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5,
          matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" }

def Records.ifaceIndex (records : Records) (interface : Interface) : Nat :=
  records.ifaceNames.idxOf interface.id

def Records.projectedPolicies (records : Records) : List InterfacePolicy :=
  nativePolicies records.inventory records.interfaces records.ifaceIndex

def Records.deployment (records : Records) (base : Deployment) : Deployment :=
  { base with
    processing := some records.inventory
    devices := records.components
    interfaces := records.interfaces
    tunnels := records.tunnels
    policies := records.projectedPolicies
    focus := none
    services := [], managementServices := [], managementHistory := [], managementExchanges := []
    udpBindings := [], grayManagementTunnels := [], carrierBindings := []
    dropIPv4Options := fun _ => true
    grayWorkstation := fun _ => False
    policyApproved := fun _ _ => False
    aoApproved := fun _ _ => False
    grayManagementService := fun _ _ => False
    intendedPeer := fun source destination =>
      ∃ tunnel ∈ records.tunnels, tunnel.sender = source ∧ tunnel.receiver = destination
    reachableSource := records.reachableSource }

def Records.hookMasks (records : Records) : List HookMask :=
  records.interfaces.flatMap fun interface =>
    records.masks.flatMap fun entry =>
      if entry.device = interface.device then
        (if entry.packet.ingress =
            (records.configuration.ip.interfaceName ((records.ifaceNames.idxOf interface.id))) then
          [⟨interface.id, .inbound, .forward, entry.packet⟩] else []) ++
        (if entry.packet.egress =
            (records.configuration.ip.interfaceName ((records.ifaceNames.idxOf interface.id))) then
          [⟨interface.id, .outbound, .forward, entry.packet⟩] else [])
      else []

instance (records : Records) (base : Deployment) :
    DecidableRel (records.deployment base).intendedPeer := by
  intro source destination
  unfold Records.deployment
  infer_instance

end TDN.Deployments.OuterToGray_DeviceModel

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

lemma Records.forward_programs_are_per_owner (records : Records) (first second : Nat)
    (owner : records.configuration.ip.owner first = records.configuration.ip.owner second) :
    records.configuration.ip.forwardRules first = records.configuration.ip.forwardRules second ∧
      records.configuration.ip.forwardFallback first = records.configuration.ip.forwardFallback second := by
  change (DataPlaneForwarding.ifaceAt records.nativeIfaces first).owner =
    (DataPlaneForwarding.ifaceAt records.nativeIfaces second).owner at owner
  change (DataPlaneForwarding.deviceAt records.nativeDevices (DataPlaneForwarding.ifaceAt records.nativeIfaces first).owner).forwardRules =
      (DataPlaneForwarding.deviceAt records.nativeDevices (DataPlaneForwarding.ifaceAt records.nativeIfaces second).owner).forwardRules ∧
    (DataPlaneForwarding.deviceAt records.nativeDevices (DataPlaneForwarding.ifaceAt records.nativeIfaces first).owner).forwardFallback =
      (DataPlaneForwarding.deviceAt records.nativeDevices (DataPlaneForwarding.ifaceAt records.nativeIfaces second).owner).forwardFallback
  rw [owner]
  exact ⟨rfl, rfl⟩

instance (records : Records) (interface : String) : DecidablePred (records.reachableSource interface) := by
  intro address
  unfold Records.reachableSource
  infer_instance

lemma Records.policy_indices_from_unique_interfaces (records : Records) (base : Deployment)
    (unique : InterfaceIDsUnique records.interfaces) : policyIndicesChecked (records.deployment base) = true := by
  exact device_policies_have_checked_indices (records.deployment base) records.inventory records.ifaceIndex rfl unique

end TDN.Deployments.OuterToGray_DeviceModel

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

instance (records : Records) : DecidableRel records.configuration.bridge := by
  intro first second
  change Decidable ((first, second) ∈ records.bridges)
  infer_instance

lemma Records.processing_inventory_from_structure (records : Records) (base : Deployment)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (ifaces : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧
        records.inventory.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface) :
    processingInventoryChecked (records.deployment base) records.inventory = true := by
  exact device_policy_inventory_checks_from_structure (records.deployment base) records.inventory
    records.ifaceIndex rfl structureChecked ifaces atoms records.forward_programs_are_per_owner

lemma Records.processing_coherent_from_structure (records : Records) (base : Deployment)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (ifaces : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧
        records.inventory.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface) :
    (records.deployment base).ProcessingCoherent := by
  exact processing_coherence_from_record_checks (records.deployment base) records.inventory rfl
    (records.processing_inventory_from_structure base structureChecked ifaces atoms) rfl rfl

end TDN.Deployments.OuterToGray_DeviceModel

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance

instance (records : Records) : DecidableRel records.inventory.configuration.bridge := by
  intro first second
  change Decidable ((first, second) ∈ records.bridges)
  infer_instance

instance (records : Records) (base : Deployment) (interface : String) :
    DecidablePred ((records.deployment base).reachableSource interface) := by
  intro address
  change Decidable (records.reachableSource interface address)
  infer_instance

end TDN.Deployments.OuterToGray_DeviceModel

namespace TDN.Deployments.OuterToGray_DeviceModel

instance (records : Records) : DecidableRel records.inventory.configuration.physicalLink := by
  intro first second
  change Decidable ((first, second) ∈ records.links)
  infer_instance

end TDN.Deployments.OuterToGray_DeviceModel

namespace TDN.Deployments.OuterToGray_DeviceModel
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

def Records.ForwardMaskLookup (records : Records) (base : Deployment)
    (interface : Interface) (direction : Direction) : Prop :=
  ∀ record ∈ records.pairs, ∀ route ∈ records.routes,
    (if direction = .inbound then records.ifaceName route.ingress = interface.id
      else records.ifaceName route.egress = interface.id) →
    route.ingress ∈ records.inventory.ifaces → route.egress ∈ records.inventory.ifaces →
    DataPlaneForwarding.SelectedFibRoute records.routes route
      (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
    (direction = .inbound → records.reachableSource interface.id record.endpoints.sourceAddress) →
    ∀ choice ∈ authenticationChoices records.configuration route.ingress,
      AuthenticationChoiceValid (records.deployment base) records.inventory route.ingress
        record.endpoints.sourceAddress record.endpoints.destinationAddress choice →
      ∀ form ∈ PacketPolicy.IPsecForm.all, ∃ entry ∈ records.masks,
        entry.owner = (DataPlaneForwarding.ifaceAt records.nativeIfaces (records.ifaceIndex interface)).owner ∧
        entry.packet = form.mask record.endpoints.sourceAddress record.endpoints.destinationAddress
          (records.configuration.ip.interfaceName route.ingress)
          (records.configuration.ip.interfaceName route.egress) (choiceAuthentication choice)
          ((DataPlaneForwarding.lookupSpdPolicies (records.configuration.ip.egressPolicies route.egress)
            (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
              DataPlaneForwarding.IpsecPolicy.id) (interface.mtu.getD 0)

set_option synthInstance.maxSize 2048 in
instance (records : Records) (base : Deployment) (interface : Interface) (direction : Direction) :
    Decidable (records.ForwardMaskLookup base interface direction) := by
  unfold Records.ForwardMaskLookup
  infer_instance

lemma Records.forward_checks_from_mask_lookup (records : Records) (base : Deployment)
    (unique : InterfaceIDsUnique records.interfaces)
    (allowances : ∀ entry ∈ records.masks,
      entry.packet.IsPermittedByAclChain (DataPlaneForwarding.deviceAt records.nativeDevices entry.owner).forwardRules)
    (interface : Interface) (member : interface ∈ records.interfaces) (direction : Direction)
    (lookup : records.ForwardMaskLookup base interface direction) :
    OuterGrayForwardChecks (records.deployment base) records.inventory records.pairs interface direction := by
  intro record recordMember route routeMember name ingressMember egressMember selected reachable
    choice choiceMember valid form formMember policy policyMember policyName policyDirection hook
  obtain ⟨entry, entryMember, owner, packet⟩ := lookup record recordMember route routeMember name
    ingressMember egressMember selected reachable choice choiceMember valid form formMember
  obtain ⟨ownerInterface, ownerMember, nativeMember⟩ := List.mem_flatMap.mp policyMember
  have ownerName := device_policy_has_interface records.inventory ownerInterface _ policy nativeMember
  have same := unique ownerInterface ownerMember interface member (ownerName.symm.trans policyName)
  subst ownerInterface
  have projection := (device_policy_projects_raw_program records.inventory interface
    (records.ifaceIndex interface) policy nativeMember).2
  rw [PolicyNativeProjection, hook] at projection
  have covered := allowances entry entryMember
  rw [owner, packet] at covered
  rw [projection.1]
  exact covered

end TDN.Deployments.OuterToGray_DeviceModel
