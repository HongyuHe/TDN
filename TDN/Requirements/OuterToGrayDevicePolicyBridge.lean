import TDN.Requirements.OuterToGrayIptablesPatterns

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules MultiProtocolForwarding

theorem outer_gray_IPsec_policy_from_native_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) (pairs : List InnerIPsecPair)
    (addressChecked : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (coherent : d.ProcessingCoherent) (udpCoherent : d.UDPBindingsCoherent)
    (indices : policyIndicesChecked d = true)
    (bindings : ∀ record ∈ pairs, record.Bound d)
    (observations : IPsecObservationChecks d)
    (udp : d.udpBindings = []) (carrier : d.carrierBindings = [])
    (mechanisms : ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec)
    (coverage : InnerIPsecAddressCoverage d pairs)
    (noApproved : ∀ component traffic, ¬ d.policyApproved component traffic)
    (noManagement : ∀ component traffic, ¬ d.grayManagementService component traffic)
    (separation : OuterLocalSeparation d pairs)
    (ipv4 : ∀ record ∈ pairs, 0 < record.endpoints.sourceAddress ∧
      record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32)
    (vpn : ∀ device ∈ d.devices, device.layer = some .outer →
      device.kind = .vpn ∧ d.dropIPv4Options device.id = true)
    (routed : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (rules : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        ∀ policy ∈ d.policies, policy.interface = interface.id →
          policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
            OuterGrayRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
              policy.direction pairs rule)
    (mtus : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      InterfaceMtuBound d interface (interface.mtu.getD 0))
    (forward : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      ∀ direction, OuterGrayForwardChecks d inventory pairs interface direction) :
    msc_outer_gray_interface_policy d false := by
  have address := address_inventory_from_checked_records d addressChecked workstations
  refine ⟨address, coherent, udpCoherent, ?_⟩
  intro interface member _ outer gray
  have covered := policy_coverage_from_checked_indices d indices interface member
  refine ⟨covered, ?_, ?_⟩
  · intro direction traffic accepted
    exact admitted_Outer_gray_packet_is_safe d inventory present interface pairs bindings address observations gray
      (routed interface member outer gray) (rules interface member outer gray) direction traffic accepted false
  · intro direction hook traffic eligible restrictions allowance
    obtain ⟨context, contextHook, supported, _⟩ := routed_eligible_packet_has_native_context
      d inventory present interface (routed interface member outer gray) direction hook traffic eligible
    obtain ⟨_, _, _, applies, _, _, _, _, packetSupported⟩ := supported
    rw [contextHook] at applies
    obtain ⟨policy, policyMember, name, policyDirection, policyHook, unique⟩ := covered direction hook applies
    refine ⟨packetSupported, eligible_packet_has_hook_context d interface direction hook traffic eligible, ?_⟩
    have notLink : hook ≠ .link := applies.2.1
    simp only [notLink, ↓reduceIte]
    refine ⟨policy, policyMember, name, policyDirection, policyHook, unique, ?_⟩
    exact eligible_Outer_gray_IPsec_packet_is_allowed d inventory present processing mode bounds pairs udp carrier
      mechanisms coverage noApproved noManagement separation ipv4 vpn interface member outer gray
      (routed interface member outer gray) (mtus interface member outer gray) direction
      (forward interface member outer gray direction) hook traffic eligible restrictions allowance policy
      policyMember name policyDirection policyHook

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules

instance (d : Deployment) (component : String) (layer : Layer) :
    Decidable (d.IsLayer component layer) := by
  unfold Deployment.IsLayer
  infer_instance

instance (record : InnerIPsecPair) (d : Deployment) [DecidableRel d.intendedPeer] :
    Decidable (record.Bound d) := by
  unfold InnerIPsecPair.Bound SameLevelComponents
  infer_instance

instance (d : Deployment) (pairs : List InnerIPsecPair) :
    Decidable (OuterLocalSeparation d pairs) := by
  unfold OuterLocalSeparation
  infer_instance

instance (d : Deployment) (interface : Interface) (rule : PacketPolicy.Rule) :
    Decidable (OuterGrayHeaderRule d interface rule) := by
  unfold OuterGrayHeaderRule
  infer_instance

instance (d : Deployment) (interface : Interface) (name : String) (direction : Direction)
    (pairs : List InnerIPsecPair) (rule : PacketPolicy.Rule)
    [DecidablePred (d.reachableSource interface.id)] :
    Decidable (OuterGrayRuleChecks d interface name direction pairs rule) := by
  unfold OuterGrayRuleChecks
  infer_instance

instance (inventory : PacketProcessing.Inventory) (iface : Nat)
    [DecidableRel inventory.configuration.bridge] :
    Decidable (DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface) := by
  unfold DeriveDataPlaneFromDeviceRecords.RoutedIface
  infer_instance

lemma gray_workstation_role_is_empty (d : Deployment)
    (none : ∀ device ∈ d.devices, device.kind ≠ .workstation)
    (declared : d.grayWorkstation = fun _ => False) :
    d.grayWorkstation = grayWorkstationRole d := by
  rw [declared]
  funext component
  apply propext
  constructor
  · intro impossible
    exact False.elim impossible
  · rintro ⟨⟨device, member, _, kind⟩, _⟩
    exact none device member kind

end TDN.Requirements.Msc
