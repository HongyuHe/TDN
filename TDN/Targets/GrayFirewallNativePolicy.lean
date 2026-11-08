import TDN.Targets.GrayFirewallNativeForms

namespace TDN.Targets.Complete
open Compliance EndpointRuleDerivation

def GrayFirewallPolicyWithForwardSourceCheck (d : Deployment) (required : Bool) : Prop :=
  d.AddressInventoryCoherent ∧
  (required = true → d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
    ∀ interface ∈ d.interfaces, d.Relevant interface.device →
      d.IsDevice interface.device .grayFirewall → d.PolicyCoverage interface ∧
        (∀ direction traffic, d.Accepts interface.id direction traffic →
          GrayFirewallRestrictions d interface direction traffic ∧ GrayPolicyAllowance d interface traffic) ∧
        ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
          d.GrayForwardPermission interface hook traffic →
          GrayFirewallRestrictions d interface direction traffic → GrayPolicyAllowance d interface traffic →
          d.AcceptsAt interface.id direction hook traffic) ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → d.IsDevice interface.device .grayFirewall →
    ∀ direction traffic, DifferentClassificationVPNs d traffic → ¬ d.Accepts interface.id direction traffic

theorem gray_firewall_allowlist_from_native_IPsec_checks (d : Deployment)
    (unfocused : d.focus = none)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : MultiProtocolExecution.HeaderProcessing)
    (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : MultiProtocolExecution.HeaderBounds processing) (pairs : List InnerIPsecPair)
    (addressChecked : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (coherent : d.ProcessingCoherent) (udpCoherent : d.UDPBindingsCoherent)
    (indices : policyIndicesChecked d = true)
    (bindings : ∀ record ∈ pairs, record.Bound d)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices, first.id = second.id → first = second)
    (observations : GrayIPsecObservationChecks d) (revocation : GrayRevocationServiceAbsent d)
    (udp : d.udpBindings = []) (carrier : d.carrierBindings = [])
    (mechanisms : ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec)
    (coverage : InnerIPsecAddressCoverage d pairs)
    (unique : NativeNamesUniqueByComponent inventory)
    (ipv4 : ∀ record ∈ pairs, 0 < record.endpoints.sourceAddress ∧
      record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32)
    (roles : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ device ∈ d.devices, device.id = interface.device →
        device.kind = .grayFirewall ∧ device.layer = none)
    (noApproved : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ traffic, ¬ d.policyApproved interface.device traffic)
    (noManagement : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ traffic, ¬ d.grayManagementService interface.device traffic)
    (noInbound : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ iface ∈ inventory.ifaces,
        inventory.componentName (inventory.configuration.ip.owner iface) = interface.device →
        inventory.configuration.ip.inbound iface = [])
    (separation : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      PeerEndpointSeparation d pairs interface)
    (routed : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        PolicyDerivation.RoutedIface inventory iface)
    (rules : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        ∀ policy ∈ d.policies, policy.interface = interface.id →
          policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
            GrayIPsecRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
              policy.direction pairs rule)
    (mtus : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      InterfaceMtuBound d interface (interface.mtu.getD 0))
    (forward : ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
      ∀ direction, GrayForwardChecks d inventory pairs interface direction)
    (required : Bool) : msc_gray_firewall_allowlist d required := by
  have cleared : { d with focus := none } = d := by
    cases d
    cases unfocused
    rfl
  unfold msc_gray_firewall_allowlist
  rw [cleared]
  change GrayFirewallPolicyWithForwardSourceCheck d required
  have address := address_inventory_from_checked_records d addressChecked workstations
  have safe (interface : Interface) (member : interface ∈ d.interfaces)
      (role : d.IsDevice interface.device .grayFirewall) (direction : Direction) (traffic : Traffic)
      (accepted : d.Accepts interface.id direction traffic) :
      GrayFirewallRestrictions d interface direction traffic ∧ GrayPolicyAllowance d interface traffic :=
    admitted_Gray_firewall_IPsec_packet_is_safe d inventory present interface pairs bindings identifiers
      (roles interface member role) carrier address observations (routed interface member role)
      (rules interface member role) direction traffic accepted
  refine ⟨address, ?_, ?_⟩
  · intro _
    refine ⟨coherent, udpCoherent, ?_⟩
    intro interface member _ role
    have covered := policy_coverage_from_checked_indices d indices interface member
    refine ⟨covered, safe interface member role, ?_⟩
    intro direction hook traffic eligible permission _ allowance
    obtain ⟨context, contextHook, supported, _⟩ := routed_eligible_packet_has_native_context
      d inventory present interface (routed interface member role) direction hook traffic eligible
    obtain ⟨_, _, _, applies, _, _, _, _, packetSupported⟩ := supported
    rw [contextHook] at applies
    obtain ⟨policy, policyMember, name, policyDirection, policyHook, only⟩ := covered direction hook applies
    refine ⟨packetSupported, eligible_packet_has_hook_context d interface direction hook traffic eligible, ?_⟩
    have notLink : hook ≠ .link := applies.2.1
    simp only [notLink, ↓reduceIte]
    refine ⟨policy, policyMember, name, policyDirection, policyHook, only, ?_⟩
    exact eligible_Gray_IPsec_packet_is_allowed d inventory present processing mode bounds pairs udp carrier
      mechanisms coverage revocation unique interface (separation interface member role) ipv4
      (noApproved interface member role) (noManagement interface member role) (noInbound interface member role)
      (routed interface member role) (mtus interface member role) direction
      (forward interface member role direction) hook traffic eligible permission allowance policy policyMember
      name policyDirection policyHook
  · intro interface member _ role direction traffic different accepted
    have restrictions := (safe interface member role direction traffic accepted).1
    exact restrictions.2.2.2.2.2 different

end TDN.Targets.Complete
