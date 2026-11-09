import TDN.Requirements.GrayFirewallRuleTemplates

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules MultiProtocolForwarding

def PeerEndpointSeparation (d : Deployment) (pairs : List InnerIPsecPair)
    (interface : Interface) : Prop :=
  ∀ endpoint ∈ d.interfaces, endpoint.device = interface.device →
    ∀ record ∈ pairs, ¬ endpoint.HasLocalAddress record.endpoints.sourceAddress ∧
      endpoint.address ≠ some record.endpoints.destinationAddress

instance (d : Deployment) (pairs : List InnerIPsecPair) (interface : Interface) :
    Decidable (PeerEndpointSeparation d pairs interface) := by
  unfold PeerEndpointSeparation
  infer_instance

lemma separated_peer_packet_uses_forward_hook (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (pairs : List InnerIPsecPair) (interface : Interface)
    (separation : PeerEndpointSeparation d pairs interface) (direction : Direction)
    (context : PacketProcessing.Context) (traffic : Traffic)
    (supported : d.SupportedAt interface direction context traffic)
    (record : InnerIPsecPair) (recordMember : record ∈ pairs)
    (nonzero : record.endpoints.sourceAddress ≠ 0)
    (nonIPv6 : record.endpoints.sourceAddress ≠ 2^128)
    (source : traffic.packet.source = record.endpoints.sourceAddress)
    (destination : traffic.packet.destination = record.endpoints.destinationAddress) :
    context.hook = .forward := by
  obtain ⟨actual, actualPresent, _, applies, _, location, _, packetEq, _⟩ := supported
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  have sourceHeader : context.header.source = record.endpoints.sourceAddress := by
    rw [packetEq, context_packet_source] at source
    exact source
  have destinationHeader : context.header.destination = record.endpoints.destinationAddress := by
    rw [packetEq, context_packet_destination] at destination
    exact destination
  obtain ⟨_, _, _, _, _, location⟩ := location
  cases hook : context.hook with
  | forward => rfl
  | input =>
    cases direction with
    | outbound => simp [Interface.HookApplies, HookDirection, hook] at applies
    | inbound =>
      simp only [hook] at location
      obtain ⟨endpoint, endpointMember, owner, address⟩ := location.2
      have denied := (separation endpoint endpointMember owner record recordMember).2
      exact False.elim (denied (address.trans (congrArg some destinationHeader)))
  | output =>
    cases direction with
    | inbound => simp [Interface.HookApplies, HookDirection, hook] at applies
    | outbound =>
      simp only [hook] at location
      rcases location.2 with ⟨endpoint, endpointMember, owner, address⟩ | dhcp | solicitation
      · have denied := (separation endpoint endpointMember owner record recordMember).1
        exact False.elim (denied (by simpa only [sourceHeader] using address))
      · exact False.elim (nonzero (sourceHeader.symm.trans dhcp.1))
      · exact False.elim (nonIPv6 (sourceHeader.symm.trans solicitation.1))
  | link => simp [Interface.HookApplies, hook] at applies

def GrayForwardChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (pairs : List InnerIPsecPair) (interface : Interface) (direction : Direction) : Prop :=
  ∀ record ∈ pairs, ∀ route ∈ inventory.configuration.ip.routes,
    (if direction = .inbound then inventory.ifaceName route.ingress = interface.id
      else inventory.ifaceName route.egress = interface.id) →
    route.ingress ∈ inventory.ifaces → route.egress ∈ inventory.ifaces →
    DataPlaneForwarding.SelectedFibRoute inventory.configuration.ip.routes route
      (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
    GrayIncomingSource d inventory interface.device route.ingress record.endpoints.sourceAddress →
    ∀ form ∈ PacketPolicy.IPsecForm.all, ∀ policy ∈ d.policies,
      policy.interface = interface.id → policy.direction = direction → policy.hook = .forward →
      (form.maskWithOptions record.endpoints.sourceAddress record.endpoints.destinationAddress
        (inventory.configuration.ip.interfaceName route.ingress)
        (inventory.configuration.ip.interfaceName route.egress) []
        ((DataPlaneForwarding.lookupSpdPolicies (inventory.configuration.ip.egressPolicies route.egress)
          (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
            DataPlaneForwarding.IpsecPolicy.id) (interface.mtu.getD 0)).IsPermittedByAclChain policy.rules

set_option synthInstance.maxSize 2048 in
instance (d : Deployment) (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (interface : Interface) (direction : Direction)
    [∀ name, DecidablePred (d.reachableSource name)] :
    Decidable (GrayForwardChecks d inventory pairs interface direction) := by
  unfold GrayForwardChecks
  infer_instance

lemma eligible_Gray_IPsec_packet_is_allowed (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) (pairs : List InnerIPsecPair)
    (udp : d.udpBindings = []) (carrier : d.carrierBindings = [])
    (mechanisms : ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec)
    (coverage : InnerIPsecAddressCoverage d pairs) (revocation : GrayRevocationServiceAbsent d)
    (unique : DeviceNamesUniqueByComponent inventory)
    (interface : Interface) (separation : PeerEndpointSeparation d pairs interface)
    (ipv4 : ∀ record ∈ pairs, 0 < record.endpoints.sourceAddress ∧
      record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32)
    (noApproved : ∀ traffic, ¬ d.policyApproved interface.device traffic)
    (noManagement : ∀ traffic, ¬ d.grayManagementService interface.device traffic)
    (noInbound : ∀ iface ∈ inventory.ifaces,
      inventory.componentName (inventory.configuration.ip.owner iface) = interface.device →
      inventory.configuration.ip.ingressPolicies iface = [])
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (mtuBound : InterfaceMtuBound d interface (interface.mtu.getD 0))
    (direction : Direction) (checks : GrayForwardChecks d inventory pairs interface direction)
    (hook : PacketProcessing.Hook) (traffic : Traffic)
    (eligible : d.PacketEligibleAt interface direction hook traffic)
    (permission : d.GrayForwardPermission interface hook traffic)
    (allowance : GrayPolicyAllowance d interface traffic)
    (policy : InterfacePolicy) (policyMember : policy ∈ d.policies)
    (policyName : policy.interface = interface.id) (policyDirection : policy.direction = direction)
    (policyHook : policy.hook = hook) : policy.Accepts traffic := by
  obtain ⟨context, contextHook, supported, sizeEligible, ingressEligible⟩ :=
    routed_eligible_packet_has_native_context d inventory present interface routed direction hook traffic eligible
  have supportedForLater := supported
  obtain ⟨actual, actualPresent, _, _, atHook, location, raw, packetEq, packetSupported⟩ := supported
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  obtain ⟨ipsec, record, recordMember, source, destination⟩ := Gray_IPsec_allowance_has_record
    d pairs udp carrier mechanisms coverage revocation interface noApproved noManagement traffic packetSupported allowance
  have recordIPv4 := ipv4 record recordMember
  have sourceNonIPv6 : record.endpoints.sourceAddress ≠ 2^128 := by omega
  have forwardHook := separated_peer_packet_uses_forward_hook d inventory present pairs interface separation
    direction context traffic supportedForLater record recordMember (Nat.ne_of_gt recordIPv4.1)
    sourceNonIPv6 source destination
  have hookForward : hook = .forward := contextHook.symm.trans forwardHook
  have sourceHeader : context.header.source = record.endpoints.sourceAddress := by
    rw [packetEq, context_packet_source] at source
    exact source
  have destinationHeader : context.header.destination = record.endpoints.destinationAddress := by
    rw [packetEq, context_packet_destination] at destination
    exact destination
  have atHookForLater := atHook
  obtain ⟨visible, forward⟩ := atHook
  rw [forwardHook] at forward
  obtain ⟨entered, route, ingress, _, routedStep, _, _, selected, atEntry, atExit⟩ := forward
  have ingressIfaces := ingress_has_native_ifaces ingress
  have preserved := route_from_ingress_preserves_local_state ingressIfaces.2.2 routedStep
  have enteredIface : context.state.enteredIface = context.entry.iface :=
    preserved.2.1.trans ingressIfaces.2.1
  obtain ⟨entryMember, exitMember, enteredMember, owner, sameOwner, location⟩ := location
  have entryOwner : inventory.componentName (inventory.configuration.ip.owner context.entry.iface) =
      interface.device := by
    rw [← enteredIface, sameOwner]
    exact owner
  obtain ⟨_, _, coherent, _⟩ := ingressEligible
  have empty := forward_context_without_inbound_policies_has_empty_authentication
    inventory.configuration processing mode bounds context forwardHook coherent atHookForLater
    (noInbound context.entry.iface entryMember entryOwner)
  have routeIngress : route.ingress = context.state.enteredIface :=
    atEntry.trans (ingressIfaces.1.trans enteredIface.symm)
  have nativeIngress : route.ingress ∈ inventory.ifaces := routeIngress ▸ enteredMember
  have nativeEgress : route.egress ∈ inventory.ifaces := atExit ▸ exitMember
  have nativeName : (if direction = .inbound then inventory.ifaceName route.ingress = interface.id
      else inventory.ifaceName route.egress = interface.id) := by
    rw [forwardHook] at location
    cases direction <;> simpa [routeIngress, atExit] using location
  have ingressName : inventory.configuration.ip.interfaceName route.ingress = traffic.packet.ingress := by
    rw [packetEq]
    simp [PacketProcessing.Context.Packet, forwardHook, policyHeader, routeIngress]
  have routeOwner : inventory.componentName (inventory.configuration.ip.owner route.ingress) =
      interface.device := by
    rw [routeIngress, sameOwner]
    exact owner
  have incoming := forward_permission_has_known_source_at_actual_iface d inventory present unique interface traffic
    route.ingress nativeIngress routeOwner ingressName (by simpa only [hookForward] using permission)
  have incomingPoint : GrayIncomingSource d inventory interface.device route.ingress record.endpoints.sourceAddress := by
    simpa only [source] using incoming
  have selectedPoint := (selected_route_depends_on_destination _ route context.header
    (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) destinationHeader).mp selected
  have complete : context.raw.Complete traffic.packet := by
    simpa only [packetEq] using raw.1
  obtain ⟨form, formMember, formMatches⟩ := PacketPolicy.decoded_IPsec_has_form context.raw traffic.packet
    complete (by simpa only [source] using recordIPv4.2.1) ipsec
  have size := eligible_forward_size_at_interface d inventory present interface direction context traffic
    forwardHook supportedForLater sizeEligible (interface.mtu.getD 0) mtuBound
  have covered := checks record recordMember route selected.1 nativeName nativeIngress nativeEgress
    selectedPoint incomingPoint form formMember policy policyMember policyName policyDirection
    (policyHook.trans hookForward)
  have egressName : traffic.packet.egress = inventory.configuration.ip.interfaceName route.egress := by
    rw [packetEq]
    simp [PacketProcessing.Context.Packet, forwardHook, policyHeader, atExit]
  have inbound : [] = traffic.packet.matchedInboundPolicyIds := by
    rw [packetEq]
    simpa only [PacketProcessing.Context.Packet, forwardHook, policyHeader] using empty.symm
  have outbound :
      ((DataPlaneForwarding.lookupSpdPolicies (inventory.configuration.ip.egressPolicies route.egress)
        (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
          DataPlaneForwarding.IpsecPolicy.id) = traffic.packet.matchedOutboundPolicyIds := by
    rw [packetEq]
    simp only [PacketProcessing.Context.Packet, forwardHook, policyHeader, atExit]
    rw [selected_associations_depend_on_addresses _ context.header
      (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) sourceHeader destinationHeader]
  exact PacketPolicy.AclFlowSelector.covered_packets_are_allowed _ policy.rules covered policy.defaultVerdict traffic.packet
    (PacketPolicy.IPsecForm.maskWithOptions_matches form _ _ _ _ _ _ _ traffic.packet formMatches source destination
      ingressName.symm egressName inbound outbound size)

end TDN.Requirements.Msc
