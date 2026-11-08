import TDN.Targets.OuterGrayNormalForms
import TDN.Semantics.IPsecInput
import TDN.Semantics.IPsecPacketForms

namespace TDN.Targets.Complete
open Compliance EndpointRuleDerivation MultiProtocolExecution

def authenticationChoices (configuration : MultiProtocolExecution.Config) (iface : Nat) :
    List (Option Execution.Association) :=
  none :: (configuration.ip.inbound iface).map some

def choiceAuthentication (choice : Option Execution.Association) : List Nat :=
  choice.toList.map Execution.Association.id

def PotentialArrival (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface source : Nat) : Prop :=
  NativeIngressAttachment inventory iface ∨
    (∃ interface ∈ d.interfaces,
      interface.device = inventory.componentName (inventory.configuration.ip.owner iface) ∧
        interface.HasLocalAddress source) ∨ source = 0 ∨ source = 2^128

instance (inventory : PacketProcessing.Inventory) (iface : Nat)
    [DecidableRel inventory.configuration.physicalLink] :
    Decidable (NativeIngressAttachment inventory iface) := by
  unfold NativeIngressAttachment
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (iface source : Nat)
    [DecidableRel inventory.configuration.physicalLink] :
    Decidable (PotentialArrival d inventory iface source) := by
  unfold PotentialArrival
  infer_instance

lemma eligible_native_arrival_has_potential_source (d : Deployment)
    (inventory : PacketProcessing.Inventory) (state : MultiProtocolExecution.State) (source : Nat)
    (arrival : d.NativeArrivalEligible inventory state)
    (sameSource : ∀ incoming, state.frame.visibleHeader = some incoming → incoming.source = source) :
    PotentialArrival d inventory state.iface source := by
  rcases arrival with attachment | ⟨incoming, visible, localSource⟩
  · exact Or.inl attachment
  · have sourceEq := sameSource incoming visible
    rcases localSource with owned | dhcp | solicitation
    · exact Or.inr (Or.inl (by simpa only [sourceEq] using owned))
    · exact Or.inr (Or.inr (Or.inl (sourceEq.symm.trans dhcp.1)))
    · exact Or.inr (Or.inr (Or.inr (sourceEq.symm.trans solicitation.1)))

def AuthenticationChoiceValid (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface source destination : Nat) (choice : Option Execution.Association) : Prop :=
  match choice with
  | none => PotentialArrival d inventory iface source ∧
      ¬ d.InboundIPsecRequired inventory iface (addressPoint source destination)
  | some policy => PotentialArrival d inventory iface policy.sender ∧
      policy.matches (addressPoint source destination) = true ∧
      IPsecInputPossible inventory.configuration iface policy

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (iface : Nat) :
    Decidable (d.InboundIPsecBoundary inventory iface) := by
  unfold Deployment.InboundIPsecBoundary
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) (header : PacketPolicy.Packet) :
    Decidable (d.InboundIPsecRequired inventory iface header) := by
  unfold Deployment.InboundIPsecRequired
  infer_instance

instance (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface source destination : Nat) (choice : Option Execution.Association)
    [DecidableRel inventory.configuration.physicalLink] :
    Decidable (AuthenticationChoiceValid d inventory iface source destination choice) := by
  unfold AuthenticationChoiceValid
  cases choice <;> infer_instance

lemma context_packet_source (context : PacketProcessing.Context)
    (configuration : MultiProtocolExecution.Config) :
    (context.Packet configuration).source = context.header.source := by
  cases hook : context.hook <;> simp [PacketProcessing.Context.Packet, hook, policyHeader]

lemma context_packet_destination (context : PacketProcessing.Context)
    (configuration : MultiProtocolExecution.Config) :
    (context.Packet configuration).destination = context.header.destination := by
  cases hook : context.hook <;> simp [PacketProcessing.Context.Packet, hook, policyHeader]

lemma eligible_forward_has_route_and_authentication (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing)
    (noApproved : ∀ component traffic, ¬ d.policyApproved component traffic)
    (interface : Interface) (direction : Direction) (context : PacketProcessing.Context)
    (traffic : Traffic) (hook : context.hook = .forward)
    (supported : d.SupportedAt interface direction context traffic)
    (eligible : d.ContextIngressEligible context traffic)
    (source destination : Nat) (sourceEq : traffic.packet.source = source)
    (destinationEq : traffic.packet.destination = destination) :
    ∃ route ∈ inventory.configuration.ip.routes,
      route.ingress = context.state.enteredIface ∧ route.egress = context.state.iface ∧
      Execution.SelectedRoute inventory.configuration.ip.routes route (addressPoint source destination) ∧
      ∃ choice ∈ authenticationChoices inventory.configuration route.ingress,
        AuthenticationChoiceValid d inventory route.ingress source destination choice ∧
        context.state.authenticated = choiceAuthentication choice := by
  obtain ⟨actual, actualPresent, _, _, atHook, _, _, packetEq, _⟩ := supported
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  obtain ⟨validInventory, validPresent, coherent, arrival, required⟩ := eligible
  have same : validInventory = inventory := Option.some.inj (validPresent.symm.trans present)
  subst validInventory
  have sourceHeader : context.header.source = source := by
    rw [packetEq, context_packet_source] at sourceEq
    exact sourceEq
  have destinationHeader : context.header.destination = destination := by
    rw [packetEq, context_packet_destination] at destinationEq
    exact destinationEq
  obtain ⟨visible, atHook⟩ := atHook
  rw [hook] at atHook
  obtain ⟨entered, route, ingress, _, routed, _, _, selected, atEntry, atExit⟩ := atHook
  have ingressIfaces := ingress_has_native_ifaces ingress
  obtain ⟨enteredIface, authentication⟩ := ingress_route_detailed_authentication processing mode bounds
    coherent ingress routed visible
  have routeEntry : route.ingress = context.state.enteredIface :=
    atEntry.trans (ingressIfaces.1.trans enteredIface.symm)
  refine ⟨route, selected.1, routeEntry, atExit, ?_, ?_⟩
  · exact (selected_route_depends_on_destination _ route context.header
      (addressPoint source destination) destinationHeader).mp selected
  · rcases authentication with ⟨empty, sourceBefore⟩ |
        ⟨policy, configured, matched, authenticated, sourceBefore, inputPossible⟩
    · refine ⟨none, by simp [authenticationChoices], ?_, by simpa [choiceAuthentication] using empty⟩
      constructor
      · rw [routeEntry, enteredIface]
        exact eligible_native_arrival_has_potential_source d inventory context.entry source (arrival hook)
          (fun incoming visible => (sourceBefore incoming visible).trans sourceHeader)
      · intro boundary
        have entryEq : route.ingress = context.entry.iface := routeEntry.trans enteredIface
        rw [entryEq] at boundary
        have actualRequired : d.InboundIPsecRequired inventory context.entry.iface context.header := by
          rcases boundary with external | ⟨policy, configured, matched⟩
          · exact Or.inl external
          · exact Or.inr ⟨policy, configured, (association_matches_depends_on_addresses policy context.header
              (addressPoint source destination) sourceHeader destinationHeader).trans matched⟩
        rcases required hook actualRequired with ⟨decryptedState, decrypted, routed, _⟩ | ⟨_, approved, _⟩
        · exact decrypted_route_has_authentication decrypted routed empty
        · exact noApproved _ traffic approved
    · refine ⟨some policy, ?_, ?_, by simpa [choiceAuthentication] using authenticated⟩
      · simp only [authenticationChoices, List.mem_cons, List.mem_map]
        right
        exact ⟨policy, by simpa only [routeEntry, enteredIface] using configured, rfl⟩
      · refine ⟨?_, ?_, ?_⟩
        · rw [routeEntry, enteredIface]
          exact eligible_native_arrival_has_potential_source d inventory context.entry policy.sender
            (arrival hook) sourceBefore
        · exact (association_matches_depends_on_addresses policy context.header
            (addressPoint source destination) sourceHeader destinationHeader).symm.trans matched
        · rw [routeEntry, enteredIface]
          rcases required hook (Or.inr ⟨policy, configured, matched⟩) with
              ⟨_, _, _, admitted⟩ | ⟨_, approved, _⟩
          · exact inputPossible admitted
          · exact False.elim (noApproved _ traffic approved)

def OuterLocalSeparation (d : Deployment) (pairs : List InnerIPsecPair) : Prop :=
  ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer →
    ∀ endpoint ∈ d.interfaces, endpoint.device = interface.device →
      ∀ record ∈ pairs, ¬ endpoint.HasLocalAddress record.endpoints.sourceAddress ∧
        endpoint.address ≠ some record.endpoints.destinationAddress

lemma recorded_inner_packet_uses_forward_hook (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (pairs : List InnerIPsecPair) (separation : OuterLocalSeparation d pairs)
    (interface : Interface) (member : interface ∈ d.interfaces)
    (outer : d.IsLayer interface.device .outer) (direction : Direction)
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
      have denied := (separation interface member outer endpoint endpointMember owner record recordMember).2
      exact False.elim (denied (address.trans (congrArg some destinationHeader)))
  | output =>
    cases direction with
    | inbound => simp [Interface.HookApplies, HookDirection, hook] at applies
    | outbound =>
      simp only [hook] at location
      rcases location.2 with ⟨endpoint, endpointMember, owner, address⟩ | dhcp | solicitation
      · have denied := (separation interface member outer endpoint endpointMember owner record recordMember).1
        exact False.elim (denied (by simpa only [sourceHeader] using address))
      · exact False.elim (nonzero (sourceHeader.symm.trans dhcp.1))
      · exact False.elim (nonIPv6 (sourceHeader.symm.trans solicitation.1))
  | link => simp [Interface.HookApplies, hook] at applies

def InterfaceMtuBound (d : Deployment) (interface : Interface) (bound : Nat) : Prop :=
  ∀ other ∈ d.interfaces, other.id = interface.id →
    ∀ mtu ∈ other.mtu.toList, mtu ≤ bound

instance (d : Deployment) (interface : Interface) (bound : Nat) :
    Decidable (InterfaceMtuBound d interface bound) := by
  unfold InterfaceMtuBound
  infer_instance

lemma eligible_forward_size_at_interface (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (direction : Direction) (context : PacketProcessing.Context)
    (traffic : Traffic) (hook : context.hook = .forward)
    (supported : d.SupportedAt interface direction context traffic)
    (eligible : d.ContextSizeEligible context) (bound : Nat)
    (mtuBound : InterfaceMtuBound d interface bound) :
    ∃ bytes, traffic.packet.networkBytes = some bytes ∧ bytes ≤ bound := by
  obtain ⟨actual, actualPresent, _, _, _, location, _, packetEq, _⟩ := supported
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  obtain ⟨sizeInventory, sizePresent, bytes, total, receiveBound, sendBound⟩ := eligible
  have same : sizeInventory = inventory := Option.some.inj (sizePresent.symm.trans present)
  subst sizeInventory
  refine ⟨bytes, by simpa only [packetEq] using total, ?_⟩
  have name := location.2.2.2.2.2
  rw [hook] at name
  cases direction with
  | inbound =>
    obtain ⟨mtu, ⟨other, member, ifaceName, observed⟩, size⟩ := receiveBound (Or.inr hook)
    have otherName : other.id = interface.id := ifaceName.trans name
    exact size.trans (mtuBound other member otherName mtu (by simp [observed]))
  | outbound =>
    obtain ⟨mtu, ⟨other, member, ifaceName, observed⟩, size, _⟩ := sendBound (Or.inr hook)
    have otherName : other.id = interface.id := ifaceName.trans name
    exact size.trans (mtuBound other member otherName mtu (by simp [observed]))

instance (routes : List Execution.Route) (route : Execution.Route) (packet : PacketPolicy.Packet) :
    Decidable (Execution.SelectedRoute routes route packet) := by
  unfold Execution.SelectedRoute Execution.Route.matches
  infer_instance

def OuterGrayForwardChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (pairs : List InnerIPsecPair) (interface : Interface) (direction : Direction) : Prop :=
  ∀ record ∈ pairs, ∀ route ∈ inventory.configuration.ip.routes,
    (if direction = .inbound then inventory.ifaceName route.ingress = interface.id
      else inventory.ifaceName route.egress = interface.id) →
    route.ingress ∈ inventory.ifaces → route.egress ∈ inventory.ifaces →
    Execution.SelectedRoute inventory.configuration.ip.routes route
      (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) →
    (direction = .inbound → d.reachableSource interface.id record.endpoints.sourceAddress) →
    ∀ choice ∈ authenticationChoices inventory.configuration route.ingress,
      AuthenticationChoiceValid d inventory route.ingress record.endpoints.sourceAddress
        record.endpoints.destinationAddress choice →
      ∀ form ∈ PacketPolicy.IPsecForm.all, ∀ policy ∈ d.policies,
        policy.interface = interface.id → policy.direction = direction → policy.hook = .forward →
        (form.mask record.endpoints.sourceAddress record.endpoints.destinationAddress
          (inventory.configuration.ip.interfaceName route.ingress)
          (inventory.configuration.ip.interfaceName route.egress) (choiceAuthentication choice)
          ((Execution.selectedAssociations (inventory.configuration.ip.outbound route.egress)
            (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
              Execution.Association.id) (interface.mtu.getD 0)).Covers policy.rules

set_option synthInstance.maxSize 2048 in
instance (d : Deployment) (inventory : PacketProcessing.Inventory) (pairs : List InnerIPsecPair)
    (interface : Interface) (direction : Direction)
    [DecidablePred (d.reachableSource interface.id)]
    [DecidableRel inventory.configuration.physicalLink] :
    Decidable (OuterGrayForwardChecks d inventory pairs interface direction) := by
  unfold OuterGrayForwardChecks
  infer_instance

lemma eligible_Outer_gray_IPsec_packet_is_allowed (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (processing : HeaderProcessing) (mode : inventory.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing) (pairs : List InnerIPsecPair)
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
    (interface : Interface) (member : interface ∈ d.interfaces)
    (outer : d.IsLayer interface.device .outer) (gray : interface.zone = .gray)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface)
    (mtuBound : InterfaceMtuBound d interface (interface.mtu.getD 0))
    (direction : Direction) (checks : OuterGrayForwardChecks d inventory pairs interface direction)
    (hook : PacketProcessing.Hook) (traffic : Traffic)
    (eligible : d.PacketEligibleAt interface direction hook traffic)
    (restrictions : OuterGrayRestrictions d interface direction false traffic)
    (allowance : OuterPolicyAllowance d interface.device false traffic)
    (policy : InterfacePolicy) (policyMember : policy ∈ d.policies)
    (policyName : policy.interface = interface.id) (policyDirection : policy.direction = direction)
    (policyHook : policy.hook = hook) : policy.Accepts traffic := by
  obtain ⟨ipsec, record, recordMember, source, destination⟩ := Outer_IPsec_allowance_has_record
    d pairs udp carrier mechanisms coverage noApproved noManagement interface.device traffic allowance
  obtain ⟨context, contextHook, supported, sizeEligible, ingressEligible⟩ :=
    routed_eligible_packet_has_native_context d inventory present interface routed direction hook traffic eligible
  have recordIPv4 := ipv4 record recordMember
  have sourceNonIPv6 : record.endpoints.sourceAddress ≠ 2^128 := by omega
  have forwardHook := recorded_inner_packet_uses_forward_hook d inventory present pairs separation
    interface member outer direction context traffic supported record recordMember
    (Nat.ne_of_gt recordIPv4.1) sourceNonIPv6 source destination
  have hookForward : hook = .forward := contextHook.symm.trans forwardHook
  have supportedForLater := supported
  obtain ⟨actual, actualPresent, _, _, _, location, raw, packetEq, packetSupported⟩ := supported
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  have sourceHeader : context.header.source = record.endpoints.sourceAddress := by
    rw [packetEq, context_packet_source] at source
    exact source
  have destinationHeader : context.header.destination = record.endpoints.destinationAddress := by
    rw [packetEq, context_packet_destination] at destination
    exact destination
  obtain ⟨route, routeMember, routeIngress, routeEgress, selected, choice, choiceMember,
    validChoice, authentication⟩ := eligible_forward_has_route_and_authentication d inventory present
      processing mode bounds noApproved interface direction context traffic forwardHook
      supportedForLater ingressEligible record.endpoints.sourceAddress record.endpoints.destinationAddress source destination
  have nativeIngress : route.ingress ∈ inventory.ifaces := routeIngress ▸ location.2.2.1
  have nativeEgress : route.egress ∈ inventory.ifaces := routeEgress ▸ location.2.1
  have nativeName : (if direction = .inbound then inventory.ifaceName route.ingress = interface.id
      else inventory.ifaceName route.egress = interface.id) := by
    have name := location.2.2.2.2.2
    rw [forwardHook] at name
    cases direction <;> simpa [routeIngress, routeEgress] using name
  have reachable : direction = .inbound →
      d.reachableSource interface.id record.endpoints.sourceAddress := by
    intro inbound
    simpa only [source] using restrictions.2.2.1 inbound
  have complete : context.raw.Complete traffic.packet := by
    simpa only [packetEq] using raw.1
  obtain ⟨form, formMember, formMatches⟩ := PacketPolicy.decoded_IPsec_has_form context.raw traffic.packet
    complete (by simpa only [source] using recordIPv4.2.1) ipsec
  have version : traffic.ipVersion = some 4 := by
    rw [packetSupported.1]
    change PacketIPVersion traffic.packet = some 4
    rcases ipsec with esp | ike | udpESP
    · simp [PacketIPVersion, esp, source, destination, recordIPv4.2.1, recordIPv4.2.2]
    · simp [PacketIPVersion, ike.1, source, destination, recordIPv4.2.1, recordIPv4.2.2]
    · simp [PacketIPVersion, udpESP.1, source, destination, recordIPv4.2.1, recordIPv4.2.2]
  obtain ⟨device, deviceMember, owner, layer⟩ := outer
  obtain ⟨kind, options⟩ := vpn device deviceMember layer
  have words : traffic.packet.ipv4HeaderWords = 5 :=
    (restrictions.1 device deviceMember owner).2.2.1 kind layer version options
  have size := eligible_forward_size_at_interface d inventory present interface direction context traffic
    forwardHook supportedForLater sizeEligible (interface.mtu.getD 0) mtuBound
  have covered := checks record recordMember route routeMember nativeName nativeIngress nativeEgress
    selected reachable choice choiceMember validChoice form formMember policy policyMember policyName
    policyDirection (policyHook.trans hookForward)
  have ingressName : traffic.packet.ingress = inventory.configuration.ip.interfaceName route.ingress := by
    rw [packetEq]
    simp [PacketProcessing.Context.Packet, forwardHook, policyHeader, routeIngress]
  have egressName : traffic.packet.egress = inventory.configuration.ip.interfaceName route.egress := by
    rw [packetEq]
    simp [PacketProcessing.Context.Packet, forwardHook, policyHeader, routeEgress]
  have inbound : choiceAuthentication choice = traffic.packet.inboundPolicies := by
    rw [packetEq]
    simpa only [PacketProcessing.Context.Packet, forwardHook, policyHeader] using authentication.symm
  have outbound :
      ((Execution.selectedAssociations (inventory.configuration.ip.outbound route.egress)
        (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress)).map
          Execution.Association.id) = traffic.packet.outboundPolicies := by
    rw [packetEq]
    simp only [PacketProcessing.Context.Packet, forwardHook, policyHeader, routeEgress]
    rw [selected_associations_depend_on_addresses _ context.header
      (addressPoint record.endpoints.sourceAddress record.endpoints.destinationAddress) sourceHeader destinationHeader]
  exact PacketPolicy.Mask.covered_packets_are_allowed _ policy.rules covered policy.defaultVerdict traffic.packet
    (PacketPolicy.IPsecForm.mask_matches form _ _ _ _ _ _ _ traffic.packet formMatches source destination
      ingressName egressName words inbound outbound size)

end TDN.Targets.Complete
