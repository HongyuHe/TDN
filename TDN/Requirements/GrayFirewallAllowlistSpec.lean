import TDN.Requirements.NormalizedOuterToGrayRules

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules

def GrayIPsecObservationChecks (d : Deployment) : Prop :=
  (∀ service ∈ d.services, service.protocol ≠ "esp") ∧
    ∀ device ∈ d.devices, device.kind ≠ .workstation

instance (d : Deployment) : Decidable (GrayIPsecObservationChecks d) := by
  unfold GrayIPsecObservationChecks
  infer_instance

lemma registered_ESP_service_is_absent (d : Deployment) (packet : PacketPolicy.Packet)
    (checks : GrayIPsecObservationChecks d) (esp : packet.protocol = "esp") :
    d.RegisteredService packet = none := by
  unfold Deployment.RegisteredService
  have absent : d.services.find? (fun service =>
      service.protocol == packet.protocol &&
        ((d.PacketOwner packet packet.destination == some service.device &&
          packet.destinationPort == service.port) ||
        (d.PacketOwner packet packet.source == some service.device &&
          packet.sourcePort == service.port))) = none := by
    apply List.find?_eq_none.mpr
    intro service member
    simp [esp, checks.1 service member]
  rw [absent]
  rfl

lemma Gray_IPsec_observation_is_not_management (d : Deployment)
    (packet : PacketPolicy.Packet) (checks : GrayIPsecObservationChecks d)
    (protocol : IPsecPacket packet) :
    (d.Observe packet).trafficClass ≠ .management ∧ (d.Observe packet).service ≠ "http" := by
  have workstation : d.devices.any (fun device => device.kind == .workstation &&
      (d.PacketOwner packet packet.source == some device.id ||
        d.PacketOwner packet packet.destination == some device.id)) = false := by
    apply List.any_eq_false.mpr
    intro device member
    simp [checks.2 device member]
  have observedClass : d.ObservedClass packet ≠ .management := by
    rcases protocol with esp | ike | udpESP
    · have absent := registered_ESP_service_is_absent d packet checks esp
      have notIKE : ¬ PacketIKE packet := by simp [PacketIKE, esp]
      have notUDPESP : ¬ PacketUDPESP packet := by simp [PacketUDPESP, esp]
      unfold Deployment.ObservedClass
      simp only [notIKE, notUDPESP, ↓reduceIte]
      split
      · decide
      · simp [absent, PacketClass, PacketService, PacketPortService, PacketIKE,
          PacketUDPESP, PacketMKA, PacketARP, PacketIsEthernet, esp, workstation]
    · simp [Deployment.ObservedClass, ike]
    · by_cases ike : PacketIKE packet
      · simp [Deployment.ObservedClass, ike]
      · simp [Deployment.ObservedClass, ike, udpESP]
  constructor
  · change (if d.RevocationEndpoint packet then .protectedData else d.ObservedClass packet) ≠ .management
    split
    · decide
    · exact observedClass
  · change d.ObservedService packet ≠ "http"
    rcases protocol with esp | ike | udpESP
    · have absent := registered_ESP_service_is_absent d packet checks esp
      simp [Deployment.ObservedService, PacketService, PacketPortService, PacketIKE,
        PacketUDPESP, esp, absent]
    · simp [Deployment.ObservedService, ike]
    · by_cases ike : PacketIKE packet
      · simp [Deployment.ObservedService, ike]
      · simp [Deployment.ObservedService, ike, udpESP]

lemma IPsec_same_level_excludes_different_classification (d : Deployment)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (carrier : d.carrierBindings = []) (traffic : Traffic)
    (ipsec : IPsecPacket traffic.packet) (same : d.SameLevelInner traffic) :
    ¬ DifferentClassificationVPNs d traffic := by
  obtain ⟨source, sourceMember, destination, destinationMember, _, _, level, _, pair⟩ := same
  obtain ⟨sourceMetadata, destinationMetadata, _, _⟩ :=
    IPsecPacket.InnerPair_is_IP d traffic source.id destination.id ipsec carrier pair
  rintro ⟨first, firstMember, second, secondMember, _, _, _, _, different, pair⟩
  obtain ⟨firstMetadata, secondMetadata, _, _⟩ :=
    IPsecPacket.InnerPair_is_IP d traffic first.id second.id ipsec carrier pair
  have firstID : first.id = source.id := Option.some.inj (firstMetadata.symm.trans sourceMetadata)
  have secondID : second.id = destination.id :=
    Option.some.inj (secondMetadata.symm.trans destinationMetadata)
  have firstEq := identifiers first firstMember source sourceMember firstID
  have secondEq := identifiers second secondMember destination destinationMember secondID
  subst first
  subst second
  exact different (congrArg SecurityLevel.classification level)

lemma Gray_firewall_header_is_eligible (d : Deployment) (interface : Interface)
    (roles : ∀ device ∈ d.devices, device.id = interface.device →
      device.kind = .grayFirewall ∧ device.layer = none)
    (traffic : Traffic) : d.HeaderEligible interface traffic := by
  intro device member owner
  have actual := roles device member owner
  simp [actual.1, actual.2]

def GrayIPsecRuleChecks (d : Deployment) (interface : Interface) (name : String)
    (direction : Direction) (pairs : List InnerIPsecPair) (rule : PacketPolicy.Rule) : Prop :=
  RuleMissesHook name direction rule ∨
    ∃ record ∈ pairs, record.Guards rule ∧
      (direction = .inbound → d.reachableSource interface.id record.endpoints.sourceAddress)

instance (d : Deployment) (interface : Interface) (name : String)
    (direction : Direction) (pairs : List InnerIPsecPair) (rule : PacketPolicy.Rule)
    [DecidablePred (d.reachableSource interface.id)] :
    Decidable (GrayIPsecRuleChecks d interface name direction pairs rule) := by
  unfold GrayIPsecRuleChecks
  infer_instance

lemma checked_Gray_IPsec_rule_is_safe (d : Deployment) (interface : Interface)
    (name : String) (direction : Direction) (hook : PacketProcessing.Hook)
    (pairs : List InnerIPsecPair) (bindings : ∀ record ∈ pairs, record.Bound d)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (roles : ∀ device ∈ d.devices, device.id = interface.device →
      device.kind = .grayFirewall ∧ device.layer = none)
    (carrier : d.carrierBindings = []) (coherent : d.AddressInventoryCoherent)
    (observations : GrayIPsecObservationChecks d)
    (rule : PacketPolicy.Rule) (checks : GrayIPsecRuleChecks d interface name direction pairs rule)
    (traffic : Traffic) (supported : d.Supported traffic)
    (context : PacketAtHook name direction hook traffic.packet)
    (matched : rule.toFilter.accepts traffic.packet = true) :
    GrayFirewallRestrictions d interface direction traffic ∧ GrayPolicyAllowance d interface traffic := by
  rcases checks with missed | ⟨record, member, guarded, reachable⟩
  · exact False.elim (hook_mismatch_cannot_match name direction hook traffic.packet context rule missed matched)
  obtain ⟨tunnel, sameLevel, appropriate⟩ := matched_IPsec_pair_is_permitted_tunnel d
    coherent record (bindings record member) rule guarded traffic supported matched
  have ipsec := IPsec_rule_has_IPsec_packet rule traffic.packet guarded.2.2.2 matched
  obtain ⟨notManagement, notHTTP⟩ :=
    Gray_IPsec_observation_is_not_management d traffic.packet observations ipsec
  have notManagementTraffic : traffic.trafficClass ≠ .management := by
    rw [supported.1]
    exact notManagement
  have notHTTPTraffic : traffic.service ≠ "http" := by
    rw [supported.1]
    exact notHTTP
  refine ⟨⟨Gray_firewall_header_is_eligible d interface roles traffic, ?_, ?_, ?_, ?_,
    IPsec_same_level_excludes_different_classification d identifiers carrier traffic ipsec sameLevel⟩,
    Or.inl ⟨Or.inl tunnel, sameLevel, appropriate⟩⟩
  · intro management
    exact False.elim (notManagementTraffic management)
  · intro _ _
    exact sameLevel
  · intro inbound
    have interval := PacketPolicy.matching_atom matched guarded.2.1
    have source : traffic.packet.source = record.endpoints.sourceAddress := by
      change record.endpoints.sourceAddress ≤ traffic.packet.source ∧
        traffic.packet.source ≤ record.endpoints.sourceAddress at interval
      omega
    rw [source]
    exact reachable inbound
  · intro http
    exact False.elim (notHTTPTraffic http)

end TDN.Requirements.Msc

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules

lemma admitted_Gray_firewall_IPsec_packet_is_safe (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (pairs : List InnerIPsecPair)
    (bindings : ∀ record ∈ pairs, record.Bound d)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (roles : ∀ device ∈ d.devices, device.id = interface.device →
      device.kind = .grayFirewall ∧ device.layer = none)
    (carrier : d.carrierBindings = []) (coherent : d.AddressInventoryCoherent)
    (observations : GrayIPsecObservationChecks d)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          GrayIPsecRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
            policy.direction pairs rule)
    (direction : Direction) (traffic : Traffic) (accepted : d.Accepts interface.id direction traffic) :
    GrayFirewallRestrictions d interface direction traffic ∧ GrayPolicyAllowance d interface traffic := by
  obtain ⟨hook, supported, context, admitted⟩ := accepted
  obtain ⟨actual, actualPresent, iface, ifaceMember, ifaceName, _, _, _, _, bound⟩ := context
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  by_cases link : hook = .link
  · subst hook
    exact False.elim (DeriveDataPlaneFromDeviceRecords.routed_iface_has_no_link_operation d inventory present
      interface.id routed direction traffic admitted)
  · simp only [link, ↓reduceIte] at admitted
    obtain ⟨policy, policyMember, policyName, policyDirection, _, _, allows⟩ := admitted
    have localChecks := checks iface ifaceMember ifaceName policy policyMember policyName
    obtain ⟨rule, ruleMember, matched, allow⟩ :=
      DeriveDataPlaneFromDeviceRecords.policy_acceptance_has_matching_rule policy traffic localChecks.1 allows
    apply checked_Gray_IPsec_rule_is_safe d interface _ direction hook pairs bindings identifiers
      roles carrier coherent observations rule _ traffic supported bound matched
    simpa only [policyDirection] using localChecks.2 rule ruleMember allow

theorem Gray_firewall_cross_classification_denied_from_local_rules (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (pairs : List InnerIPsecPair)
    (bindings : ∀ record ∈ pairs, record.Bound d)
    (identifiers : ∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.id = second.id → first = second)
    (roles : ∀ device ∈ d.devices, device.id = interface.device →
      device.kind = .grayFirewall ∧ device.layer = none)
    (carrier : d.carrierBindings = []) (coherent : d.AddressInventoryCoherent)
    (observations : GrayIPsecObservationChecks d)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          GrayIPsecRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
            policy.direction pairs rule)
    (direction : Direction) (traffic : Traffic)
    (different : DifferentClassificationVPNs d traffic) :
    ¬ d.Accepts interface.id direction traffic := by
  intro accepted
  have safe := admitted_Gray_firewall_IPsec_packet_is_safe d inventory present interface pairs bindings
    identifiers roles carrier coherent observations routed checks direction traffic accepted
  exact safe.1.2.2.2.2.2 different

end TDN.Requirements.Msc
