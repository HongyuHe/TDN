import TDN.Targets.CompleteHeaderFiltering
import TDN.Targets.EndpointRuleDerivation
import TDN.Semantics.HookPrograms
import TDN.Targets.HookContext
import TDN.Semantics.PolicyMasks

namespace TDN.Targets.Complete
open Compliance EndpointRuleDerivation

def IPsecPacket (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = "esp" ∨ PacketIKE packet ∨ PacketUDPESP packet

lemma request_framing_is_IPsec (packet : PacketPolicy.Packet)
    (framing : packet.IPsecUDPFramingWithOptions) : IPsecPacket packet := by
  obtain ⟨_, _, _, _, _, udp, bytes, payload, _, alternatives⟩ := framing
  rcases alternatives with ⟨port, header⟩ | ⟨port, length, nonzero | ⟨zero, header⟩⟩
  · exact Or.inr (Or.inl ⟨udp, Or.inl ⟨Or.inr port, by simpa [payload, PacketIKEHeader] using header⟩⟩)
  · exact Or.inr (Or.inr ⟨udp, Or.inr port, by simpa [payload] using length,
      by simpa [payload] using nonzero⟩)
  · exact Or.inr (Or.inl ⟨udp, Or.inr ⟨Or.inr port,
      by simpa [payload] using zero, by simpa [payload, PacketIKEHeader] using header⟩⟩)

lemma reply_framing_is_IPsec (packet : PacketPolicy.Packet)
    (framing : packet.IPsecUDPReplyFramingWithOptions) : IPsecPacket packet := by
  have request := request_framing_is_IPsec
    ({ packet with sourcePort := packet.destinationPort, destinationPort := packet.sourcePort } : PacketPolicy.Packet)
    framing
  simpa only [IPsecPacket, PacketIKE, PacketUDPESP, or_comm] using request

lemma IKE_service_is_control (packet : PacketPolicy.Packet) (ike : PacketIKE packet) :
    PacketService packet = "ike" ∧ PacketClass packet = .control := by
  simp [PacketService, PacketClass, ike]

lemma IPsec_service_is_not_management (packet : PacketPolicy.Packet)
    (protocol : IPsecPacket packet) : PacketClass packet ≠ .management := by
  rcases protocol with esp | ike | udpESP
  · simp [PacketClass, PacketService, PacketPortService, PacketIKE, PacketUDPESP,
      PacketMKA, PacketARP, PacketIsEthernet, esp]
  · rw [(IKE_service_is_control packet ike).2]
    decide
  · by_cases ike : PacketIKE packet
    · rw [(IKE_service_is_control packet ike).2]
      decide
    · have udp := udpESP.1
      simp [PacketClass, PacketService, ike, udpESP, PacketMKA, PacketARP,
        PacketIsEthernet, udp]

def IPsecAtom : PacketPolicy.Atom → Prop
  | .protocol name => name = "esp"
  | .ipsecUDPFramingWithOptions | .ipsecUDPReplyFramingWithOptions => True
  | _ => False

instance (atom : PacketPolicy.Atom) : Decidable (IPsecAtom atom) := by
  cases atom <;> unfold IPsecAtom <;> infer_instance

def IPsecRule (rule : PacketPolicy.Rule) : Prop :=
  ∃ atom ∈ rule.atoms, IPsecAtom atom

instance (rule : PacketPolicy.Rule) : Decidable (IPsecRule rule) := by
  unfold IPsecRule
  infer_instance

lemma IPsec_rule_has_IPsec_packet (rule : PacketPolicy.Rule) (packet : PacketPolicy.Packet)
    (guard : IPsecRule rule) (matched : rule.toFilter.accepts packet = true) :
    IPsecPacket packet := by
  obtain ⟨atom, member, kind⟩ := guard
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [IPsecAtom] at kind
  case protocol name =>
    exact Or.inl (holds.trans kind)
  case ipsecUDPFramingWithOptions => exact request_framing_is_IPsec packet holds
  case ipsecUDPReplyFramingWithOptions => exact reply_framing_is_IPsec packet holds

structure InnerIPsecPair where
  endpoints : EndpointPair
  tunnel : String

def InnerIPsecPair.Bound (record : InnerIPsecPair) (d : Deployment) : Prop :=
  record.endpoints.Bound d ∧ record.endpoints.view = .internet ∧
  SameLevelComponents d record.endpoints.source record.endpoints.destination ∧
  ∃ tunnel ∈ d.tunnels, tunnel.id = record.tunnel ∧ tunnel.layer = .inner ∧
    tunnel.mechanism = .ipsec ∧ tunnel.sender = record.endpoints.source ∧
    tunnel.receiver = record.endpoints.destination

def InnerIPsecPair.Guards (record : InnerIPsecPair) (rule : PacketPolicy.Rule) : Prop :=
  record.endpoints.view.RuleGuard rule ∧
  .sourceRange record.endpoints.sourceAddress record.endpoints.sourceAddress ∈ rule.atoms ∧
  .destinationRange record.endpoints.destinationAddress record.endpoints.destinationAddress ∈ rule.atoms ∧
  IPsecRule rule

instance (record : InnerIPsecPair) (rule : PacketPolicy.Rule) :
    Decidable (record.Guards rule) := by
  unfold InnerIPsecPair.Guards
  infer_instance

lemma matched_IPsec_pair_is_permitted_tunnel (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (record : InnerIPsecPair)
    (bound : record.Bound d) (rule : PacketPolicy.Rule) (guard : record.Guards rule)
    (traffic : Traffic) (supported : d.Supported traffic)
    (matched : rule.toFilter.accepts traffic.packet = true) :
    d.TunnelTraffic traffic ∧ d.SameLevelInner traffic ∧ d.AppropriateInnerTunnel traffic := by
  have protocol : IPsecProtocol traffic := IPsec_rule_has_IPsec_packet rule traffic.packet guard.2.2.2 matched
  have sameLevel := matched_same_level_pair_is_inner_traffic d coherent record.endpoints bound.1
    bound.2.2.1 rule guard.1 guard.2.1 guard.2.2.1 traffic supported matched
  obtain ⟨source, destination, sourceInterface, destinationInterface⟩ :=
    matched_bound_pair_recovers_metadata d coherent record.endpoints bound.1 rule guard.1
      guard.2.1 guard.2.2.1 traffic supported matched
  obtain ⟨tunnel, member, _, layer, mechanism, sender, receiver⟩ := bound.2.2.2
  refine ⟨Or.inl (Or.inl protocol), sameLevel, tunnel, member, layer, ?_, Or.inl ⟨mechanism, Or.inl protocol⟩⟩
  apply Or.inl
  rw [sender, receiver]
  exact ⟨source, destination, sourceInterface, destinationInterface⟩


def RuleMissesHook (name : String) (direction : Direction) (rule : PacketPolicy.Rule) : Prop :=
  ∃ atom ∈ rule.atoms,
    match atom, direction with
    | .ingress other, .inbound => name ≠ other
    | .egress other, .outbound => name ≠ other
    | _, _ => False

instance (name : String) (direction : Direction) (rule : PacketPolicy.Rule) :
    Decidable (RuleMissesHook name direction rule) := by
  unfold RuleMissesHook
  have (atom : PacketPolicy.Atom) : Decidable
      (match atom, direction with
       | .ingress other, .inbound => name ≠ other
       | .egress other, .outbound => name ≠ other
       | _, _ => False) := by cases atom <;> cases direction <;> infer_instance
  infer_instance

lemma hook_mismatch_cannot_match (name : String) (direction : Direction)
    (hook : PacketProcessing.Hook) (packet : PacketPolicy.Packet)
    (context : PacketAtHook name direction hook packet)
    (rule : PacketPolicy.Rule) (missed : RuleMissesHook name direction rule) :
    rule.toFilter.accepts packet ≠ true := by
  intro matchesRule
  obtain ⟨atom, member, mismatch⟩ := missed
  have holds := PacketPolicy.matching_atom matchesRule member
  cases direction <;> cases hook <;> cases atom <;>
    simp_all [PacketAtHook, HookDirection, PacketPolicy.Atom.holds]

def IPsecObservationChecks (d : Deployment) : Prop :=
  d.services = [] ∧ ∀ device ∈ d.devices, device.kind ≠ .workstation

lemma IPsec_observation_is_not_management (d : Deployment) (packet : PacketPolicy.Packet)
    (checks : IPsecObservationChecks d) (protocol : IPsecPacket packet) :
    (d.Observe packet).trafficClass ≠ .management ∧ (d.Observe packet).service ≠ "http" := by
  have workstation : d.devices.any (fun device => device.kind == .workstation &&
      (d.PacketOwner packet packet.source == some device.id ||
        d.PacketOwner packet packet.destination == some device.id)) = false := by
    apply List.any_eq_false.mpr
    intro device member
    simp [checks.2 device member]
  have observedClass : d.ObservedClass packet ≠ .management := by
    have packetClass := IPsec_service_is_not_management packet protocol
    unfold Deployment.ObservedClass
    split
    · decide
    · split
      · decide
      · split
        · decide
        · simp only [Deployment.RegisteredService, checks.1, List.find?_nil,
            Option.map_none, workstation, Bool.false_eq_true, ↓reduceIte]
          split
          · decide
          · exact packetClass
  constructor
  · change (if d.RevocationEndpoint packet then .protectedData else d.ObservedClass packet) ≠ .management
    split
    · decide
    · exact observedClass
  · change d.ObservedService packet ≠ "http"
    unfold Deployment.ObservedService
    split
    · decide
    · split
      · decide
      · simp only [Deployment.RegisteredService, checks.1, List.find?_nil, Option.map_none]
        rcases protocol with esp | ike | udpESP
        · simp [PacketService, PacketPortService, PacketIKE, PacketUDPESP, esp]
        · simp_all [PacketService]
        · simp_all [PacketService]

def OuterGrayHeaderRule (d : Deployment) (interface : Interface) (rule : PacketPolicy.Rule) : Prop :=
  RuleHeaderGuard rule ∧ ∀ device ∈ d.devices, device.id = interface.device →
    device.kind = .vpn → device.layer = some .outer → d.dropIPv4Options device.id = true →
      .ipv4HeaderWords 5 ∈ rule.atoms

lemma guarded_rule_has_eligible_header (d : Deployment) (interface : Interface)
    (rule : PacketPolicy.Rule) (guard : OuterGrayHeaderRule d interface rule)
    (traffic : Traffic) (supported : d.Supported traffic)
    (gray : interface.zone = .gray) (matched : rule.toFilter.accepts traffic.packet = true) :
    d.HeaderEligible interface traffic := by
  have header := guarded_rule_has_permitted_header rule traffic.packet guard.1 matched
  have version : traffic.ipVersion = PacketIPVersion traffic.packet := by rw [supported.1]; rfl
  have protocol : traffic.ipProtocol = PacketIPProtocol traffic.packet := by rw [supported.1]; rfl
  intro device member owner
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro _ v4
    rw [version] at v4
    rw [protocol]
    rcases header with h4 | h6
    · exact h4.2
    · simp [h6.1] at v4
  · intro _ v6
    rw [version] at v6
    rcases header with h4 | h6
    · simp [h4.1] at v6
    · exact h6.2
  · intro vpn outer _ selected
    exact PacketPolicy.matching_atom matched (guard.2 device member owner vpn outer selected)
  · intro _ black
    simp [gray] at black

def OuterGrayRuleChecks (d : Deployment) (interface : Interface) (name : String)
    (direction : Direction) (pairs : List InnerIPsecPair) (rule : PacketPolicy.Rule) : Prop :=
  RuleMissesHook name direction rule ∨
  ∃ record ∈ pairs, record.Guards rule ∧ OuterGrayHeaderRule d interface rule ∧
    (direction = .inbound → d.reachableSource interface.id record.endpoints.sourceAddress)

lemma checked_Outer_gray_rule_is_safe (d : Deployment) (interface : Interface)
    (name : String) (direction : Direction) (hook : PacketProcessing.Hook)
    (pairs : List InnerIPsecPair) (bindings : ∀ record ∈ pairs, record.Bound d)
    (coherent : d.AddressInventoryCoherent) (observations : IPsecObservationChecks d)
    (gray : interface.zone = .gray) (rule : PacketPolicy.Rule)
    (checks : OuterGrayRuleChecks d interface name direction pairs rule)
    (traffic : Traffic) (supported : d.Supported traffic)
    (context : PacketAtHook name direction hook traffic.packet)
    (matched : rule.toFilter.accepts traffic.packet = true) (cdpOnGray : Bool) :
    OuterGrayRestrictions d interface direction cdpOnGray traffic ∧
      OuterPolicyAllowance d interface.device cdpOnGray traffic := by
  rcases checks with missed | ⟨record, member, guarded, header, reachable⟩
  · exact False.elim (hook_mismatch_cannot_match name direction hook traffic.packet context rule missed matched)
  · obtain ⟨tunnel, sameLevel, appropriate⟩ := matched_IPsec_pair_is_permitted_tunnel d
      coherent record (bindings record member) rule guarded traffic supported matched
    have protocol := IPsec_rule_has_IPsec_packet rule traffic.packet guarded.2.2.2 matched
    obtain ⟨notManagement, notHTTP⟩ := IPsec_observation_is_not_management d traffic.packet observations protocol
    have notManagementTraffic : traffic.trafficClass ≠ .management := by rw [supported.1]; exact notManagement
    have notHTTPTraffic : traffic.service ≠ "http" := by rw [supported.1]; exact notHTTP
    refine ⟨⟨guarded_rule_has_eligible_header d interface rule header traffic supported gray matched,
      ?_, ?_, ?_, ?_⟩, Or.inl ⟨Or.inl tunnel, Or.inl ⟨sameLevel, appropriate⟩⟩⟩
    · intro management
      exact False.elim (notManagementTraffic management)
    · intro inbound
      have bounds := PacketPolicy.matching_atom matched guarded.2.1
      have source : traffic.packet.source = record.endpoints.sourceAddress := by
        change record.endpoints.sourceAddress ≤ traffic.packet.source ∧
          traffic.packet.source ≤ record.endpoints.sourceAddress at bounds
        omega
      rw [source]
      exact reachable inbound
    · intro _ _
      exact Or.inl sameLevel
    · intro http
      exact False.elim (notHTTPTraffic http)


lemma routed_iface_has_no_link_path (d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) (routed : PolicyDerivation.RoutedIface inventory iface) :
    ¬ d.LinkPath inventory iface := by
  rintro (⟨mac, member, physical⟩ | ⟨next, member, bridge⟩ | ⟨carrier, member, virtual⟩)
  · exact routed.1 mac member physical
  · rcases bridge with forward | reverse
    · exact (routed.2.1 next member).1 forward
    · exact (routed.2.1 next member).2 reverse
  · exact routed.2.2.1 carrier member virtual

lemma routed_eligible_packet_has_native_context (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface)
    (direction : Direction) (hook : PacketProcessing.Hook) (traffic : Traffic)
    (eligible : d.PacketEligibleAt interface direction hook traffic) :
    ∃ context, context.hook = hook ∧ d.SupportedAt interface direction context traffic ∧
      d.ContextSizeEligible context ∧ d.ContextIngressEligible context traffic := by
  rcases eligible with native | ⟨_, context, supported, _⟩
  · exact native
  · obtain ⟨actual, actualPresent, iface, _, _, _, link, name, _⟩ := supported
    have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
    subst actual
    exact False.elim (routed_iface_has_no_link_path d inventory context.iface
      (routed context.iface iface name) link)

structure HookMask where
  interface : String
  direction : Direction
  hook : PacketProcessing.Hook
  packet : PacketPolicy.Mask

lemma admitted_Outer_gray_packet_is_safe (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (pairs : List InnerIPsecPair)
    (bindings : ∀ record ∈ pairs, record.Bound d)
    (coherent : d.AddressInventoryCoherent) (observations : IPsecObservationChecks d)
    (gray : interface.zone = .gray)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          OuterGrayRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
            policy.direction pairs rule)
    (direction : Direction) (traffic : Traffic) (accepted : d.Accepts interface.id direction traffic)
    (cdpOnGray : Bool) :
    OuterGrayRestrictions d interface direction cdpOnGray traffic ∧
      OuterPolicyAllowance d interface.device cdpOnGray traffic := by
  obtain ⟨hook, supported, context, admitted⟩ := accepted
  obtain ⟨actual, actualPresent, iface, ifaceMember, ifaceName, _, _, _, _, bound⟩ := context
  have same : actual = inventory := Option.some.inj (actualPresent.symm.trans present)
  subst actual
  by_cases link : hook = .link
  · subst hook
    exact False.elim (PolicyDerivation.routed_iface_has_no_link_operation d inventory present
      interface.id routed direction traffic admitted)
  · simp only [link, ↓reduceIte] at admitted
    obtain ⟨policy, policyMember, policyName, policyDirection, _, _, allows⟩ := admitted
    have records := checks iface ifaceMember ifaceName policy policyMember policyName
    obtain ⟨rule, ruleMember, matched, allow⟩ :=
      PolicyDerivation.policy_acceptance_has_matching_rule policy traffic records.1 allows
    apply checked_Outer_gray_rule_is_safe d interface _ direction hook pairs bindings
      coherent observations gray rule _ traffic supported bound matched cdpOnGray
    simpa only [policyDirection] using records.2 rule ruleMember allow

theorem outer_gray_IPsec_policy_from_rule_and_mask_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (cdpOnGray : Bool) (pairs : List InnerIPsecPair) (masks : List HookMask)
    (addressChecked : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (processing : d.ProcessingCoherent) (udp : d.UDPBindingsCoherent)
    (indices : policyIndicesChecked d = true)
    (bindings : ∀ record ∈ pairs, record.Bound d)
    (observations : IPsecObservationChecks d)
    (routed : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        PolicyDerivation.RoutedIface inventory iface)
    (rules : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
        ∀ policy ∈ d.policies, policy.interface = interface.id →
          policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
            OuterGrayRuleChecks d interface (inventory.configuration.ip.interfaceName iface)
              policy.direction pairs rule)
    (maskPrograms : ∀ entry ∈ masks, ∀ policy ∈ d.policies,
      policy.interface = entry.interface → policy.direction = entry.direction → policy.hook = entry.hook →
      entry.packet.Covers policy.rules)
    (normalForms : ∀ interface ∈ d.interfaces, d.IsLayer interface.device .outer → interface.zone = .gray →
      ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
        OuterGrayRestrictions d interface direction cdpOnGray traffic →
        OuterPolicyAllowance d interface.device cdpOnGray traffic →
        ∃ entry ∈ masks, entry.interface = interface.id ∧ entry.direction = direction ∧
          entry.hook = hook ∧ entry.packet.Matches traffic.packet) :
    msc_outer_gray_interface_policy d cdpOnGray := by
  have address := address_inventory_from_checked_records d addressChecked workstations
  refine ⟨address, processing, udp, ?_⟩
  intro interface member _ outer gray
  have covered := policy_coverage_from_checked_indices d indices interface member
  refine ⟨covered, ?_, ?_⟩
  · intro direction traffic accepted
    exact admitted_Outer_gray_packet_is_safe d inventory present interface pairs bindings
      address observations gray (routed interface member outer gray)
      (rules interface member outer gray) direction traffic accepted cdpOnGray
  · intro direction hook traffic eligible restrictions allowance
    obtain ⟨context, contextHook, supported, _⟩ := routed_eligible_packet_has_native_context
      d inventory present interface (routed interface member outer gray) direction hook traffic eligible
    obtain ⟨actualInventory, actualPresent, actualInterface, applies, _, _, _, _, packetSupported⟩ := supported
    rw [contextHook] at applies
    obtain ⟨policy, policyMember, name, policyDirection, policyHook, unique⟩ := covered direction hook applies
    obtain ⟨entry, entryMember, entryName, entryDirection, entryHook, matchesPacket⟩ :=
      normalForms interface member outer gray direction hook traffic eligible restrictions allowance
    refine ⟨packetSupported, eligible_packet_has_hook_context d interface direction hook traffic eligible, ?_⟩
    have notLink : hook ≠ .link := applies.2.1
    simp only [notLink, ↓reduceIte]
    refine ⟨policy, policyMember, name, policyDirection, policyHook, unique, ?_⟩
    apply PacketPolicy.Mask.covered_packets_are_allowed entry.packet policy.rules
      (maskPrograms entry entryMember policy policyMember
        (name.trans entryName.symm) (policyDirection.trans entryDirection.symm)
        (policyHook.trans entryHook.symm)) policy.defaultVerdict traffic.packet matchesPacket

end TDN.Targets.Complete
