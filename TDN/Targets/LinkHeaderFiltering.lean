import TDN.Targets.CompleteHeaderFiltering

namespace TDN.Targets.Complete
open Compliance

set_option maxRecDepth 4000 in
lemma byte_field_two (bytes : List UInt8) (length : 4 ≤ bytes.length) :
    PacketPolicy.byteField bytes 2 2 =
      (bytes[2]?.getD 0).toNat * 256 + (bytes[3]?.getD 0).toNat := by
  cases bytes with
  | nil => simp at length
  | cons first bytes =>
    cases bytes with
    | nil => simp at length
    | cons second bytes =>
      cases bytes with
      | nil => simp at length
      | cons third bytes =>
        cases bytes with
        | nil => simp at length
        | cons fourth bytes => simp [PacketPolicy.byteField]

lemma mka_framing_is_control_protocol (packet : PacketPolicy.Packet) (actor : Nat)
    (framing : packet.MKAFraming actor) : PacketMKA packet := by
  obtain ⟨ethernet, etherType, source, bytes, payload, length, kind, declared, sci⟩ := framing
  refine ⟨⟨ethernet, by simp [etherType]⟩, etherType, ?_, ?_, ?_⟩
  · simpa [payload] using (show 4 ≤ bytes.length by omega)
  · simpa [payload] using kind
  · simpa [payload, byte_field_two bytes (by omega)] using declared

def MKAObservationRecords (d : Deployment) (actor : Nat) : Prop :=
  (∀ service ∈ d.services, service.protocol ≠ "ethernet") ∧
  ∀ device ∈ d.devices, device.kind = .revocationService →
    ∀ interface ∈ d.interfaces, interface.device = device.id →
      interface.linkAddress ≠ some (actor / 65536) ∧
      interface.linkAddress ≠ some 1652522221571

instance (d : Deployment) (actor : Nat) : Decidable (MKAObservationRecords d actor) := by
  unfold MKAObservationRecords
  infer_instance

lemma registered_service_none_on_ethernet (d : Deployment) (packet : PacketPolicy.Packet)
    (records : ∀ service ∈ d.services, service.protocol ≠ "ethernet")
    (ethernet : packet.protocol = "ethernet") : d.RegisteredService packet = none := by
  unfold Deployment.RegisteredService
  have absent : d.services.find? (fun service =>
      service.protocol == packet.protocol &&
        ((d.PacketOwner packet packet.destination == some service.device &&
          packet.destinationPort == service.port) ||
         (d.PacketOwner packet packet.source == some service.device &&
          packet.sourcePort == service.port))) = none := by
    apply List.find?_eq_none.mpr
    intro service member
    simp [ethernet, records service member]
  rw [absent]
  rfl

lemma mka_observation_class (d : Deployment) (packet : PacketPolicy.Packet) (actor : Nat)
    (records : MKAObservationRecords d actor)
    (framing : packet.MKAFraming actor)
    (destination : packet.destination = 1652522221571) :
    (d.Observe packet).trafficClass = .control := by
  have ethernet := framing.1
  have etherType := framing.2.1
  have source := framing.2.2.1
  have noService := registered_service_none_on_ethernet d packet records.1 ethernet
  have notRevocation : d.RevocationEndpoint packet = false := by
    unfold Deployment.RevocationEndpoint
    apply Bool.eq_false_iff.mpr
    intro hit
    obtain ⟨device, member, matchedDevice⟩ := List.any_eq_true.mp hit
    simp only [Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true] at matchedDevice
    obtain ⟨⟨address, kind⟩, _⟩ := matchedDevice
    rcases address with address | address
    · obtain ⟨interface, present, owner, assigned⟩ :=
        packet_owner_has_interface d packet packet.destination device.id address
      have forbidden := (records.2 device member kind interface present owner).2
      apply forbidden
      simpa [Interface.PacketAddress, ethernet, etherType, destination] using assigned
    · obtain ⟨interface, present, owner, assigned⟩ :=
        packet_owner_has_interface d packet packet.source device.id address
      have forbidden := (records.2 device member kind interface present owner).1
      apply forbidden
      simpa [Interface.PacketAddress, ethernet, etherType, source] using assigned
  have notIKE : ¬ PacketIKE packet := by simp [PacketIKE, ethernet]
  have notUDPESP : ¬ PacketUDPESP packet := by simp [PacketUDPESP, ethernet]
  have control : PacketClass packet = .control := by
    have mka := mka_framing_is_control_protocol packet actor framing
    simp [PacketClass, PacketService, PacketPortService, notIKE, notUDPESP, ethernet, mka]
  simp only [Deployment.Observe, notRevocation, Bool.false_eq_true, ↓reduceIte]
  simp only [Deployment.ObservedClass, notIKE, notUDPESP, ↓reduceIte]
  split
  · rfl
  · simp [noService]

def UnicastLinkDestinationAtom : PacketPolicy.Atom → Prop
  | .destinationRange low high => low = high ∧ high / 2^40 % 2 = 0
  | _ => False

instance (atom : PacketPolicy.Atom) : Decidable (UnicastLinkDestinationAtom atom) := by
  cases atom <;> unfold UnicastLinkDestinationAtom <;> infer_instance

def LinkRuleHeaderGuard (d : Deployment) (inventory : PacketProcessing.Inventory)
    (interface : Interface) (iface : Nat) (rule : PacketPolicy.Rule) : Prop :=
  (∃ atom ∈ rule.atoms, UnicastLinkDestinationAtom atom) ∨
  ∃ endpoint ∈ inventory.mkaPeers,
    endpoint.destinationIface = iface ∧
    .mkaFraming endpoint.actorSCI ∈ rule.atoms ∧
    .destinationRange 1652522221571 1652522221571 ∈ rule.atoms ∧
    .payloadByteEquals 0 3 ∈ rule.atoms ∧
    MKAObservationRecords d endpoint.actorSCI ∧
    ∃ tunnel ∈ d.tunnels, tunnel.id = endpoint.tunnel ∧ tunnel.layer = .outer ∧
      tunnel.mechanism = .macsec ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.sourceIface) = tunnel.sender ∧
      inventory.componentName (inventory.configuration.ip.owner endpoint.destinationIface) = tunnel.receiver ∧
      tunnel.receiver = interface.device ∧ d.intendedPeer tunnel.sender tunnel.receiver

instance (d : Deployment) [DecidableRel d.intendedPeer] (inventory : PacketProcessing.Inventory)
    (interface : Interface) (iface : Nat) (rule : PacketPolicy.Rule) :
    Decidable (LinkRuleHeaderGuard d inventory interface iface rule) := by
  unfold LinkRuleHeaderGuard
  infer_instance

lemma link_rule_multicast_restriction (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (iface : Nat) (name : inventory.ifaceName iface = interface.id)
    (rule : PacketPolicy.Rule) (traffic : Traffic) (supported : d.Supported traffic)
    (ethernet : traffic.packet.protocol = "ethernet")
    (guard : LinkRuleHeaderGuard d inventory interface iface rule)
    (approvedMKA : ∀ endpoint ∈ inventory.mkaPeers,
      inventory.ifaceName endpoint.destinationIface = interface.id →
      ∀ packet, packet.MKAFraming endpoint.actorSCI →
      packet.destination = 1652522221571 →
        d.policyApproved interface.device (d.Observe packet))
    (matched : rule.toFilter.accepts traffic.packet = true) :
    traffic.multicast = false ∨ NecessaryApprovedL2Control d interface traffic := by
  rcases guard with ⟨atom, member, unicast⟩ |
      ⟨endpoint, member, target, mkaAtom, destinationAtom, versionAtom, records,
        tunnel, tunnelMember, tunnelId, outer, macsec, sender, receiver, owner, peer⟩
  · have bounds := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [UnicastLinkDestinationAtom] at unicast
    case destinationRange low high =>
      change low ≤ traffic.packet.destination ∧ traffic.packet.destination ≤ high at bounds
      have address : traffic.packet.destination = high := by omega
      left
      have same := congrArg Traffic.multicast supported.1
      simpa [Deployment.Observe, PacketMulticast, PacketIPVersion, ethernet, address, unicast.2] using same
  · have framing : traffic.packet.MKAFraming endpoint.actorSCI :=
      PacketPolicy.matching_atom matched mkaAtom
    have bounds := PacketPolicy.matching_atom matched destinationAtom
    change 1652522221571 ≤ traffic.packet.destination ∧ traffic.packet.destination ≤ 1652522221571 at bounds
    have address : traffic.packet.destination = 1652522221571 := by omega
    have version : (traffic.packet.payloadBytes.bind (fun bytes => bytes[0]?)) = some 3 :=
      PacketPolicy.matching_atom matched versionAtom
    right
    refine ⟨?_, ?_, address, inventory, present, endpoint, member, (congrArg inventory.ifaceName target).trans name,
      framing, version, tunnel, tunnelMember, tunnelId, outer, macsec, sender, receiver, owner, peer⟩
    · exact (congrArg Traffic.trafficClass supported.1).trans
        (mka_observation_class d traffic.packet endpoint.actorSCI records framing address)
    · exact (congrArg (d.policyApproved interface.device) supported.1).mpr
        (approvedMKA endpoint member ((congrArg inventory.ifaceName target).trans name)
          traffic.packet framing address)

end TDN.Targets.Complete

namespace TDN.Targets.Complete
open Compliance PolicyDerivation

lemma header_atoms_force_admission_properties (d : Deployment)
    (objective : String → Bool)
    (objectiveDefinition : ∀ component, objective component = d.dropIPv4Options component)
    (device : Device) (interface : Interface) (policy : InterfacePolicy) (traffic : Traffic)
    (supported : d.Supported traffic)
    (checked : HeaderInterfacePolicyCheck d device interface policy)
    (admitted : policy.Accepts traffic) :
    (device.layer = some .outer → interface.zone = .black →
      traffic.multicast = false ∨ NecessaryApprovedL2Control d interface traffic) ∧
    (device.kind = .vpn → traffic.ipVersion = some 4 → traffic.ipProtocol ∈ [6, 17, 50, 1]) ∧
    (device.kind = .vpn → traffic.ipVersion = some 6 →
      traffic.packet.ipv6NextHeader ∈ [50, 6, 17, 58]) ∧
    (device.kind = .vpn → device.layer = some .outer → traffic.ipVersion = some 4 →
      objective device.id = true → traffic.packet.ipv4HeaderWords = 5) := by
  obtain ⟨rule, member, matched, allow⟩ :=
    policy_acceptance_has_matching_rule policy traffic checked.1 admitted
  obtain ⟨headerGuard, unicastGuard, optionGuard⟩ := checked.2 rule member allow
  have header := guarded_rule_has_permitted_header rule traffic.packet headerGuard matched
  have version : traffic.ipVersion = PacketIPVersion traffic.packet := by
    exact congrArg Traffic.ipVersion supported.1
  have protocol : traffic.ipProtocol = PacketIPProtocol traffic.packet := by
    exact congrArg Traffic.ipProtocol supported.1
  have multicast : traffic.multicast = PacketMulticast traffic.packet := by
    exact congrArg Traffic.multicast supported.1
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro outer black
    apply Or.inl
    rw [multicast]
    exact unicast_rule_is_not_multicast rule traffic.packet (unicastGuard outer black)
      (header.elim (fun v => Or.inl v.1) (fun v => Or.inr v.1)) matched
  · intro _ ipv4
    rw [version] at ipv4
    rw [protocol]
    rcases header with v4 | v6
    · exact v4.2
    · simp [v6.1] at ipv4
  · intro _ ipv6
    rw [version] at ipv6
    rcases header with v4 | v6
    · simp [v4.1] at ipv6
    · exact v6.2
  · intro vpn outer _ selected
    exact PacketPolicy.matching_atom matched
      (optionGuard vpn outer ((objectiveDefinition device.id).symm.trans selected))

def LinkHeaderPolicyChecks (d : Deployment) (inventory : PacketProcessing.Inventory) : Prop :=
  ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices,
    interface.device = device.id → HeaderFilterApplies device interface →
    ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      match LinkAdmission.lookup inventory.configuration.linkPolicies iface with
      | none => True
      | some policy => policy.inbound.fallback = .deny ∧
          ∀ rule ∈ policy.inbound.rules, rule.verdict = .allow →
            LinkRuleHeaderGuard d inventory interface iface rule

instance (d : Deployment) [DecidableRel d.intendedPeer]
    (inventory : PacketProcessing.Inventory) : Decidable (LinkHeaderPolicyChecks d inventory) := by
  unfold LinkHeaderPolicyChecks
  have (interface : Interface) (iface : Nat) :
      Decidable (match LinkAdmission.lookup inventory.configuration.linkPolicies iface with
        | none => True
        | some policy => policy.inbound.fallback = .deny ∧
            ∀ rule ∈ policy.inbound.rules, rule.verdict = .allow →
              LinkRuleHeaderGuard d inventory interface iface rule) := by
    cases LinkAdmission.lookup inventory.configuration.linkPolicies iface <;> infer_instance
  infer_instance

def LinkPolicyRecordChecks (d : Deployment) (inventory : PacketProcessing.Inventory) : Prop :=
  (∀ iface ∈ inventory.ifaces, d.LinkPath inventory iface →
    (LinkAdmission.lookup inventory.configuration.linkPolicies iface).isSome = true) ∧
  (∀ entry ∈ inventory.configuration.linkPolicies,
    entry.1 ∈ inventory.ifaces ∧ d.LinkPath inventory entry.1) ∧
  (∀ first ∈ inventory.configuration.linkPolicies,
    ∀ second ∈ inventory.configuration.linkPolicies, first.1 = second.1 → first = second)

instance (d : Deployment) (inventory : PacketProcessing.Inventory)
    [DecidableRel inventory.configuration.bridge] :
    Decidable (LinkPolicyRecordChecks d inventory) := by
  unfold LinkPolicyRecordChecks Deployment.LinkPath
  infer_instance

lemma link_policy_completeness_from_records (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (checks : LinkPolicyRecordChecks d inventory) : d.LinkPoliciesComplete := by
  refine ⟨inventory, present, ?_, checks.2.1, checks.2.2⟩
  intro iface member path
  exact Option.isSome_iff_exists.mp (checks.1 iface member path)

theorem ip_and_link_header_filtering_from_inventory_and_rule_atoms (d : Deployment)
    (inventory : PacketProcessing.Inventory) (objective : String → Bool)
    (objectiveDefinition : ∀ component, objective component = d.dropIPv4Options component)
    (present : d.processing = some inventory)
    (addressChecked : addressRecordsChecked d = true)
    (workstationDefinition : d.grayWorkstation = grayWorkstationRole d)
    (processingChecked : processingInventoryChecked d inventory = true)
    (lengthDefinition : (fun packet payload =>
      inventory.configuration.networkBytes (.datagram packet) payload) =
        (fun packet _ => packet.networkBytes))
    (localAddressDefinition : inventory.configuration.ip.localAddress = nativeLocalAddress d inventory)
    (indicesChecked : policyIndicesChecked d = true)
    (ipRulesChecked : headerPoliciesChecked d = true)
    (linkRecords : LinkPolicyRecordChecks d inventory)
    (linkRules : LinkHeaderPolicyChecks d inventory)
    (approvedMKA : ∀ interface ∈ d.interfaces, ∀ endpoint ∈ inventory.mkaPeers,
      inventory.ifaceName endpoint.destinationIface = interface.id →
      ∀ packet, packet.MKAFraming endpoint.actorSCI →
      packet.destination = 1652522221571 →
        d.policyApproved interface.device (d.Observe packet)) :
    msc_ip_header_and_multicast_filtering d objective := by
  have address := address_inventory_from_checked_records d addressChecked workstationDefinition
  have processing := processing_coherence_from_record_checks d inventory present processingChecked
    lengthDefinition localAddressDefinition
  have checks : HeaderPolicyChecks d := of_decide_eq_true ipRulesChecked
  refine ⟨objectiveDefinition, address, processing,
    link_policy_completeness_from_records d inventory present linkRecords, ?_⟩
  intro interface interfaceMember _ device deviceMember _ owner applies
  refine ⟨policy_coverage_from_checked_indices d indicesChecked interface interfaceMember, ?_⟩
  intro traffic admitted
  have supported := accepted_traffic_supported d interface.id .inbound traffic admitted
  obtain ⟨hook, _, _, admission⟩ := admitted
  by_cases link : hook = .link
  · subst hook
    have operation : d.LinkOperation interface.id .inbound traffic := admission
    have ethernet : traffic.packet.protocol = "ethernet" := by
      by_contra notEthernet
      exact non_ethernet_has_no_link_operation d interface.id .inbound traffic notEthernet operation
    obtain ⟨_, actual, same, iface, ifaceMember, name, policy, selected, accepted⟩ := operation
    have sameInventory : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    have policyChecks := linkRules interface interfaceMember device deviceMember owner applies
      iface ifaceMember name
    rw [selected] at policyChecks
    have acceptedRule : ∃ rule ∈ policy.inbound.rules,
        rule.toFilter.accepts traffic.packet = true ∧ rule.verdict = .allow := by
      change Filter.evaluate (policy.inbound.rules.map PacketPolicy.Rule.toFilter)
        policy.inbound.fallback traffic.packet = .allow at accepted
      rw [policyChecks.1] at accepted
      obtain ⟨rule, member, matched, allow⟩ := Filter.allowed_has_matching_allow
        (policy.inbound.rules.map PacketPolicy.Rule.toFilter) traffic.packet accepted
      obtain ⟨original, originalMember, sameRule⟩ := List.mem_map.mp member
      subst rule
      exact ⟨original, originalMember, matched, allow⟩
    obtain ⟨rule, ruleMember, matched, allow⟩ := acceptedRule
    have version : traffic.ipVersion = none := by
      have sameVersion := congrArg Traffic.ipVersion supported.1
      simpa [Deployment.Observe, PacketIPVersion, ethernet] using sameVersion
    refine ⟨fun _ _ => link_rule_multicast_restriction d inventory present interface iface name
      rule traffic supported ethernet (policyChecks.2 rule ruleMember allow)
        (approvedMKA interface interfaceMember) matched, ?_, ?_, ?_⟩
    · intro _ impossible
      simp [version] at impossible
    · intro _ impossible
      simp [version] at impossible
    · intro _ _ impossible
      simp [version] at impossible
  · simp only [link, ↓reduceIte] at admission
    obtain ⟨policy, member, name, direction, _, _, accepted⟩ := admission
    exact header_atoms_force_admission_properties d objective objectiveDefinition device interface policy
      traffic supported (checks interface interfaceMember device deviceMember owner applies
        policy member name direction) accepted

end TDN.Targets.Complete

namespace TDN.Compliance

instance (association : LayeredFrame.MACsecAssociation) (bytes : List UInt8) :
    Decidable (MACsecPayload association bytes) := by
  unfold MACsecPayload
  infer_instance

end TDN.Compliance
