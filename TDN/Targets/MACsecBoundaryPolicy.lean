import TDN.Targets.NativeBoundarySpecification
import TDN.Targets.PhysicalBoundaryCoverage
import TDN.Targets.EndpointRuleDerivation

namespace TDN.Targets.Complete
open Compliance

structure MACsecBoundaryPeer where
  source : String
  destination : String
  destinationAddress : Nat
  deriving DecidableEq

def MACsecBoundaryPeer.Bound (peer : MACsecBoundaryPeer) (d : Deployment) : Prop :=
  (∃ interface ∈ d.interfaces, interface.device = peer.destination ∧
    interface.linkAddress = some peer.destinationAddress) ∧
  d.intendedPeer peer.source peer.destination

instance instDecidableMACsecBoundaryPeerBound (peer : MACsecBoundaryPeer) (d : Deployment) [DecidableRel d.intendedPeer] :
    Decidable (peer.Bound d) := by
  unfold MACsecBoundaryPeer.Bound
  infer_instance

def MACsecBoundaryDataRule (device : String) (direction : Direction)
    (peers : List MACsecBoundaryPeer) (rule : PacketPolicy.Rule) : Prop :=
  .protocol "ethernet" ∈ rule.atoms ∧ .etherTypes [35045] ∈ rule.atoms ∧
    (direction = .outbound → ∃ peer ∈ peers, peer.source = device ∧
      .destinationRange peer.destinationAddress peer.destinationAddress ∈ rule.atoms)

instance (device : String) (direction : Direction) (peers : List MACsecBoundaryPeer)
    (rule : PacketPolicy.Rule) : Decidable (MACsecBoundaryDataRule device direction peers rule) := by
  unfold MACsecBoundaryDataRule
  infer_instance

def MACsecBoundaryProgramChecks (device : String) (peers : List MACsecBoundaryPeer)
    (policy : LinkAdmission.IfacePolicy) : Prop :=
  ∀ direction ∈ [Direction.inbound, .outbound],
    (if direction = .outbound then policy.outbound else policy.inbound).fallback = .deny ∧
    ∀ rule ∈ (if direction = .outbound then policy.outbound else policy.inbound).rules,
      rule.verdict = .allow → MACsecBoundaryDataRule device direction peers rule

instance (device : String) (peers : List MACsecBoundaryPeer) (policy : LinkAdmission.IfacePolicy) :
    Decidable (MACsecBoundaryProgramChecks device peers policy) := by
  unfold MACsecBoundaryProgramChecks
  infer_instance

def MACsecBoundaryDataChecks (d : Deployment) (inventory : PacketProcessing.Inventory)
    (peers : List MACsecBoundaryPeer) : Prop :=
  ∀ interface ∈ d.interfaces, interface.zone = .black →
    ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      match LinkAdmission.lookup inventory.configuration.linkPolicies iface with
      | none => True
      | some policy => MACsecBoundaryProgramChecks interface.device peers policy

instance (d : Deployment) (inventory : PacketProcessing.Inventory) (peers : List MACsecBoundaryPeer) :
    Decidable (MACsecBoundaryDataChecks d inventory peers) := by
  unfold MACsecBoundaryDataChecks
  have (interface : Interface) (iface : Nat) : Decidable
      (match LinkAdmission.lookup inventory.configuration.linkPolicies iface with
       | none => True
       | some policy => MACsecBoundaryProgramChecks interface.device peers policy) := by
    cases LinkAdmission.lookup inventory.configuration.linkPolicies iface <;> infer_instance
  infer_instance

lemma interface_without_IP_has_no_native_boundary_admission (d : Deployment)
    (noAddresses : ∀ interface ∈ d.interfaces, interface.address = none)
    (interface : String) (direction : Direction) (traffic : Traffic) :
    ¬ d.NativeBoundaryAccepts interface direction traffic := by
  rintro ⟨inventory, present, filtering, member, context, supported, _⟩
  obtain ⟨actual, _, _, applies, _⟩ := supported
  have absent := noAddresses filtering member
  simp [Interface.HookApplies, absent] at applies

lemma MACsec_boundary_link_admission_has_matching_rule (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (noAddresses : ∀ interface ∈ d.interfaces, interface.address = none)
    (peers : List MACsecBoundaryPeer) (checks : MACsecBoundaryDataChecks d inventory peers)
    (interface : Interface) (member : interface ∈ d.interfaces) (black : interface.zone = .black)
    (direction : Direction) (traffic : Traffic)
    (admitted : d.BoundaryAccepts interface.id direction traffic) :
    d.Supported traffic ∧ ∃ rule, rule.toFilter.accepts traffic.packet = true ∧
      MACsecBoundaryDataRule interface.device direction peers rule := by
  have actual : d.Supported traffic ∧ ∃ iface ∈ inventory.ifaces,
      inventory.ifaceName iface = interface.id ∧
      LinkAdmission.Admitted inventory.configuration.linkPolicies iface
        (direction = .outbound) traffic.packet := by
    rcases admitted with native | link | physical
    · exact False.elim
        (interface_without_IP_has_no_native_boundary_admission d noAddresses interface.id direction traffic native)
    · obtain ⟨supported, _, _, other, same, iface, ifaceMember, name, allowed⟩ := link
      have identity : other = inventory := Option.some.inj (same.symm.trans present)
      subst other
      exact ⟨supported, iface, ifaceMember, name, allowed⟩
    · obtain ⟨other, same, iface, ifaceMember, _, name, _, _, _, _, _, _, _, _, supported, allowed⟩ := physical
      have identity : other = inventory := Option.some.inj (same.symm.trans present)
      subst other
      exact ⟨supported, iface, ifaceMember, name, allowed⟩
  obtain ⟨supported, iface, ifaceMember, name, policy, selected, allowed⟩ := actual
  have programChecks := checks interface member black iface ifaceMember name
  rw [selected] at programChecks
  have directionMember : direction ∈ [Direction.inbound, .outbound] := by cases direction <;> simp
  obtain ⟨fallback, rules⟩ := programChecks direction directionMember
  have allowedProgram :
      (if direction = .outbound then policy.outbound else policy.inbound).Accepts traffic.packet := by
    cases direction <;> simpa using allowed
  have accepted : Filter.evaluate
      ((if direction = .outbound then policy.outbound else policy.inbound).rules.map PacketPolicy.Rule.toFilter)
      .deny traffic.packet = .allow := by
    simpa only [LinkAdmission.Program.Accepts, fallback] using allowedProgram
  obtain ⟨filter, filterMember, matched, verdict⟩ := Filter.allowed_has_matching_allow _ traffic.packet accepted
  obtain ⟨rule, ruleMember, same⟩ := List.mem_map.mp filterMember
  subst filter
  exact ⟨supported, rule, matched, rules rule ruleMember verdict⟩

lemma checked_MACsec_boundary_data_rule_has_protocol_and_peer (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (peers : List MACsecBoundaryPeer)
    (bound : ∀ peer ∈ peers, peer.Bound d) (device : String) (direction : Direction)
    (rule : PacketPolicy.Rule) (traffic : Traffic) (supported : d.Supported traffic)
    (checks : MACsecBoundaryDataRule device direction peers rule)
    (matched : rule.toFilter.accepts traffic.packet = true) :
    PacketMACsec traffic.packet ∧
      (direction = .outbound → d.IntendedPacketPeer device traffic) := by
  have ethernet : traffic.packet.protocol = "ethernet" := PacketPolicy.matching_atom matched checks.1
  obtain ⟨type, selected, member⟩ := PacketPolicy.matching_atom matched checks.2.1
  have typeEq : type = 35045 := by simpa using member
  subst type
  refine ⟨⟨⟨ethernet, by simp [selected]⟩, selected⟩, ?_⟩
  intro outbound
  obtain ⟨peer, peerMember, source, destinationAtom⟩ := checks.2.2 outbound
  obtain ⟨⟨interface, interfaceMember, owner, address⟩, intended⟩ := bound peer peerMember
  have bounds := PacketPolicy.matching_atom matched destinationAtom
  have destination : traffic.packet.destination = peer.destinationAddress := by
    change peer.destinationAddress ≤ traffic.packet.destination ∧
      traffic.packet.destination ≤ peer.destinationAddress at bounds
    omega
  have packetAddress : interface.PacketAddress traffic.packet = some traffic.packet.destination := by
    simp [Interface.PacketAddress, ethernet, selected, address, destination]
  have metadata := packet_owner_of_interface d traffic.packet interface interfaceMember _ packetAddress
    (EndpointRuleDerivation.address_inventory_owner_uniqueness d coherent traffic.packet _)
  exact Or.inl ⟨peer.destination,
    (congrArg Traffic.destinationDevice supported.1).trans (metadata.trans (congrArg some owner)),
    source ▸ intended⟩

end TDN.Targets.Complete

namespace TDN.Targets.Complete
open Compliance

theorem MACsec_boundary_interface_filtering_from_link_rule_checks (d : Deployment)
    (focus : d.focus = none)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (address : d.AddressInventoryCoherent) (processing : d.ProcessingCoherent)
    (udp : d.UDPBindingsCoherent) (coverage : d.LinkPoliciesComplete)
    (noAddresses : ∀ interface ∈ d.interfaces, interface.address = none)
    (roles : ∀ device ∈ d.devices, device.layer = some .outer ∧ device.kind = .macsec)
    (peers : List MACsecBoundaryPeer) (bound : ∀ peer ∈ peers, peer.Bound d)
    (checks : MACsecBoundaryDataChecks d inventory peers)
    (required : Bool) (internal : String → Bool) (localOuter : String → String) :
    msc_boundary_interface_filtering d required internal localOuter := by
  have cleared : { d with focus := none } = d := by
    cases d
    simp_all
  unfold msc_boundary_interface_filtering
  rw [cleared]
  refine ⟨address, processing, udp, ?_⟩
  intro interface member _ device deviceMember _ owner assessed
  obtain ⟨outer, macsec⟩ := roles device deviceMember
  have black : interface.zone = .black := by
    rcases assessed with outerBlack | innerGray | innerRed | firewall
    · exact outerBlack.2
    · simp [outer] at innerGray
    · simp [outer] at innerRed
    · simp [macsec] at firewall
  have programs : d.BoundaryPolicyCoverage interface := by
    constructor
    · intro direction hook applies
      simp [Interface.HookApplies, noAddresses interface member] at applies
    · intro actual same iface ifaceMember name path
      obtain ⟨registered, registeredPresent, complete, _⟩ := coverage
      have identity : registered = actual := Option.some.inj (registeredPresent.symm.trans same)
      subst registered
      exact complete iface ifaceMember path
  refine ⟨programs, ?_⟩
  intro direction traffic admitted
  have crypto : CryptographicBoundary device interface := Or.inl ⟨outer, black⟩
  have physical : d.BoundaryAccepts interface.id direction traffic := by
    simpa only [Deployment.BoundaryAdmission, crypto, ↓reduceIte] using admitted
  obtain ⟨supported, rule, matched, ruleChecks⟩ :=
    MACsec_boundary_link_admission_has_matching_rule d inventory present noAddresses peers checks
      interface member black direction traffic physical
  obtain ⟨protocol, peer⟩ := checked_MACsec_boundary_data_rule_has_protocol_and_peer d address
    peers bound interface.device direction rule traffic supported ruleChecks matched
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro _ _
    refine ⟨?_, fun _ => Or.inl protocol, ?_⟩
    · intro vpn
      simp [macsec] at vpn
    · intro outbound
      exact Or.inl (owner ▸ peer outbound)
  · intro inner
    simp [outer] at inner
  · intro inner
    simp [outer] at inner
  · intro firewall
    simp [macsec] at firewall

end TDN.Targets.Complete

namespace TDN.Targets.Complete
open Compliance

lemma admitted_plaintext_at_MACsec_boundary_violates_requirement (d : Deployment)
    (focus : d.focus = none) (interface : Interface) (member : interface ∈ d.interfaces)
    (device : Device) (deviceMember : device ∈ d.devices)
    (owner : interface.device = device.id) (outer : device.layer = some .outer)
    (black : interface.zone = .black) (macsec : device.kind = .macsec)
    (direction : Direction) (traffic : Traffic)
    (admitted : d.BoundaryAdmission device interface direction traffic)
    (plaintext : ¬ PacketMACsec traffic.packet) (unapproved : ¬ ApprovedControl d device.id traffic)
    (required : Bool) (internal : String → Bool) (localOuter : String → String) :
    ¬ msc_boundary_interface_filtering d required internal localOuter := by
  intro specification
  have cleared : { d with focus := none } = d := by
    cases d
    simp_all
  unfold msc_boundary_interface_filtering at specification
  rw [cleared] at specification
  obtain ⟨_, _, _, all⟩ := specification
  have checked := all interface member (by simp [Deployment.Relevant, focus]) device deviceMember
    (by simp [Deployment.Relevant, focus]) owner (Or.inl ⟨outer, black⟩)
  have permitted := ((checked.2 direction traffic admitted).1 outer black).2.1 macsec
  exact permitted.elim plaintext unapproved

end TDN.Targets.Complete
