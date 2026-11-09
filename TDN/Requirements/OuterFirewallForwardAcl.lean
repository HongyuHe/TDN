import TDN.Requirements.DerivePerimeterContext

namespace TDN.Requirements.Msc
open Compliance

def FirewallAddressGuard (d : Deployment) (outer : String) (internal : Bool)
    (rule : PacketPolicy.Rule) : Prop :=
  ∃ interface ∈ d.interfaces, interface.device = outer ∧ interface.zone = .black ∧
    ∃ address, interface.address = some address ∧
      (if internal then .sourceRange address address ∈ rule.atoms
        else .destinationRange address address ∈ rule.atoms)

instance (d : Deployment) (outer : String) (internal : Bool) (rule : PacketPolicy.Rule) :
    Decidable (FirewallAddressGuard d outer internal rule) := by
  unfold FirewallAddressGuard
  letI : DecidablePred (fun interface : Interface =>
      match interface.address with
      | none => False
      | some address => if internal then .sourceRange address address ∈ rule.atoms
        else .destinationRange address address ∈ rule.atoms) := fun interface => by
    cases assigned : interface.address <;> simp only [assigned] <;> infer_instance
  exact decidable_of_iff
    (∃ interface ∈ d.interfaces, interface.device = outer ∧ interface.zone = .black ∧
      match interface.address with
      | none => False
      | some address => if internal then .sourceRange address address ∈ rule.atoms
        else .destinationRange address address ∈ rule.atoms) (by
      constructor
      · rintro ⟨interface, member, owner, zone, matched⟩
        cases address : interface.address with
        | none => simp [address] at matched
        | some value => exact ⟨interface, member, owner, zone, value, address, by simpa [address] using matched⟩
      · rintro ⟨interface, member, owner, zone, value, address, atom⟩
        exact ⟨interface, member, owner, zone, by simpa [address] using atom⟩)

def FirewallBoundaryRule (d : Deployment) (outer : String) (internal : Bool)
    (name : String) (direction : Direction) (rule : PacketPolicy.Rule) : Prop :=
  RuleMissesHook name direction rule ∨
    IPsecRule rule ∧ (direction = .inbound → FirewallAddressGuard d outer internal rule)

instance (d : Deployment) (outer : String) (internal : Bool)
    (name : String) (direction : Direction) (rule : PacketPolicy.Rule) :
    Decidable (FirewallBoundaryRule d outer internal name direction rule) := by
  unfold FirewallBoundaryRule
  infer_instance

lemma matching_firewall_address_guard (d : Deployment) (firewall outer : String) (internal : Bool)
    (firewallRole : d.IsDevice firewall .outerFirewall) (outerRole : d.IsLayer outer .outer)
    (rule : PacketPolicy.Rule) (guard : FirewallAddressGuard d outer internal rule)
    (packet : PacketPolicy.Packet) (matched : rule.toFilter.accepts packet = true) :
    if internal then LocalOuterAddress d firewall outer packet.source
      else LocalOuterAddress d firewall outer packet.destination := by
  obtain ⟨interface, member, owner, black, address, assigned, atom⟩ := guard
  cases internal
  · have interval := PacketPolicy.matching_atom matched atom
    change address ≤ packet.destination ∧ packet.destination ≤ address at interval
    exact ⟨firewallRole, outerRole, interface, member, owner, black,
      (by
        have same : packet.destination = address := by omega
        simpa only [same] using assigned)⟩
  · have interval := PacketPolicy.matching_atom matched atom
    change address ≤ packet.source ∧ packet.source ≤ address at interval
    exact ⟨firewallRole, outerRole, interface, member, owner, black,
      (by
        have same : packet.source = address := by omega
        simpa only [same] using assigned)⟩

theorem firewall_admission_from_local_rule_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (outer : String) (internal : Bool)
    (firewallRole : d.IsDevice interface.device .outerFirewall)
    (outerRole : d.IsLayer outer .outer)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          FirewallBoundaryRule d outer internal (inventory.configuration.ip.interfaceName iface)
            policy.direction rule)
    (direction : Direction) (traffic : Traffic) (accepted : d.Accepts interface.id direction traffic) :
    IPsecPacket traffic.packet ∧
      (direction = .inbound →
        if internal then LocalOuterAddress d interface.device outer traffic.packet.source
        else LocalOuterAddress d interface.device outer traffic.packet.destination) := by
  have fallback : ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny := by
    obtain ⟨_, _, ⟨actual, same, iface, member, name, _⟩, _⟩ := accepted
    have identity : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    intro policy memberPolicy sameName
    exact (checks iface member name policy memberPolicy sameName).1
  obtain ⟨iface, member, name, hook, context, policy, policyMember, policyName,
    policyDirection, _, rule, ruleMember, allow, matched⟩ :=
    routed_acceptance_has_local_matching_rule d inventory present interface.id direction traffic routed fallback accepted
  have guarded := (checks iface member name policy policyMember policyName).2 rule ruleMember allow
  rw [policyDirection] at guarded
  rcases guarded with misses | ⟨protocol, address⟩
  · exact False.elim (hook_mismatch_cannot_match _ direction hook traffic.packet context rule misses matched)
  · exact ⟨IPsec_rule_has_IPsec_packet rule traffic.packet protocol matched,
      fun inbound => matching_firewall_address_guard d interface.device outer internal
        firewallRole outerRole rule (address inbound) traffic.packet matched⟩

end TDN.Requirements.Msc
