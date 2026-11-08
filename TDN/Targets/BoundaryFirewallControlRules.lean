import TDN.Targets.BoundaryFirewallRules
import TDN.Targets.BoundaryControlRules

namespace TDN.Targets.Complete
open Compliance

def FirewallControlBoundaryRule (d : Deployment) (controls : List BoundaryControlFlow)
    (device outer : String) (internal : Bool) (name : String)
    (direction : Direction) (hook : PacketProcessing.Hook) (rule : PacketPolicy.Rule) : Prop :=
  FirewallBoundaryRule d outer internal name direction rule ∨
    BoundaryControlRule controls device name direction hook rule

instance (d : Deployment) (controls : List BoundaryControlFlow) (device outer : String)
    (internal : Bool) (name : String) (direction : Direction)
    (hook : PacketProcessing.Hook) (rule : PacketPolicy.Rule) :
    Decidable (FirewallControlBoundaryRule d controls device outer internal name direction hook rule) := by
  unfold FirewallControlBoundaryRule
  infer_instance

theorem firewall_control_admission_from_local_rule_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (controls : List BoundaryControlFlow)
    (approval : d.policyApproved = BoundaryControlApproval controls)
    (observations : BoundaryControlObservationChecks d controls)
    (interface : Interface) (outer : String) (internal : Bool)
    (firewallRole : d.IsDevice interface.device .outerFirewall)
    (outerRole : d.IsLayer outer .outer)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      PolicyDerivation.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          FirewallControlBoundaryRule d controls interface.device outer internal
            (inventory.configuration.ip.interfaceName iface) policy.direction policy.hook rule)
    (direction : Direction) (traffic : Traffic) (accepted : d.Accepts interface.id direction traffic) :
    (IPsecPacket traffic.packet ∧
      (direction = .inbound →
        if internal then LocalOuterAddress d interface.device outer traffic.packet.source
        else LocalOuterAddress d interface.device outer traffic.packet.destination)) ∨
      ApprovedControl d interface.device traffic := by
  have fallback : ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny := by
    obtain ⟨_, _, ⟨actual, same, iface, member, name, _⟩, _⟩ := accepted
    have identity : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    intro policy memberPolicy sameName
    exact (checks iface member name policy memberPolicy sameName).1
  obtain ⟨iface, member, name, hook, context, policy, policyMember, policyName,
    policyDirection, policyHook, rule, ruleMember, allow, matched⟩ :=
    routed_acceptance_has_local_matching_rule d inventory present interface.id direction traffic routed fallback accepted
  have guarded := (checks iface member name policy policyMember policyName).2 rule ruleMember allow
  rw [policyDirection, policyHook] at guarded
  rcases guarded with guarded | control
  ·
    rcases guarded with misses | ⟨protocol, address⟩
    · exact False.elim (hook_mismatch_cannot_match _ direction hook traffic.packet context rule misses matched)
    · exact Or.inl ⟨IPsec_rule_has_IPsec_packet rule traffic.packet protocol matched,
        fun inbound => matching_firewall_address_guard d interface.device outer internal
          firewallRole outerRole rule (address inbound) traffic.packet matched⟩

  · obtain ⟨_, supported, _⟩ := accepted
    exact Or.inr (matching_boundary_control_rule_is_approved d controls approval observations
      interface.device _ direction hook traffic supported context rule control matched)

end TDN.Targets.Complete
