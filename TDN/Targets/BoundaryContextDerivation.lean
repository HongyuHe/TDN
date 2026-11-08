import TDN.Targets.BoundaryOwnerDerivation
import TDN.Targets.BoundaryRuleDerivation

namespace TDN.Targets.Complete
open Compliance MultiProtocolExecution

lemma native_inbound_context_has_interface_name (d : Deployment)
    (inventory : PacketProcessing.Inventory) (interface : Interface)
    (context : PacketProcessing.Context)
    (atHook : context.AtHook inventory.configuration)
    (location : d.ContextLocation inventory interface .inbound context) :
    inventory.ifaceName context.entry.iface = interface.id := by
  obtain ⟨_, _, _, _, _, side⟩ := location
  cases hook : context.hook with
  | input =>
    simp only [hook] at side
    simp only [PacketProcessing.Context.AtHook, hook] at atHook
    have ifaces := ingress_has_native_ifaces atHook.2.1
    exact (congrArg inventory.ifaceName ifaces.2.1.symm).trans side.1
  | forward =>
    simp only [hook] at side
    simp only [PacketProcessing.Context.AtHook, hook] at atHook
    obtain ⟨_, entered, _, ingress, _, route, _⟩ := atHook
    have incoming := ingress_has_native_ifaces ingress
    have final := route_from_ingress_preserves_local_state incoming.2.2 route
    exact (congrArg inventory.ifaceName
      (incoming.2.1.symm.trans final.2.1.symm)).trans side
  | output => simp [hook] at side
  | link => simp [hook] at side

lemma native_outbound_context_has_interface_name (d : Deployment)
    (inventory : PacketProcessing.Inventory) (interface : Interface)
    (context : PacketProcessing.Context)
    (location : d.ContextLocation inventory interface .outbound context) :
    inventory.ifaceName context.state.iface = interface.id := by
  obtain ⟨_, _, _, _, _, side⟩ := location
  cases hook : context.hook <;> simp_all

lemma supported_native_context_has_packet_hook (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (direction : Direction) (context : PacketProcessing.Context)
    (supported : d.SupportedAt interface direction context
      (d.Observe (context.Packet inventory.configuration))) :
    context.AtHook inventory.configuration ∧
      d.ContextLocation inventory interface direction context ∧
      HookDirection context.hook direction := by
  obtain ⟨actual, same, _, applies, atHook, location, _⟩ := supported
  have identity : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  exact ⟨atHook, location, applies.1⟩

lemma admitted_native_packet_has_protocol_or_annotation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      PolicyDerivation.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      ∀ policy ∈ d.policies, policy.interface = interface →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          NativeProtocolRule (inventory.configuration.ip.interfaceName iface) policy.direction rule)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface direction traffic) :
    IPsecPacket traffic.packet ∨
      if direction = .inbound then traffic.packet.inboundPolicies ≠ []
      else traffic.packet.outboundPolicies ≠ [] := by
  have fallback : ∀ policy ∈ d.policies, policy.interface = interface →
      policy.defaultVerdict = .deny := by
    obtain ⟨_, _, ⟨actual, same, iface, member, name, _⟩, _⟩ := accepted
    have identity : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    intro policy memberPolicy sameName
    exact (checks iface member name policy memberPolicy sameName).1
  obtain ⟨iface, member, name, hook, context, policy, policyMember, policyName,
    policyDirection, _, rule, ruleMember, allow, matched⟩ :=
    routed_acceptance_has_local_matching_rule d inventory present interface direction traffic routed fallback accepted
  have guarded := (checks iface member name policy policyMember policyName).2 rule ruleMember allow
  rw [policyDirection] at guarded
  exact matching_native_protocol_rule _ direction hook rule guarded traffic.packet context matched

end TDN.Targets.Complete
