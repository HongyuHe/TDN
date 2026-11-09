import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc
open Compliance

def GrayFirewallPolicyBeforeForwardSourceCheck (d : Deployment) (grayFirewallRequired : Bool) : Prop :=
  d.AddressInventoryCoherent ∧
  (grayFirewallRequired = true → d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
    ∀ interface ∈ d.interfaces, d.Relevant interface.device →
      d.IsDevice interface.device .grayFirewall → d.PolicyCoverage interface ∧
        (∀ direction traffic, d.Accepts interface.id direction traffic →
          GrayFirewallRestrictions d interface direction traffic ∧
          GrayPolicyAllowance d interface traffic) ∧
        ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
          GrayFirewallRestrictions d interface direction traffic →
          GrayPolicyAllowance d interface traffic →
          d.AcceptsAt interface.id direction hook traffic) ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → d.IsDevice interface.device .grayFirewall →
    ∀ direction traffic, DifferentClassificationVPNs d traffic →
      ¬ d.Accepts interface.id direction traffic

def msc_gray_firewall_allowlist_before_forward_source_check (d : Deployment) (required : Bool) : Prop :=
  GrayFirewallPolicyBeforeForwardSourceCheck { d with focus := none } required

lemma missing_required_Gray_allowance_refutes_complete_spec (d : Deployment)
    (focus : d.focus = none) (interface : Interface) (member : interface ∈ d.interfaces)
    (role : d.IsDevice interface.device .grayFirewall)
    (direction : Direction) (hook : PacketProcessing.Hook) (traffic : Traffic)
    (eligible : d.PacketEligibleAt interface direction hook traffic)
    (restrictions : GrayFirewallRestrictions d interface direction traffic)
    (allowed : GrayPolicyAllowance d interface traffic)
    (denied : ¬ d.AcceptsAt interface.id direction hook traffic) :
    ¬ msc_gray_firewall_allowlist_before_forward_source_check d true := by
  intro specification
  have cleared : { d with focus := none } = d := by
    cases d
    cases focus
    rfl
  unfold msc_gray_firewall_allowlist_before_forward_source_check at specification
  rw [cleared] at specification
  have required := specification.2.1 rfl
  have checked := required.2.2 interface member (by simp [Deployment.Relevant, focus]) role
  exact denied (checked.2.2 direction hook traffic eligible restrictions allowed)

end TDN.Requirements.Msc
