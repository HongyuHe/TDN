import TDN.Targets.BoundaryControlRules

namespace TDN.Targets.Complete
open Compliance

def GrayControlInventoryDisjoint (d : Deployment) (controls : List BoundaryControlFlow) : Prop :=
  ∀ interface ∈ d.interfaces, d.IsDevice interface.device .grayFirewall →
    ∀ control ∈ controls, control.device ≠ interface.device

instance (d : Deployment) (controls : List BoundaryControlFlow) :
    Decidable (GrayControlInventoryDisjoint d controls) := by
  have (interface : Interface) : Decidable (d.IsDevice interface.device .grayFirewall) := by
    unfold Deployment.IsDevice
    infer_instance
  unfold GrayControlInventoryDisjoint
  infer_instance

lemma declared_control_inventory_has_no_Gray_firewall_approval (d : Deployment)
    (controls : List BoundaryControlFlow) (approval : d.policyApproved = BoundaryControlApproval controls)
    (disjoint : GrayControlInventoryDisjoint d controls)
    (interface : Interface) (member : interface ∈ d.interfaces)
    (role : d.IsDevice interface.device .grayFirewall) (traffic : Traffic) :
    ¬ d.policyApproved interface.device traffic := by
  intro approved
  rw [approval] at approved
  obtain ⟨control, controlMember, matched⟩ := approved
  exact disjoint interface member role control controlMember matched.1

end TDN.Targets.Complete
