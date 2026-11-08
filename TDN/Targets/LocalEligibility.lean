import TDN.Targets.ComplianceModel

namespace TDN.Compliance

theorem coherent_local_input_has_ingress_eligibility (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (context : PacketProcessing.Context) (traffic : Traffic)
    (hook : context.hook = .input) (coherent : context.entry.frame.HeadersCoherent) :
    d.ContextIngressEligible context traffic := by
  refine ⟨inventory, present, coherent, ?_, ?_⟩
  · intro forward
    cases hook.symm.trans forward
  · intro forward
    cases hook.symm.trans forward

theorem coherent_local_output_has_ingress_eligibility (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (context : PacketProcessing.Context) (traffic : Traffic)
    (hook : context.hook = .output) (coherent : context.entry.frame.HeadersCoherent) :
    d.ContextIngressEligible context traffic := by
  refine ⟨inventory, present, coherent, ?_, ?_⟩
  · intro forward
    cases hook.symm.trans forward
  · intro forward
    cases hook.symm.trans forward

end TDN.Compliance
