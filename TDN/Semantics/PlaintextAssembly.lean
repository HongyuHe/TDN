import TDN.Semantics.ByteFlows
import TDN.Semantics.ExecutionDomains

namespace TDN.Execution

def PlaintextAssembly (before after : State) : Prop :=
  before.datapathStage = .received ∧ after.datapathStage = .received ∧ before.iface = after.iface ∧
  before.frame.tags = [] ∧ after.frame.tags = []

lemma plaintext_assembly_preserves_domain (c : Environment) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) {before after : State}
    (assembly : PlaintextAssembly before after)
    (safe : DomainInvariant c expectedEncapStack allowed before) :
    DomainInvariant c expectedEncapStack allowed after := by
  obtain ⟨receivedBefore, receivedAfter, iface, emptyBefore, emptyAfter⟩ := assembly
  simp only [DomainInvariant, receivedBefore] at safe
  simp only [DomainInvariant, receivedAfter]
  exact ⟨emptyAfter.trans (emptyBefore.symm.trans safe.1 |>.trans (congrArg expectedEncapStack iface)),
    iface ▸ safe.2⟩

end TDN.Execution
