import TDN.Semantics.ByteFlows
import TDN.Semantics.ExecutionDomains

namespace TDN.Execution

def PlaintextAssembly (before after : State) : Prop :=
  before.phase = .received ∧ after.phase = .received ∧ before.port = after.port ∧
  before.frame.tags = [] ∧ after.frame.tags = []

lemma plaintext_assembly_preserves_domain (c : Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) {before after : State}
    (assembly : PlaintextAssembly before after)
    (safe : DomainInvariant c layout allowed before) :
    DomainInvariant c layout allowed after := by
  obtain ⟨receivedBefore, receivedAfter, port, emptyBefore, emptyAfter⟩ := assembly
  simp only [DomainInvariant, receivedBefore] at safe
  simp only [DomainInvariant, receivedAfter]
  exact ⟨emptyAfter.trans (emptyBefore.symm.trans safe.1 |>.trans (congrArg layout port)),
    port ▸ safe.2⟩

end TDN.Execution
