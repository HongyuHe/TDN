import TDN.Semantics.CiphertextTransit
import TDN.Evidence.FreshSharedExecutionWitness

open TDN Execution
open TDN.Imported.FreshSharedExecution

private theorem blackTransit : (transit config).MTr witnessState33
    [.linkTransmit, .local, .route, .filter, .local, .linkTransmit] witnessState39 := by
  exact .stepL ⟨witnessStep33, by decide⟩
    (.stepL ⟨witnessStep34, by decide⟩
      (.stepL ⟨witnessStep35, by decide⟩
        (.stepL ⟨witnessStep36, by decide⟩
          (.stepL ⟨witnessStep37, by decide⟩
            (.stepL ⟨witnessStep38, by decide⟩ .refl)))))

/-- The actual Black router/firewall path inspects the same visible ESP packet
for every replacement of the hidden payload and envelope metadata. -/
example (payload domain : Nat) (envelopes : List Envelope) :
    (lts config).MTr (withHiddenContent payload domain envelopes witnessState33)
      [.linkTransmit, .local, .route, .filter, .local, .linkTransmit]
      (withHiddenContent payload domain envelopes witnessState39) :=
  transit_path_ignores_hidden_content config payload domain envelopes blackTransit

example : ¬ TransitAction .decrypt := by
  simp [TransitAction]

example : ¬ TransitAction .encrypt := by
  simp [TransitAction]

example : ¬ TransitAction .deliver := by
  simp [TransitAction]
