import TDN.Evidence.FreshReassembledDomains
import TDN.Evidence.FreshSharedIsolationWitness
import TDN.Semantics.StrictResponseProjection

open TDN Execution
open TDN.Imported.FreshSharedIsolation

-- The trace reaches the actual selected Red endpoint before local input/reassembly.
def arrival : Targets.FragmentArrival := ⟨witnessState0, witnessState57, witnessActions.take 57⟩

lemma actual_received_prefix :
    (lts config).MTr witnessState0 (witnessActions.take 57) witnessState57 := by
  exact Cslib.LTS.MTr.stepL witnessStep0 (Cslib.LTS.MTr.stepL witnessStep1 (Cslib.LTS.MTr.stepL witnessStep2 (Cslib.LTS.MTr.stepL witnessStep3 (Cslib.LTS.MTr.stepL witnessStep4 (Cslib.LTS.MTr.stepL witnessStep5 (Cslib.LTS.MTr.stepL witnessStep6 (Cslib.LTS.MTr.stepL witnessStep7 (Cslib.LTS.MTr.stepL witnessStep8 (Cslib.LTS.MTr.stepL witnessStep9 (Cslib.LTS.MTr.stepL witnessStep10 (Cslib.LTS.MTr.stepL witnessStep11 (Cslib.LTS.MTr.stepL witnessStep12 (Cslib.LTS.MTr.stepL witnessStep13 (Cslib.LTS.MTr.stepL witnessStep14 (Cslib.LTS.MTr.stepL witnessStep15 (Cslib.LTS.MTr.stepL witnessStep16 (Cslib.LTS.MTr.stepL witnessStep17 (Cslib.LTS.MTr.stepL witnessStep18 (Cslib.LTS.MTr.stepL witnessStep19 (Cslib.LTS.MTr.stepL witnessStep20 (Cslib.LTS.MTr.stepL witnessStep21 (Cslib.LTS.MTr.stepL witnessStep22 (Cslib.LTS.MTr.stepL witnessStep23 (Cslib.LTS.MTr.stepL witnessStep24 (Cslib.LTS.MTr.stepL witnessStep25 (Cslib.LTS.MTr.stepL witnessStep26 (Cslib.LTS.MTr.stepL witnessStep27 (Cslib.LTS.MTr.stepL witnessStep28 (Cslib.LTS.MTr.stepL witnessStep29 (Cslib.LTS.MTr.stepL witnessStep30 (Cslib.LTS.MTr.stepL witnessStep31 (Cslib.LTS.MTr.stepL witnessStep32 (Cslib.LTS.MTr.stepL witnessStep33 (Cslib.LTS.MTr.stepL witnessStep34 (Cslib.LTS.MTr.stepL witnessStep35 (Cslib.LTS.MTr.stepL witnessStep36 (Cslib.LTS.MTr.stepL witnessStep37 (Cslib.LTS.MTr.stepL witnessStep38 (Cslib.LTS.MTr.stepL witnessStep39 (Cslib.LTS.MTr.stepL witnessStep40 (Cslib.LTS.MTr.stepL witnessStep41 (Cslib.LTS.MTr.stepL witnessStep42 (Cslib.LTS.MTr.stepL witnessStep43 (Cslib.LTS.MTr.stepL witnessStep44 (Cslib.LTS.MTr.stepL witnessStep45 (Cslib.LTS.MTr.stepL witnessStep46 (Cslib.LTS.MTr.stepL witnessStep47 (Cslib.LTS.MTr.stepL witnessStep48 (Cslib.LTS.MTr.stepL witnessStep49 (Cslib.LTS.MTr.stepL witnessStep50 (Cslib.LTS.MTr.stepL witnessStep51 (Cslib.LTS.MTr.stepL witnessStep52 (Cslib.LTS.MTr.stepL witnessStep53 (Cslib.LTS.MTr.stepL witnessStep54 (Cslib.LTS.MTr.stepL witnessStep55 (Cslib.LTS.MTr.stepL witnessStep56 (Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))))))))))))))))))))))))))

abbrev B := ReassemblyOrigins.ByteOrigin Nat Nat Nat
def goodPiece : Fragmentation.Fragment Nat B := ⟨42, 0, [⟨65, 1, 1⟩]⟩
def foreignPiece : Fragmentation.Fragment Nat B := ⟨42, 0, [⟨65, 2, 1⟩]⟩

-- Byte value 65 is illustrative. The endpoint/path facts are the imported checked trace.
example : Targets.ArrivedFragment config redSources 196 arrival goodPiece := by
  refine ⟨?_, actual_received_prefix, rfl, rfl, rfl, ?_⟩
  · unfold Targets.RedPayloadOrigin
    decide
  · intro byte member
    have same : byte = ⟨65, 1, 1⟩ := by simpa [goodPiece] using member
    subst byte
    constructor <;> decide

-- The ordinary fragment key stays unchanged; source-iface provenance rejects a forged domain.
example : ¬ Targets.ArrivedFragment config redSources 196 arrival foreignPiece := by
  intro arrived
  have impossible := (arrived.2.2.2.2.2 ⟨65, 2, 1⟩ (by simp [foreignPiece])).1
  have actual : config.recipientDomain arrival.start.iface = some 1 := by decide
  rw [actual] at impossible
  contradiction

-- A blocked response extension preserves an underlying execution for any state space.
example {S A : Type} (network : Cslib.LTS S A) (responses : KernelResponses.Config S)
    (guards : ∀ source, responses.generates source → ∀ iface,
      responses.outputFallback source iface = .deny ∧
      ∀ rule ∈ responses.outputRules source iface, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule)
    {a b : S} {labels : List (KernelResponses.Action A)}
    (run : (KernelResponses.lts network responses).MTr (.network a) labels (.network b)) :
    ∃ actions, network.MTr a actions b :=
  KernelResponses.strict_response_result_has_network_execution network responses guards run
