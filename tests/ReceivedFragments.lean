import TDN.Deployments.SnapshotReassembledDomains
import TDN.Deployments.ProfileShared_IsolationTrace
import TDN.Models.BlockedRepliesReduceToForwarding

open TDN DataPlaneForwarding
open TDN.Deployments.ProfileShared_EnclaveIsolation

-- The trace reaches the actual selected Red endpoint before local input/reassembly.
def arrival : Requirements.FragmentArrival := ⟨witnessState0, witnessState57, witnessActions.take 57⟩

lemma actual_received_prefix :
    (lts config).MTr witnessState0 (witnessActions.take 57) witnessState57 := by
  exact Cslib.LTS.MTr.stepL witness_step0 (Cslib.LTS.MTr.stepL witness_step1 (Cslib.LTS.MTr.stepL witness_step2 (Cslib.LTS.MTr.stepL witness_step3 (Cslib.LTS.MTr.stepL witness_step4 (Cslib.LTS.MTr.stepL witness_step5 (Cslib.LTS.MTr.stepL witness_step6 (Cslib.LTS.MTr.stepL witness_step7 (Cslib.LTS.MTr.stepL witness_step8 (Cslib.LTS.MTr.stepL witness_step9 (Cslib.LTS.MTr.stepL witness_step10 (Cslib.LTS.MTr.stepL witness_step11 (Cslib.LTS.MTr.stepL witness_step12 (Cslib.LTS.MTr.stepL witness_step13 (Cslib.LTS.MTr.stepL witness_step14 (Cslib.LTS.MTr.stepL witness_step15 (Cslib.LTS.MTr.stepL witness_step16 (Cslib.LTS.MTr.stepL witness_step17 (Cslib.LTS.MTr.stepL witness_step18 (Cslib.LTS.MTr.stepL witness_step19 (Cslib.LTS.MTr.stepL witness_step20 (Cslib.LTS.MTr.stepL witness_step21 (Cslib.LTS.MTr.stepL witness_step22 (Cslib.LTS.MTr.stepL witness_step23 (Cslib.LTS.MTr.stepL witness_step24 (Cslib.LTS.MTr.stepL witness_step25 (Cslib.LTS.MTr.stepL witness_step26 (Cslib.LTS.MTr.stepL witness_step27 (Cslib.LTS.MTr.stepL witness_step28 (Cslib.LTS.MTr.stepL witness_step29 (Cslib.LTS.MTr.stepL witness_step30 (Cslib.LTS.MTr.stepL witness_step31 (Cslib.LTS.MTr.stepL witness_step32 (Cslib.LTS.MTr.stepL witness_step33 (Cslib.LTS.MTr.stepL witness_step34 (Cslib.LTS.MTr.stepL witness_step35 (Cslib.LTS.MTr.stepL witness_step36 (Cslib.LTS.MTr.stepL witness_step37 (Cslib.LTS.MTr.stepL witness_step38 (Cslib.LTS.MTr.stepL witness_step39 (Cslib.LTS.MTr.stepL witness_step40 (Cslib.LTS.MTr.stepL witness_step41 (Cslib.LTS.MTr.stepL witness_step42 (Cslib.LTS.MTr.stepL witness_step43 (Cslib.LTS.MTr.stepL witness_step44 (Cslib.LTS.MTr.stepL witness_step45 (Cslib.LTS.MTr.stepL witness_step46 (Cslib.LTS.MTr.stepL witness_step47 (Cslib.LTS.MTr.stepL witness_step48 (Cslib.LTS.MTr.stepL witness_step49 (Cslib.LTS.MTr.stepL witness_step50 (Cslib.LTS.MTr.stepL witness_step51 (Cslib.LTS.MTr.stepL witness_step52 (Cslib.LTS.MTr.stepL witness_step53 (Cslib.LTS.MTr.stepL witness_step54 (Cslib.LTS.MTr.stepL witness_step55 (Cslib.LTS.MTr.stepL witness_step56 (Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))))))))))))))))))))))))))

abbrev B := ReassemblyOrigins.ByteOrigin Nat Nat Nat
def goodPiece : Fragmentation.PayloadFragment Nat B := ⟨42, 0, [⟨65, 1, 1⟩]⟩
def foreignPiece : Fragmentation.PayloadFragment Nat B := ⟨42, 0, [⟨65, 2, 1⟩]⟩

-- Byte value 65 is illustrative. The endpoint/path facts are the imported checked trace.
example : Requirements.ArrivedFragment config redSources 196 arrival goodPiece := by
  refine ⟨?_, actual_received_prefix, rfl, rfl, rfl, ?_⟩
  · unfold Requirements.RedPayloadOrigin
    native_decide
  · intro byte member
    have same : byte = ⟨65, 1, 1⟩ := by simpa [goodPiece] using member
    subst byte
    constructor <;> native_decide

-- The ordinary fragment key stays unchanged; source-iface provenance rejects a forged domain.
example : ¬ Requirements.ArrivedFragment config redSources 196 arrival foreignPiece := by
  intro arrived
  have impossible := (arrived.2.2.2.2.2 ⟨65, 2, 1⟩ (by simp [foreignPiece])).1
  have actual : config.ifaceSecurityDomain arrival.start.iface = some 1 := by native_decide
  rw [actual] at impossible
  contradiction

-- A blocked response extension preserves an underlying execution for any state space.
example {S A : Type} (network : Cslib.LTS S A) (responses : KernelResponses.ReplyConfig S)
    (guards : ∀ source, responses.generates source → ∀ iface,
      responses.outputFallback source iface = .deny ∧
      ∀ rule ∈ responses.outputRules source iface, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule)
    {a b : S} {labels : List (KernelResponses.ReplyAction A)}
    (run : (KernelResponses.lts network responses).MTr (.network a) labels (.network b)) :
    ∃ actions, network.MTr a actions b :=
  KernelResponses.strict_response_result_has_network_forwarding network responses guards run
