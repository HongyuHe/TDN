import TDN.Import.Command
import TDN.Semantics.GuardedResponseNetwork
import TDN.Evidence.FreshFamily444V13ResponseGuards

namespace TDN.Imported.Family444V13
open Execution
set_option maxRecDepth 100000
set_option maxHeartbeats 0

tdn_data responseData : GuardedResponseNetwork.Data from "../../data/evidence/FreshFamily444V13ResponseExecution.json" ["TDN.Imported.Family444V13.responseData"]

lemma response_default_checks : ∀ guard ∈ responseSourceGuards,
    (deviceAt devices guard.1).outputFallback = .deny := by decide

theorem gateway_response_executions_keep_stack
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (GuardedResponseNetwork.responseConfig responseData)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    StackInvariant config layout after :=
  GuardedResponseNetwork.all_guarded_response_executions_preserve_stack responseData
    local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered
    response_default_checks run initial

lemma guardedWitnessStep0 :
    (GuardedResponseNetwork.network responseData).Tr witnessState0 .route witnessState1 := by
  exact ⟨witnessStep0, by decide⟩

lemma guardedWitnessStep1 :
    (GuardedResponseNetwork.network responseData).Tr witnessState1 .filter witnessState2 := by
  exact ⟨witnessStep1, by decide⟩

lemma guardedWitnessStep2 :
    (GuardedResponseNetwork.network responseData).Tr witnessState2 .local witnessState3 := by
  exact ⟨witnessStep2, by decide⟩

lemma guardedWitnessStep3 :
    (GuardedResponseNetwork.network responseData).Tr witnessState3 .wire witnessState4 := by
  exact ⟨witnessStep3, by decide⟩

lemma guardedWitnessStep4 :
    (GuardedResponseNetwork.network responseData).Tr witnessState4 .local witnessState5 := by
  exact ⟨witnessStep4, by decide⟩

lemma guardedWitnessStep5 :
    (GuardedResponseNetwork.network responseData).Tr witnessState5 .route witnessState6 := by
  exact ⟨witnessStep5, by decide⟩

lemma guardedWitnessStep6 :
    (GuardedResponseNetwork.network responseData).Tr witnessState6 .filter witnessState7 := by
  exact ⟨witnessStep6, by decide⟩

lemma guardedWitnessStep7 :
    (GuardedResponseNetwork.network responseData).Tr witnessState7 .encrypt witnessState8 := by
  exact ⟨witnessStep7, by decide⟩

lemma guardedWitnessStep8 :
    (GuardedResponseNetwork.network responseData).Tr witnessState8 .route witnessState9 := by
  exact ⟨witnessStep8, by decide⟩

lemma guardedWitnessStep9 :
    (GuardedResponseNetwork.network responseData).Tr witnessState9 .wire witnessState10 := by
  exact ⟨witnessStep9, by decide⟩

lemma guardedWitnessStep10 :
    (GuardedResponseNetwork.network responseData).Tr witnessState10 .local witnessState11 := by
  exact ⟨witnessStep10, by decide⟩

lemma guardedWitnessStep11 :
    (GuardedResponseNetwork.network responseData).Tr witnessState11 .route witnessState12 := by
  exact ⟨witnessStep11, by decide⟩

lemma guardedWitnessStep12 :
    (GuardedResponseNetwork.network responseData).Tr witnessState12 .filter witnessState13 := by
  exact ⟨witnessStep12, by decide⟩

lemma guardedWitnessStep13 :
    (GuardedResponseNetwork.network responseData).Tr witnessState13 .encrypt witnessState14 := by
  exact ⟨witnessStep13, by decide⟩

lemma guardedWitnessStep14 :
    (GuardedResponseNetwork.network responseData).Tr witnessState14 .route witnessState15 := by
  exact ⟨witnessStep14, by decide⟩

lemma guardedWitnessStep15 :
    (GuardedResponseNetwork.network responseData).Tr witnessState15 .wire witnessState16 := by
  exact ⟨witnessStep15, by decide⟩

lemma guardedWitnessStep16 :
    (GuardedResponseNetwork.network responseData).Tr witnessState16 .local witnessState17 := by
  exact ⟨witnessStep16, by decide⟩

lemma guardedWitnessStep17 :
    (GuardedResponseNetwork.network responseData).Tr witnessState17 .route witnessState18 := by
  exact ⟨witnessStep17, by decide⟩

lemma guardedWitnessStep18 :
    (GuardedResponseNetwork.network responseData).Tr witnessState18 .filter witnessState19 := by
  exact ⟨witnessStep18, by decide⟩

lemma guardedWitnessStep19 :
    (GuardedResponseNetwork.network responseData).Tr witnessState19 .local witnessState20 := by
  exact ⟨witnessStep19, by decide⟩

lemma guardedWitnessStep20 :
    (GuardedResponseNetwork.network responseData).Tr witnessState20 .wire witnessState21 := by
  exact ⟨witnessStep20, by decide⟩

lemma guardedWitnessStep21 :
    (GuardedResponseNetwork.network responseData).Tr witnessState21 .local witnessState22 := by
  exact ⟨witnessStep21, by decide⟩

lemma guardedWitnessStep22 :
    (GuardedResponseNetwork.network responseData).Tr witnessState22 .route witnessState23 := by
  exact ⟨witnessStep22, by decide⟩

lemma guardedWitnessStep23 :
    (GuardedResponseNetwork.network responseData).Tr witnessState23 .filter witnessState24 := by
  exact ⟨witnessStep23, by decide⟩

lemma guardedWitnessStep24 :
    (GuardedResponseNetwork.network responseData).Tr witnessState24 .local witnessState25 := by
  exact ⟨witnessStep24, by decide⟩

lemma guardedWitnessStep25 :
    (GuardedResponseNetwork.network responseData).Tr witnessState25 .wire witnessState26 := by
  exact ⟨witnessStep25, by decide⟩

lemma guardedWitnessStep26 :
    (GuardedResponseNetwork.network responseData).Tr witnessState26 .decrypt witnessState27 := by
  exact ⟨witnessStep26, by decide⟩

lemma guardedWitnessStep27 :
    (GuardedResponseNetwork.network responseData).Tr witnessState27 .route witnessState28 := by
  exact ⟨witnessStep27, by decide⟩

lemma guardedWitnessStep28 :
    (GuardedResponseNetwork.network responseData).Tr witnessState28 .filter witnessState29 := by
  exact ⟨witnessStep28, by decide⟩

lemma guardedWitnessStep29 :
    (GuardedResponseNetwork.network responseData).Tr witnessState29 .local witnessState30 := by
  exact ⟨witnessStep29, by decide⟩

lemma guardedWitnessStep30 :
    (GuardedResponseNetwork.network responseData).Tr witnessState30 .wire witnessState31 := by
  exact ⟨witnessStep30, by decide⟩

lemma guardedWitnessStep31 :
    (GuardedResponseNetwork.network responseData).Tr witnessState31 .decrypt witnessState32 := by
  exact ⟨witnessStep31, by decide⟩

lemma guardedWitnessStep32 :
    (GuardedResponseNetwork.network responseData).Tr witnessState32 .route witnessState33 := by
  exact ⟨witnessStep32, by decide⟩

lemma guardedWitnessStep33 :
    (GuardedResponseNetwork.network responseData).Tr witnessState33 .filter witnessState34 := by
  exact ⟨witnessStep33, by decide⟩

lemma guardedWitnessStep34 :
    (GuardedResponseNetwork.network responseData).Tr witnessState34 .local witnessState35 := by
  exact ⟨witnessStep34, by decide⟩

lemma guardedWitnessStep35 :
    (GuardedResponseNetwork.network responseData).Tr witnessState35 .wire witnessState36 := by
  exact ⟨witnessStep35, by decide⟩

lemma guardedWitnessStep36 :
    (GuardedResponseNetwork.network responseData).Tr witnessState36 .local witnessState37 := by
  exact ⟨witnessStep36, by decide⟩

lemma guardedWitnessStep37 :
    (GuardedResponseNetwork.network responseData).Tr witnessState37 .local witnessState38 := by
  exact ⟨witnessStep37, by decide⟩

lemma guardedWitnessStep38 :
    (GuardedResponseNetwork.network responseData).Tr witnessState38 .deliver witnessState39 := by
  exact ⟨witnessStep38, by decide⟩

theorem positive_delivery_with_early_source_guards :
    (GuardedResponseNetwork.network responseData).MTr witnessState0 witnessActions witnessState39 := by
  exact Cslib.LTS.MTr.stepL guardedWitnessStep0 (Cslib.LTS.MTr.stepL guardedWitnessStep1 (Cslib.LTS.MTr.stepL guardedWitnessStep2 (Cslib.LTS.MTr.stepL guardedWitnessStep3 (Cslib.LTS.MTr.stepL guardedWitnessStep4 (Cslib.LTS.MTr.stepL guardedWitnessStep5 (Cslib.LTS.MTr.stepL guardedWitnessStep6 (Cslib.LTS.MTr.stepL guardedWitnessStep7 (Cslib.LTS.MTr.stepL guardedWitnessStep8 (Cslib.LTS.MTr.stepL guardedWitnessStep9 (Cslib.LTS.MTr.stepL guardedWitnessStep10 (Cslib.LTS.MTr.stepL guardedWitnessStep11 (Cslib.LTS.MTr.stepL guardedWitnessStep12 (Cslib.LTS.MTr.stepL guardedWitnessStep13 (Cslib.LTS.MTr.stepL guardedWitnessStep14 (Cslib.LTS.MTr.stepL guardedWitnessStep15 (Cslib.LTS.MTr.stepL guardedWitnessStep16 (Cslib.LTS.MTr.stepL guardedWitnessStep17 (Cslib.LTS.MTr.stepL guardedWitnessStep18 (Cslib.LTS.MTr.stepL guardedWitnessStep19 (Cslib.LTS.MTr.stepL guardedWitnessStep20 (Cslib.LTS.MTr.stepL guardedWitnessStep21 (Cslib.LTS.MTr.stepL guardedWitnessStep22 (Cslib.LTS.MTr.stepL guardedWitnessStep23 (Cslib.LTS.MTr.stepL guardedWitnessStep24 (Cslib.LTS.MTr.stepL guardedWitnessStep25 (Cslib.LTS.MTr.stepL guardedWitnessStep26 (Cslib.LTS.MTr.stepL guardedWitnessStep27 (Cslib.LTS.MTr.stepL guardedWitnessStep28 (Cslib.LTS.MTr.stepL guardedWitnessStep29 (Cslib.LTS.MTr.stepL guardedWitnessStep30 (Cslib.LTS.MTr.stepL guardedWitnessStep31 (Cslib.LTS.MTr.stepL guardedWitnessStep32 (Cslib.LTS.MTr.stepL guardedWitnessStep33 (Cslib.LTS.MTr.stepL guardedWitnessStep34 (Cslib.LTS.MTr.stepL guardedWitnessStep35 (Cslib.LTS.MTr.stepL guardedWitnessStep36 (Cslib.LTS.MTr.stepL guardedWitnessStep37 (Cslib.LTS.MTr.stepL guardedWitnessStep38 (Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))))))))

lemma initial_guarded_state_is_safe : GuardedResponseNetwork.Safe responseData witnessState0 := by
  exact ⟨witness_initial_stack, trivial, by decide⟩

end TDN.Imported.Family444V13
