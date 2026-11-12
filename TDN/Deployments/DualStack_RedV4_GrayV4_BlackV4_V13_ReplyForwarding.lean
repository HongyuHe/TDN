import TDN.Import.SnapshotLoader
import TDN.Models.SourceGuardedAutoReplyNetwork
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13_ReplyGuards

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
open DataPlaneForwarding
set_option maxRecDepth 100000
set_option maxHeartbeats 0

load_network_records responseData : GuardedResponseNetwork.Data from "../../data/evidence/DualStack_RedV4_GrayV4_BlackV4_V13_ReplyForwarding.json" ["TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13.responseData"]

lemma response_default_checks : ∀ guard ∈ responseSourceGuards,
    (deviceAt devices guard.1).outputFallback = .deny := by native_decide

theorem gateway_response_traces_keep_stack
    {before after : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (GuardedResponseNetwork.responseConfig responseData)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    EncapStackConsistent config expectedEncapStack after :=
  GuardedResponseNetwork.all_guarded_response_traces_preserve_stack responseData
    local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered
    response_default_checks run initial

lemma guardedWitnessStep0 :
    (GuardedResponseNetwork.network responseData).Tr witnessState0 .route witnessState1 := by
  exact ⟨witnessStep0, by native_decide⟩

lemma guardedWitnessStep1 :
    (GuardedResponseNetwork.network responseData).Tr witnessState1 .filter witnessState2 := by
  exact ⟨witnessStep1, by native_decide⟩

lemma guardedWitnessStep2 :
    (GuardedResponseNetwork.network responseData).Tr witnessState2 .internalProcessing witnessState3 := by
  exact ⟨witnessStep2, by native_decide⟩

lemma guardedWitnessStep3 :
    (GuardedResponseNetwork.network responseData).Tr witnessState3 .linkTransmit witnessState4 := by
  exact ⟨witnessStep3, by native_decide⟩

lemma guardedWitnessStep4 :
    (GuardedResponseNetwork.network responseData).Tr witnessState4 .internalProcessing witnessState5 := by
  exact ⟨witnessStep4, by native_decide⟩

lemma guardedWitnessStep5 :
    (GuardedResponseNetwork.network responseData).Tr witnessState5 .route witnessState6 := by
  exact ⟨witnessStep5, by native_decide⟩

lemma guardedWitnessStep6 :
    (GuardedResponseNetwork.network responseData).Tr witnessState6 .filter witnessState7 := by
  exact ⟨witnessStep6, by native_decide⟩

lemma guardedWitnessStep7 :
    (GuardedResponseNetwork.network responseData).Tr witnessState7 .encrypt witnessState8 := by
  exact ⟨witnessStep7, by native_decide⟩

lemma guardedWitnessStep8 :
    (GuardedResponseNetwork.network responseData).Tr witnessState8 .route witnessState9 := by
  exact ⟨witnessStep8, by native_decide⟩

lemma guardedWitnessStep9 :
    (GuardedResponseNetwork.network responseData).Tr witnessState9 .linkTransmit witnessState10 := by
  exact ⟨witnessStep9, by native_decide⟩

lemma guardedWitnessStep10 :
    (GuardedResponseNetwork.network responseData).Tr witnessState10 .internalProcessing witnessState11 := by
  exact ⟨witnessStep10, by native_decide⟩

lemma guardedWitnessStep11 :
    (GuardedResponseNetwork.network responseData).Tr witnessState11 .route witnessState12 := by
  exact ⟨witnessStep11, by native_decide⟩

lemma guardedWitnessStep12 :
    (GuardedResponseNetwork.network responseData).Tr witnessState12 .filter witnessState13 := by
  exact ⟨witnessStep12, by native_decide⟩

lemma guardedWitnessStep13 :
    (GuardedResponseNetwork.network responseData).Tr witnessState13 .encrypt witnessState14 := by
  exact ⟨witnessStep13, by native_decide⟩

lemma guardedWitnessStep14 :
    (GuardedResponseNetwork.network responseData).Tr witnessState14 .route witnessState15 := by
  exact ⟨witnessStep14, by native_decide⟩

lemma guardedWitnessStep15 :
    (GuardedResponseNetwork.network responseData).Tr witnessState15 .linkTransmit witnessState16 := by
  exact ⟨witnessStep15, by native_decide⟩

lemma guardedWitnessStep16 :
    (GuardedResponseNetwork.network responseData).Tr witnessState16 .internalProcessing witnessState17 := by
  exact ⟨witnessStep16, by native_decide⟩

lemma guardedWitnessStep17 :
    (GuardedResponseNetwork.network responseData).Tr witnessState17 .route witnessState18 := by
  exact ⟨witnessStep17, by native_decide⟩

lemma guardedWitnessStep18 :
    (GuardedResponseNetwork.network responseData).Tr witnessState18 .filter witnessState19 := by
  exact ⟨witnessStep18, by native_decide⟩

lemma guardedWitnessStep19 :
    (GuardedResponseNetwork.network responseData).Tr witnessState19 .internalProcessing witnessState20 := by
  exact ⟨witnessStep19, by native_decide⟩

lemma guardedWitnessStep20 :
    (GuardedResponseNetwork.network responseData).Tr witnessState20 .linkTransmit witnessState21 := by
  exact ⟨witnessStep20, by native_decide⟩

lemma guardedWitnessStep21 :
    (GuardedResponseNetwork.network responseData).Tr witnessState21 .internalProcessing witnessState22 := by
  exact ⟨witnessStep21, by native_decide⟩

lemma guardedWitnessStep22 :
    (GuardedResponseNetwork.network responseData).Tr witnessState22 .route witnessState23 := by
  exact ⟨witnessStep22, by native_decide⟩

lemma guardedWitnessStep23 :
    (GuardedResponseNetwork.network responseData).Tr witnessState23 .filter witnessState24 := by
  exact ⟨witnessStep23, by native_decide⟩

lemma guardedWitnessStep24 :
    (GuardedResponseNetwork.network responseData).Tr witnessState24 .internalProcessing witnessState25 := by
  exact ⟨witnessStep24, by native_decide⟩

lemma guardedWitnessStep25 :
    (GuardedResponseNetwork.network responseData).Tr witnessState25 .linkTransmit witnessState26 := by
  exact ⟨witnessStep25, by native_decide⟩

lemma guardedWitnessStep26 :
    (GuardedResponseNetwork.network responseData).Tr witnessState26 .decrypt witnessState27 := by
  exact ⟨witnessStep26, by native_decide⟩

lemma guardedWitnessStep27 :
    (GuardedResponseNetwork.network responseData).Tr witnessState27 .route witnessState28 := by
  exact ⟨witnessStep27, by native_decide⟩

lemma guardedWitnessStep28 :
    (GuardedResponseNetwork.network responseData).Tr witnessState28 .filter witnessState29 := by
  exact ⟨witnessStep28, by native_decide⟩

lemma guardedWitnessStep29 :
    (GuardedResponseNetwork.network responseData).Tr witnessState29 .internalProcessing witnessState30 := by
  exact ⟨witnessStep29, by native_decide⟩

lemma guardedWitnessStep30 :
    (GuardedResponseNetwork.network responseData).Tr witnessState30 .linkTransmit witnessState31 := by
  exact ⟨witnessStep30, by native_decide⟩

lemma guardedWitnessStep31 :
    (GuardedResponseNetwork.network responseData).Tr witnessState31 .decrypt witnessState32 := by
  exact ⟨witnessStep31, by native_decide⟩

lemma guardedWitnessStep32 :
    (GuardedResponseNetwork.network responseData).Tr witnessState32 .route witnessState33 := by
  exact ⟨witnessStep32, by native_decide⟩

lemma guardedWitnessStep33 :
    (GuardedResponseNetwork.network responseData).Tr witnessState33 .filter witnessState34 := by
  exact ⟨witnessStep33, by native_decide⟩

lemma guardedWitnessStep34 :
    (GuardedResponseNetwork.network responseData).Tr witnessState34 .internalProcessing witnessState35 := by
  exact ⟨witnessStep34, by native_decide⟩

lemma guardedWitnessStep35 :
    (GuardedResponseNetwork.network responseData).Tr witnessState35 .linkTransmit witnessState36 := by
  exact ⟨witnessStep35, by native_decide⟩

lemma guardedWitnessStep36 :
    (GuardedResponseNetwork.network responseData).Tr witnessState36 .internalProcessing witnessState37 := by
  exact ⟨witnessStep36, by native_decide⟩

lemma guardedWitnessStep37 :
    (GuardedResponseNetwork.network responseData).Tr witnessState37 .internalProcessing witnessState38 := by
  exact ⟨witnessStep37, by native_decide⟩

lemma guardedWitnessStep38 :
    (GuardedResponseNetwork.network responseData).Tr witnessState38 .deliver witnessState39 := by
  exact ⟨witnessStep38, by native_decide⟩

theorem positive_delivery_with_early_source_guards :
    (GuardedResponseNetwork.network responseData).MTr witnessState0 witnessActions witnessState39 := by
  exact Cslib.LTS.MTr.stepL guardedWitnessStep0 (Cslib.LTS.MTr.stepL guardedWitnessStep1 (Cslib.LTS.MTr.stepL guardedWitnessStep2 (Cslib.LTS.MTr.stepL guardedWitnessStep3 (Cslib.LTS.MTr.stepL guardedWitnessStep4 (Cslib.LTS.MTr.stepL guardedWitnessStep5 (Cslib.LTS.MTr.stepL guardedWitnessStep6 (Cslib.LTS.MTr.stepL guardedWitnessStep7 (Cslib.LTS.MTr.stepL guardedWitnessStep8 (Cslib.LTS.MTr.stepL guardedWitnessStep9 (Cslib.LTS.MTr.stepL guardedWitnessStep10 (Cslib.LTS.MTr.stepL guardedWitnessStep11 (Cslib.LTS.MTr.stepL guardedWitnessStep12 (Cslib.LTS.MTr.stepL guardedWitnessStep13 (Cslib.LTS.MTr.stepL guardedWitnessStep14 (Cslib.LTS.MTr.stepL guardedWitnessStep15 (Cslib.LTS.MTr.stepL guardedWitnessStep16 (Cslib.LTS.MTr.stepL guardedWitnessStep17 (Cslib.LTS.MTr.stepL guardedWitnessStep18 (Cslib.LTS.MTr.stepL guardedWitnessStep19 (Cslib.LTS.MTr.stepL guardedWitnessStep20 (Cslib.LTS.MTr.stepL guardedWitnessStep21 (Cslib.LTS.MTr.stepL guardedWitnessStep22 (Cslib.LTS.MTr.stepL guardedWitnessStep23 (Cslib.LTS.MTr.stepL guardedWitnessStep24 (Cslib.LTS.MTr.stepL guardedWitnessStep25 (Cslib.LTS.MTr.stepL guardedWitnessStep26 (Cslib.LTS.MTr.stepL guardedWitnessStep27 (Cslib.LTS.MTr.stepL guardedWitnessStep28 (Cslib.LTS.MTr.stepL guardedWitnessStep29 (Cslib.LTS.MTr.stepL guardedWitnessStep30 (Cslib.LTS.MTr.stepL guardedWitnessStep31 (Cslib.LTS.MTr.stepL guardedWitnessStep32 (Cslib.LTS.MTr.stepL guardedWitnessStep33 (Cslib.LTS.MTr.stepL guardedWitnessStep34 (Cslib.LTS.MTr.stepL guardedWitnessStep35 (Cslib.LTS.MTr.stepL guardedWitnessStep36 (Cslib.LTS.MTr.stepL guardedWitnessStep37 (Cslib.LTS.MTr.stepL guardedWitnessStep38 (Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))))))))

lemma initial_guarded_state_is_safe : GuardedResponseNetwork.Safe responseData witnessState0 := by
  exact ⟨witness_initial_stack, trivial, by native_decide⟩

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
