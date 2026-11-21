import TDN.Import.SnapshotLoader
import TDN.Models.SourceGuardedAutoReplyNetwork
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13_ReplyGuards

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
open DataPlaneForwarding
set_option maxRecDepth 100000

load_network_records responseData : GuardedResponseNetwork.Data from "../../data/evidence/DualStack_RedV4_GrayV4_BlackV4_V13_ReplyForwarding.json" ["TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13.responseData"]

lemma response_default_checks : ∀ guard ∈ responseSourceGuards,
    (deviceAt devices guard.1).outputFallback = .deny := by native_decide

theorem gateway_response_traces_keep_stack
    {before after : DataPlaneForwarding.ForwardingState} {actions : List (KernelResponses.ReplyAction DataPlaneForwarding.ForwardingAction)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (GuardedResponseNetwork.responseConfig responseData)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    EncapStackConsistent config expectedEncapStack after :=
  GuardedResponseNetwork.all_guarded_response_traces_preserve_stack responseData
    local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered
    response_default_checks run initial

lemma guarded_witness_step0 :
    (GuardedResponseNetwork.network responseData).Tr witnessState0 .route witnessState1 := by
  exact ⟨witness_step0, by native_decide⟩

lemma guarded_witness_step1 :
    (GuardedResponseNetwork.network responseData).Tr witnessState1 .filter witnessState2 := by
  exact ⟨witness_step1, by native_decide⟩

lemma guarded_witness_step2 :
    (GuardedResponseNetwork.network responseData).Tr witnessState2 .internalProcessing witnessState3 := by
  exact ⟨witness_step2, by native_decide⟩

lemma guarded_witness_step3 :
    (GuardedResponseNetwork.network responseData).Tr witnessState3 .linkTransmit witnessState4 := by
  exact ⟨witness_step3, by native_decide⟩

lemma guarded_witness_step4 :
    (GuardedResponseNetwork.network responseData).Tr witnessState4 .internalProcessing witnessState5 := by
  exact ⟨witness_step4, by native_decide⟩

lemma guarded_witness_step5 :
    (GuardedResponseNetwork.network responseData).Tr witnessState5 .route witnessState6 := by
  exact ⟨witness_step5, by native_decide⟩

lemma guarded_witness_step6 :
    (GuardedResponseNetwork.network responseData).Tr witnessState6 .filter witnessState7 := by
  exact ⟨witness_step6, by native_decide⟩

lemma guarded_witness_step7 :
    (GuardedResponseNetwork.network responseData).Tr witnessState7 .encrypt witnessState8 := by
  exact ⟨witness_step7, by native_decide⟩

lemma guarded_witness_step8 :
    (GuardedResponseNetwork.network responseData).Tr witnessState8 .route witnessState9 := by
  exact ⟨witness_step8, by native_decide⟩

lemma guarded_witness_step9 :
    (GuardedResponseNetwork.network responseData).Tr witnessState9 .linkTransmit witnessState10 := by
  exact ⟨witness_step9, by native_decide⟩

lemma guarded_witness_step10 :
    (GuardedResponseNetwork.network responseData).Tr witnessState10 .internalProcessing witnessState11 := by
  exact ⟨witness_step10, by native_decide⟩

lemma guarded_witness_step11 :
    (GuardedResponseNetwork.network responseData).Tr witnessState11 .route witnessState12 := by
  exact ⟨witness_step11, by native_decide⟩

lemma guarded_witness_step12 :
    (GuardedResponseNetwork.network responseData).Tr witnessState12 .filter witnessState13 := by
  exact ⟨witness_step12, by native_decide⟩

lemma guarded_witness_step13 :
    (GuardedResponseNetwork.network responseData).Tr witnessState13 .encrypt witnessState14 := by
  exact ⟨witness_step13, by native_decide⟩

lemma guarded_witness_step14 :
    (GuardedResponseNetwork.network responseData).Tr witnessState14 .route witnessState15 := by
  exact ⟨witness_step14, by native_decide⟩

lemma guarded_witness_step15 :
    (GuardedResponseNetwork.network responseData).Tr witnessState15 .linkTransmit witnessState16 := by
  exact ⟨witness_step15, by native_decide⟩

lemma guarded_witness_step16 :
    (GuardedResponseNetwork.network responseData).Tr witnessState16 .internalProcessing witnessState17 := by
  exact ⟨witness_step16, by native_decide⟩

lemma guarded_witness_step17 :
    (GuardedResponseNetwork.network responseData).Tr witnessState17 .route witnessState18 := by
  exact ⟨witness_step17, by native_decide⟩

lemma guarded_witness_step18 :
    (GuardedResponseNetwork.network responseData).Tr witnessState18 .filter witnessState19 := by
  exact ⟨witness_step18, by native_decide⟩

lemma guarded_witness_step19 :
    (GuardedResponseNetwork.network responseData).Tr witnessState19 .internalProcessing witnessState20 := by
  exact ⟨witness_step19, by native_decide⟩

lemma guarded_witness_step20 :
    (GuardedResponseNetwork.network responseData).Tr witnessState20 .linkTransmit witnessState21 := by
  exact ⟨witness_step20, by native_decide⟩

lemma guarded_witness_step21 :
    (GuardedResponseNetwork.network responseData).Tr witnessState21 .internalProcessing witnessState22 := by
  exact ⟨witness_step21, by native_decide⟩

lemma guarded_witness_step22 :
    (GuardedResponseNetwork.network responseData).Tr witnessState22 .route witnessState23 := by
  exact ⟨witness_step22, by native_decide⟩

lemma guarded_witness_step23 :
    (GuardedResponseNetwork.network responseData).Tr witnessState23 .filter witnessState24 := by
  exact ⟨witness_step23, by native_decide⟩

lemma guarded_witness_step24 :
    (GuardedResponseNetwork.network responseData).Tr witnessState24 .internalProcessing witnessState25 := by
  exact ⟨witness_step24, by native_decide⟩

lemma guarded_witness_step25 :
    (GuardedResponseNetwork.network responseData).Tr witnessState25 .linkTransmit witnessState26 := by
  exact ⟨witness_step25, by native_decide⟩

lemma guarded_witness_step26 :
    (GuardedResponseNetwork.network responseData).Tr witnessState26 .decrypt witnessState27 := by
  exact ⟨witness_step26, by native_decide⟩

lemma guarded_witness_step27 :
    (GuardedResponseNetwork.network responseData).Tr witnessState27 .route witnessState28 := by
  exact ⟨witness_step27, by native_decide⟩

lemma guarded_witness_step28 :
    (GuardedResponseNetwork.network responseData).Tr witnessState28 .filter witnessState29 := by
  exact ⟨witness_step28, by native_decide⟩

lemma guarded_witness_step29 :
    (GuardedResponseNetwork.network responseData).Tr witnessState29 .internalProcessing witnessState30 := by
  exact ⟨witness_step29, by native_decide⟩

lemma guarded_witness_step30 :
    (GuardedResponseNetwork.network responseData).Tr witnessState30 .linkTransmit witnessState31 := by
  exact ⟨witness_step30, by native_decide⟩

lemma guarded_witness_step31 :
    (GuardedResponseNetwork.network responseData).Tr witnessState31 .decrypt witnessState32 := by
  exact ⟨witness_step31, by native_decide⟩

lemma guarded_witness_step32 :
    (GuardedResponseNetwork.network responseData).Tr witnessState32 .route witnessState33 := by
  exact ⟨witness_step32, by native_decide⟩

lemma guarded_witness_step33 :
    (GuardedResponseNetwork.network responseData).Tr witnessState33 .filter witnessState34 := by
  exact ⟨witness_step33, by native_decide⟩

lemma guarded_witness_step34 :
    (GuardedResponseNetwork.network responseData).Tr witnessState34 .internalProcessing witnessState35 := by
  exact ⟨witness_step34, by native_decide⟩

lemma guarded_witness_step35 :
    (GuardedResponseNetwork.network responseData).Tr witnessState35 .linkTransmit witnessState36 := by
  exact ⟨witness_step35, by native_decide⟩

lemma guarded_witness_step36 :
    (GuardedResponseNetwork.network responseData).Tr witnessState36 .internalProcessing witnessState37 := by
  exact ⟨witness_step36, by native_decide⟩

lemma guarded_witness_step37 :
    (GuardedResponseNetwork.network responseData).Tr witnessState37 .internalProcessing witnessState38 := by
  exact ⟨witness_step37, by native_decide⟩

lemma guarded_witness_step38 :
    (GuardedResponseNetwork.network responseData).Tr witnessState38 .deliver witnessState39 := by
  exact ⟨witness_step38, by native_decide⟩

theorem positive_delivery_with_early_source_guards :
    (GuardedResponseNetwork.network responseData).MTr witnessState0 witnessActions witnessState39 := by
  exact Cslib.LTS.MTr.stepL guarded_witness_step0 (Cslib.LTS.MTr.stepL guarded_witness_step1 (Cslib.LTS.MTr.stepL guarded_witness_step2 (Cslib.LTS.MTr.stepL guarded_witness_step3 (Cslib.LTS.MTr.stepL guarded_witness_step4 (Cslib.LTS.MTr.stepL guarded_witness_step5 (Cslib.LTS.MTr.stepL guarded_witness_step6 (Cslib.LTS.MTr.stepL guarded_witness_step7 (Cslib.LTS.MTr.stepL guarded_witness_step8 (Cslib.LTS.MTr.stepL guarded_witness_step9 (Cslib.LTS.MTr.stepL guarded_witness_step10 (Cslib.LTS.MTr.stepL guarded_witness_step11 (Cslib.LTS.MTr.stepL guarded_witness_step12 (Cslib.LTS.MTr.stepL guarded_witness_step13 (Cslib.LTS.MTr.stepL guarded_witness_step14 (Cslib.LTS.MTr.stepL guarded_witness_step15 (Cslib.LTS.MTr.stepL guarded_witness_step16 (Cslib.LTS.MTr.stepL guarded_witness_step17 (Cslib.LTS.MTr.stepL guarded_witness_step18 (Cslib.LTS.MTr.stepL guarded_witness_step19 (Cslib.LTS.MTr.stepL guarded_witness_step20 (Cslib.LTS.MTr.stepL guarded_witness_step21 (Cslib.LTS.MTr.stepL guarded_witness_step22 (Cslib.LTS.MTr.stepL guarded_witness_step23 (Cslib.LTS.MTr.stepL guarded_witness_step24 (Cslib.LTS.MTr.stepL guarded_witness_step25 (Cslib.LTS.MTr.stepL guarded_witness_step26 (Cslib.LTS.MTr.stepL guarded_witness_step27 (Cslib.LTS.MTr.stepL guarded_witness_step28 (Cslib.LTS.MTr.stepL guarded_witness_step29 (Cslib.LTS.MTr.stepL guarded_witness_step30 (Cslib.LTS.MTr.stepL guarded_witness_step31 (Cslib.LTS.MTr.stepL guarded_witness_step32 (Cslib.LTS.MTr.stepL guarded_witness_step33 (Cslib.LTS.MTr.stepL guarded_witness_step34 (Cslib.LTS.MTr.stepL guarded_witness_step35 (Cslib.LTS.MTr.stepL guarded_witness_step36 (Cslib.LTS.MTr.stepL guarded_witness_step37 (Cslib.LTS.MTr.stepL guarded_witness_step38 (Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))))))))

lemma initial_guarded_state_is_safe : GuardedResponseNetwork.Safe responseData witnessState0 := by
  exact ⟨witness_initial_stack, trivial, by native_decide⟩

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
