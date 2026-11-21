import TDN.Deployments.SnapshotByteEncryptionOrder
import TDN.Deployments.ProfileShared_IsolationTrace
import TDN.Models.BlockRepliesToLocalCiphertext
open TDN DataPlaneForwarding
open TDN.Deployments.ProfileShared_EnclaveIsolation
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

abbrev OriginByte := ReassemblyOrigins.ByteOrigin Nat Nat Nat
def tracked : OriginByte := ⟨65, 1, 1⟩

lemma path_to_black : (lts config).MTr witnessState0 (witnessActions.take 33) witnessState33 := by
  exact (Cslib.LTS.MTr.stepL witness_step0 (Cslib.LTS.MTr.stepL witness_step1 (Cslib.LTS.MTr.stepL witness_step2 (Cslib.LTS.MTr.stepL witness_step3 (Cslib.LTS.MTr.stepL witness_step4 (Cslib.LTS.MTr.stepL witness_step5 (Cslib.LTS.MTr.stepL witness_step6 (Cslib.LTS.MTr.stepL witness_step7 (Cslib.LTS.MTr.stepL witness_step8 (Cslib.LTS.MTr.stepL witness_step9 (Cslib.LTS.MTr.stepL witness_step10 (Cslib.LTS.MTr.stepL witness_step11 (Cslib.LTS.MTr.stepL witness_step12 (Cslib.LTS.MTr.stepL witness_step13 (Cslib.LTS.MTr.stepL witness_step14 (Cslib.LTS.MTr.stepL witness_step15 (Cslib.LTS.MTr.stepL witness_step16 (Cslib.LTS.MTr.stepL witness_step17 (Cslib.LTS.MTr.stepL witness_step18 (Cslib.LTS.MTr.stepL witness_step19 (Cslib.LTS.MTr.stepL witness_step20 (Cslib.LTS.MTr.stepL witness_step21 (Cslib.LTS.MTr.stepL witness_step22 (Cslib.LTS.MTr.stepL witness_step23 (Cslib.LTS.MTr.stepL witness_step24 (Cslib.LTS.MTr.stepL witness_step25 (Cslib.LTS.MTr.stepL witness_step26 (Cslib.LTS.MTr.stepL witness_step27 (Cslib.LTS.MTr.stepL witness_step28 (Cslib.LTS.MTr.stepL witness_step29 (Cslib.LTS.MTr.stepL witness_step30 (Cslib.LTS.MTr.stepL witness_step31 (Cslib.LTS.MTr.stepL witness_step32 Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))

lemma byte_reaches_black : ∃ actions, (ResponseByteFlows.system (lts config)
    (UniformDomainResponses.responseConfig config
      TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners)
    (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions
      [⟨.network witnessState33, [tracked]⟩] := by
  have path := EncryptedResponseGuards.network_trace_in_response_system (lts config)
    (UniformDomainResponses.responseConfig config
      TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners) path_to_black
  have lifted := ByteFlows.network_trace_on_one_carrier _
    (ResponseByteFlows.source (Requirements.RedByteOrigin config redSources))
    (ResponseByteFlows.assembly PlaintextAssembly) [tracked] path
  refine ⟨_, Cslib.LTS.MTr.stepL (ByteFlows.ByteFlowStep.inject ?_) lifted⟩
  intro byte member
  simp only [List.mem_singleton] at member
  subst byte
  change Requirements.RedByteOrigin config redSources witnessState0 tracked
  unfold Requirements.RedByteOrigin Requirements.RedPayloadOrigin
  native_decide
example : ∃ start labels, Requirements.RedByteOrigin config redSources start tracked ∧
    Requirements.BytePathOrderedEncryptions config
      TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners
      11 2 (.network start) labels (.network witnessState33) := by
  obtain ⟨actions, run⟩ := byte_reaches_black
  exact every_assembled_black_byte_has_inner_before_outer run witnessState33 [tracked]
    (by simp) rfl (by native_decide) tracked (by simp)
