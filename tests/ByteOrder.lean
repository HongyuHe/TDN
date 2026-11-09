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
  exact (Cslib.LTS.MTr.stepL witnessStep0 (Cslib.LTS.MTr.stepL witnessStep1 (Cslib.LTS.MTr.stepL witnessStep2 (Cslib.LTS.MTr.stepL witnessStep3 (Cslib.LTS.MTr.stepL witnessStep4 (Cslib.LTS.MTr.stepL witnessStep5 (Cslib.LTS.MTr.stepL witnessStep6 (Cslib.LTS.MTr.stepL witnessStep7 (Cslib.LTS.MTr.stepL witnessStep8 (Cslib.LTS.MTr.stepL witnessStep9 (Cslib.LTS.MTr.stepL witnessStep10 (Cslib.LTS.MTr.stepL witnessStep11 (Cslib.LTS.MTr.stepL witnessStep12 (Cslib.LTS.MTr.stepL witnessStep13 (Cslib.LTS.MTr.stepL witnessStep14 (Cslib.LTS.MTr.stepL witnessStep15 (Cslib.LTS.MTr.stepL witnessStep16 (Cslib.LTS.MTr.stepL witnessStep17 (Cslib.LTS.MTr.stepL witnessStep18 (Cslib.LTS.MTr.stepL witnessStep19 (Cslib.LTS.MTr.stepL witnessStep20 (Cslib.LTS.MTr.stepL witnessStep21 (Cslib.LTS.MTr.stepL witnessStep22 (Cslib.LTS.MTr.stepL witnessStep23 (Cslib.LTS.MTr.stepL witnessStep24 (Cslib.LTS.MTr.stepL witnessStep25 (Cslib.LTS.MTr.stepL witnessStep26 (Cslib.LTS.MTr.stepL witnessStep27 (Cslib.LTS.MTr.stepL witnessStep28 (Cslib.LTS.MTr.stepL witnessStep29 (Cslib.LTS.MTr.stepL witnessStep30 (Cslib.LTS.MTr.stepL witnessStep31 (Cslib.LTS.MTr.stepL witnessStep32 Cslib.LTS.MTr.refl)))))))))))))))))))))))))))))))))

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
  refine ⟨_, Cslib.LTS.MTr.stepL (ByteFlows.Step.inject ?_) lifted⟩
  intro byte member
  simp only [List.mem_singleton] at member
  subst byte
  change Requirements.RedByteOrigin config redSources witnessState0 tracked
  unfold Requirements.RedByteOrigin Requirements.RedPayloadOrigin
  decide

example : ∃ start labels, Requirements.RedByteOrigin config redSources start tracked ∧
    Requirements.BytePathOrderedEncryptions config
      TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners
      11 2 (.network start) labels (.network witnessState33) := by
  obtain ⟨actions, run⟩ := byte_reaches_black
  exact every_assembled_black_byte_has_inner_before_outer run witnessState33 [tracked]
    (by simp) rfl (by decide) tracked (by simp)
