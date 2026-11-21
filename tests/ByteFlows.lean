import TDN.Deployments.SnapshotByteReplyChecks
import TDN.Models.BlockRepliesToLocalCiphertext
import TDN.Deployments.SnapshotByteEnclaveIsolation
import TDN.Deployments.ProfileShared_IsolationTrace
open TDN DataPlaneForwarding
open TDN.Deployments.ProfileShared_EnclaveIsolation

abbrev B := ReassemblyOrigins.ByteOrigin Nat Nat Nat
def body : List B := [⟨65, 1, 1⟩, ⟨66, 1, 1⟩]
def byteSystem : Cslib.LTS (List (ByteFlows.PacketBytes DataPlaneForwarding.ForwardingState B)) (ByteFlows.ByteFlowAction DataPlaneForwarding.ForwardingAction) := ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
  PlaintextAssembly

lemma origin_bytes : ∀ byte ∈ body, Requirements.RedByteOrigin config redSources witnessState0 byte := by
  unfold body Requirements.RedByteOrigin Requirements.RedPayloadOrigin
  native_decide
lemma prefix_path : (lts config).MTr witnessState0 (witnessActions.take 4) witnessState4 := by
  exact Cslib.LTS.MTr.stepL witness_step0 (Cslib.LTS.MTr.stepL witness_step1 (Cslib.LTS.MTr.stepL witness_step2 (Cslib.LTS.MTr.stepL witness_step3 (Cslib.LTS.MTr.refl))))

lemma suffix_path : (lts config).MTr witnessState4 (witnessActions.drop 4) witnessState60 := by
  exact Cslib.LTS.MTr.stepL witness_step4 (Cslib.LTS.MTr.stepL witness_step5 (Cslib.LTS.MTr.stepL witness_step6 (Cslib.LTS.MTr.stepL witness_step7 (Cslib.LTS.MTr.stepL witness_step8 (Cslib.LTS.MTr.stepL witness_step9 (Cslib.LTS.MTr.stepL witness_step10 (Cslib.LTS.MTr.stepL witness_step11 (Cslib.LTS.MTr.stepL witness_step12 (Cslib.LTS.MTr.stepL witness_step13 (Cslib.LTS.MTr.stepL witness_step14 (Cslib.LTS.MTr.stepL witness_step15 (Cslib.LTS.MTr.stepL witness_step16 (Cslib.LTS.MTr.stepL witness_step17 (Cslib.LTS.MTr.stepL witness_step18 (Cslib.LTS.MTr.stepL witness_step19 (Cslib.LTS.MTr.stepL witness_step20 (Cslib.LTS.MTr.stepL witness_step21 (Cslib.LTS.MTr.stepL witness_step22 (Cslib.LTS.MTr.stepL witness_step23 (Cslib.LTS.MTr.stepL witness_step24 (Cslib.LTS.MTr.stepL witness_step25 (Cslib.LTS.MTr.stepL witness_step26 (Cslib.LTS.MTr.stepL witness_step27 (Cslib.LTS.MTr.stepL witness_step28 (Cslib.LTS.MTr.stepL witness_step29 (Cslib.LTS.MTr.stepL witness_step30 (Cslib.LTS.MTr.stepL witness_step31 (Cslib.LTS.MTr.stepL witness_step32 (Cslib.LTS.MTr.stepL witness_step33 (Cslib.LTS.MTr.stepL witness_step34 (Cslib.LTS.MTr.stepL witness_step35 (Cslib.LTS.MTr.stepL witness_step36 (Cslib.LTS.MTr.stepL witness_step37 (Cslib.LTS.MTr.stepL witness_step38 (Cslib.LTS.MTr.stepL witness_step39 (Cslib.LTS.MTr.stepL witness_step40 (Cslib.LTS.MTr.stepL witness_step41 (Cslib.LTS.MTr.stepL witness_step42 (Cslib.LTS.MTr.stepL witness_step43 (Cslib.LTS.MTr.stepL witness_step44 (Cslib.LTS.MTr.stepL witness_step45 (Cslib.LTS.MTr.stepL witness_step46 (Cslib.LTS.MTr.stepL witness_step47 (Cslib.LTS.MTr.stepL witness_step48 (Cslib.LTS.MTr.stepL witness_step49 (Cslib.LTS.MTr.stepL witness_step50 (Cslib.LTS.MTr.stepL witness_step51 (Cslib.LTS.MTr.stepL witness_step52 (Cslib.LTS.MTr.stepL witness_step53 (Cslib.LTS.MTr.stepL witness_step54 (Cslib.LTS.MTr.stepL witness_step55 (Cslib.LTS.MTr.stepL witness_step56 (Cslib.LTS.MTr.stepL witness_step57 (Cslib.LTS.MTr.stepL witness_step58 (Cslib.LTS.MTr.stepL witness_step59 (Cslib.LTS.MTr.refl))))))))))))))))))))))))))))))))))))))))))))))))))))))))

-- Illustrative byte values use the actual imported network path. Assembly occurs
-- at the Inner Red ingress, before subsequent filtering and both encryption layers.
example : ∃ actions, byteSystem.MTr [] actions [⟨witnessState60, body⟩] := by
  have inject : byteSystem.Tr [] .inject [⟨witnessState0, body⟩] :=
    ByteFlows.ByteFlowStep.inject origin_bytes
  have prefixRun := ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.RedByteOrigin config redSources) PlaintextAssembly body prefix_path
  have splitStep : byteSystem.Tr [⟨witnessState4, body⟩] .split
      [⟨witnessState4, [⟨65, 1, 1⟩]⟩, ⟨witnessState4, [⟨66, 1, 1⟩]⟩] :=
    ByteFlows.ByteFlowStep.split (network := lts config)
      (origin := Requirements.RedByteOrigin (Byte := Nat) config redSources)
      (canAssemble := PlaintextAssembly) (state := witnessState4) (bytes := body)
      (earlier := []) (later := [])
      (chunks := [[⟨65, 1, 1⟩], [⟨66, 1, 1⟩]]) rfl
  have compatible : PlaintextAssembly witnessState4 witnessState4 := by
    simp [PlaintextAssembly, witnessState4, IpsecFrame.encapLayerIds]
  have assemblyStep : byteSystem.Tr
      [⟨witnessState4, [⟨65, 1, 1⟩]⟩, ⟨witnessState4, [⟨66, 1, 1⟩]⟩] .assemble
      [⟨witnessState4, body⟩] := by
    apply ByteFlows.ByteFlowStep.assemble (network := lts config)
      (origin := Requirements.RedByteOrigin (Byte := Nat) config redSources)
      (canAssemble := PlaintextAssembly) (after := witnessState4)
      (earlier := []) (later := [])
      (packets := [⟨witnessState4, [⟨65, 1, 1⟩]⟩, ⟨witnessState4, [⟨66, 1, 1⟩]⟩])
    · simp
    · intro packet member
      simp only [List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl <;> exact compatible
  have suffixRun := ByteFlows.network_trace_on_one_carrier (lts config)
    (Requirements.RedByteOrigin config redSources) PlaintextAssembly body suffix_path
  exact ⟨_, Cslib.LTS.MTr.stepL inject
    (Cslib.LTS.MTr.comp _ prefixRun
      (Cslib.LTS.MTr.stepL splitStep (Cslib.LTS.MTr.stepL assemblyStep suffixRun)))⟩

-- Ciphertext is never converted into plaintext by the plaintext assembly operation.
example : ¬ PlaintextAssembly witnessState10 witnessState4 := by
  simp [PlaintextAssembly, witnessState10, witnessState4, IpsecFrame.encapLayerIds]

-- Assembly itself does not inspect domain or packet-identity annotations.
def noMoves : Cslib.LTS Unit Unit := ⟨fun _ _ _ => False⟩
def source (_s : Unit) (b : B) : Prop := b.domain = 1
def atSamePlace (_ _ : Unit) : Prop := True

example : (ByteFlows.lts noMoves source atSamePlace).Tr
    [⟨(), [⟨65, 1, 101⟩]⟩, ⟨(), [⟨66, 1, 202⟩]⟩] .assemble
    [⟨(), [⟨65, 1, 101⟩, ⟨66, 1, 202⟩]⟩] := by
  exact ByteFlows.ByteFlowStep.assemble (network := noMoves) (origin := source) (canAssemble := atSamePlace)
    (earlier := []) (later := [])
    (packets := [⟨(), [⟨65, 1, 101⟩]⟩, ⟨(), [⟨66, 1, 202⟩]⟩])
    (by simp) (by intros; trivial)

-- The useful path remains available in the combined gateway-response/byte-flow model.
example : ∃ actions, (ResponseByteFlows.system (lts config)
    (Requirements.nativeKernelResponses config TDN.Deployments.ProfileShared_DataPlane.responseGateways)
    (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions
      [⟨.network witnessState60, body⟩] := by
  have path := EncryptedResponseGuards.network_trace_in_response_system (lts config)
    (Requirements.nativeKernelResponses config TDN.Deployments.ProfileShared_DataPlane.responseGateways)
    positive_delivery_forwarding
  have lifted := ByteFlows.network_trace_on_one_carrier
    (KernelResponses.lts (lts config)
      (Requirements.nativeKernelResponses config TDN.Deployments.ProfileShared_DataPlane.responseGateways))
    (ResponseByteFlows.source (Requirements.RedByteOrigin config redSources))
    (ResponseByteFlows.assembly PlaintextAssembly) body path
  exact ⟨_, Cslib.LTS.MTr.stepL (ByteFlows.ByteFlowStep.inject origin_bytes) lifted⟩

-- Packet-list order cannot prevent selection of interleaved fragments for assembly.
example : (ByteFlows.lts noMoves source atSamePlace).Tr
    [⟨(), [⟨65, 1, 101⟩]⟩, ⟨(), [⟨90, 1, 999⟩]⟩, ⟨(), [⟨66, 1, 202⟩]⟩] .permute
    [⟨(), [⟨65, 1, 101⟩]⟩, ⟨(), [⟨66, 1, 202⟩]⟩, ⟨(), [⟨90, 1, 999⟩]⟩] := by
  exact ByteFlows.ByteFlowStep.permute (List.Perm.cons _ (List.Perm.swap _ _ []))

-- A copied prefix remains pending while the original packet can continue.
example : byteSystem.Tr [⟨witnessState4, body⟩] .copy
    [⟨witnessState4, body⟩, ⟨witnessState4, [⟨65, 1, 1⟩]⟩] := by
  apply ByteFlows.ByteFlowStep.copy (packet := ⟨witnessState4, body⟩)
  · simp
  · intro byte member
    simp only [List.mem_singleton] at member
    subst byte
    simp [body]
