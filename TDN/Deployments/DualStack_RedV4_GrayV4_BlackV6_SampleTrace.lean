import TDN.Import.ForwardingTrace
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option linter.unusedSimpArgs false

replay_forwarding_trace config from "../../data/evidence/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/DualStack_RedV4_GrayV4_BlackV6_SampleTrace.json"

lemma witness_immediate_header_checks : witnessState14.frame.packet.ipv6NextHeader ∈ [6, 17, 50, 58] ∧ witnessState26.frame.packet.ipv6NextHeader ∈ [6, 17, 50, 58] ∧ True := by native_decide

lemma witness_initial_stack : EncapStackConsistent config expectedEncapStack witnessState0 := by
  exact ⟨⟨⟨rfl, rfl, Or.inl rfl, rfl⟩, rfl⟩, rfl⟩

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV6
