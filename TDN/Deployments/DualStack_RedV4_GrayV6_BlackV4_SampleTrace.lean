import TDN.Import.ForwardingTrace
import TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option linter.unusedSimpArgs false

replay_forwarding_trace config from "../../data/evidence/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/DualStack_RedV4_GrayV6_BlackV4_SampleTrace.json"

lemma witness_immediate_header_checks : witnessState8.frame.packet.ipv6NextHeader ∈ [6, 17, 50, 58] ∧ witnessState10.frame.packet.ipv6NextHeader ∈ [6, 17, 50, 58] ∧ witnessState31.frame.packet.ipv6NextHeader ∈ [6, 17, 50, 58] ∧ True := by native_decide

lemma witness_initial_stack : EncapStackConsistent config expectedEncapStack witnessState0 := by
  exact ⟨⟨⟨rfl, rfl, Or.inl rfl, rfl⟩, rfl⟩, rfl⟩

end TDN.Deployments.DualStack_RedV4_GrayV6_BlackV4
