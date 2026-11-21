import TDN.Import.ForwardingTrace
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option linter.unusedSimpArgs false

replay_forwarding_trace config from "../../data/evidence/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/DualStack_RedV4_GrayV4_BlackV4_V13_SampleTrace.json"

lemma witness_initial_stack : EncapStackConsistent config expectedEncapStack witnessState0 := by
  exact ⟨⟨⟨rfl, rfl, Or.inl rfl, rfl⟩, rfl⟩, rfl⟩

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
