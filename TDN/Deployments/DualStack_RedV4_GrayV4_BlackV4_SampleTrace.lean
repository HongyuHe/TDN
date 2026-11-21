import TDN.Import.ForwardingTrace
import TDN.Models.IpsecEgressCorrespondence
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option linter.unusedSimpArgs false

replay_forwarding_trace config from "../../data/evidence/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/DualStack_RedV4_GrayV4_BlackV4_SampleTrace.json"

lemma witness_initial_stack : EncapStackConsistent config expectedEncapStack witnessState0 := by
  exact ⟨⟨⟨rfl, rfl, Or.inl rfl, rfl⟩, rfl⟩, rfl⟩

theorem recorded_outer_esp_egress (model : MultiProtocolForwarding.TunnelForwardingModel)
    (ip : model.ip = config) (processing : MultiProtocolForwarding.HeaderProcessing)
    (headers : model.headerProcessing = some processing)
    (links : ∀ a b, model.ip.link a b → model.physicalLink a b) :
    (MultiProtocolForwarding.lts model).MTr (IpsecEgress.asTunnelState witnessState14)
      [.route, .linkTransmit] (IpsecEgress.asTunnelState witnessState16) := by
  apply IpsecEgress.egress_trace model processing headers links (actions := [.route, .transmit])
  rw [ip]
  exact .stepL ⟨by native_decide, rfl, witness_step14⟩
    (.stepL ⟨by native_decide, witness_step15⟩ .refl)

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4
