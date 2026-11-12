import TDN.Models.BlackTransitPayloadOpacity
import TDN.Deployments.ProfileShared_SampleTrace

open TDN DataPlaneForwarding
open TDN.Deployments.ProfileShared_DataPlane

private theorem blackTransit : (transit config).MTr witnessState33
    [.linkTransmit, .internalProcessing, .route, .filter, .internalProcessing, .linkTransmit] witnessState39 := by
  exact .stepL ⟨witnessStep33, by native_decide⟩
    (.stepL ⟨witnessStep34, by native_decide⟩
      (.stepL ⟨witnessStep35, by native_decide⟩
        (.stepL ⟨witnessStep36, by native_decide⟩
          (.stepL ⟨witnessStep37, by native_decide⟩
            (.stepL ⟨witnessStep38, by native_decide⟩ .refl)))))

/-- The actual Black router/firewall path inspects the same visible ESP packet
for every replacement of the hidden payload and envelope metadata. -/
example (payload domain : Nat) (encapLayers : List EncapHeaderLayer) :
    (lts config).MTr (withHiddenContent payload domain encapLayers witnessState33)
      [.linkTransmit, .internalProcessing, .route, .filter, .internalProcessing, .linkTransmit]
      (withHiddenContent payload domain encapLayers witnessState39) :=
  transit_path_ignores_hidden_content config payload domain encapLayers blackTransit

example : ¬ TransitAction .decrypt := by
  simp [TransitAction]

example : ¬ TransitAction .encrypt := by
  simp [TransitAction]

example : ¬ TransitAction .deliver := by
  simp [TransitAction]
