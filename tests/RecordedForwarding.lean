import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_SampleTrace

open TDN TDN.DataPlaneForwarding
open TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4

private abbrev admits := @RecordedForwarding.admits config
  (fun i j => inferInstanceAs (Decidable ((i, j) ∈ links)))
  (fun i j _ => inferInstanceAs (Decidable ((i, j) ∈ switches)))
  (fun i a => inferInstanceAs (Decidable (a ∈ (deviceAt devices (ifaceAt ifaces i).owner).localAddresses)))

example : admits witnessState14 .route witnessState15 = true := by native_decide
example : admits witnessState14 .linkTransmit witnessState15 = false := by native_decide
example : admits witnessState15 .linkTransmit { witnessState16 with iface := 100000 } = false := by native_decide
example : admits witnessState13 .encrypt
    { witnessState14 with frame := { witnessState14.frame with encapLayers := [] } } = false := by native_decide

example :
    let model : MultiProtocolForwarding.TunnelForwardingModel := {
      ip := config, macIfaces := [], carriers := [], bridge := fun _ _ => False,
      physicalLink := config.link, headerProcessing := some ⟨fun _ => 64, fun _ => 64⟩ }
    (MultiProtocolForwarding.lts model).MTr (IpsecEgress.asTunnelState witnessState14)
      [.route, .linkTransmit] (IpsecEgress.asTunnelState witnessState16) :=
  recorded_outer_esp_egress _ rfl _ rfl (fun _ _ h => h)
