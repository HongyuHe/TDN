import TDN.Import.Command
import TDN.Targets.Cryptography
import TDN.Semantics.LinkProtection

namespace TDN.Imported.FinalMACsecRuntime
open LinkProtection

def ports : List (String × Config) := [("eap-tls-forward-v18/P0", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 }), ("eap-tls-forward-v18/P1", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 }), ("eap-tls-reverse-v18/P0", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 }), ("eap-tls-reverse-v18/P1", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 })]
tdn_data installedAssociations : List (String × Nat) from "../../evidence/lean/FinalMACsecRuntime.json" ["TDN.Imported.FinalMACsecRuntime.installedAssociations"]

lemma installed_association_coverage : ∀ port ∈ ports,
    ∃ binding ∈ installedAssociations, binding.1 = port.1 := by
  unfold ports installedAssociations
  decide

lemma local_settings : ∀ port ∈ ports, port.2.protectFrames = true ∧
    port.2.encryptFrames = true ∧ port.2.confidentialityOffset = 0 := by
  unfold ports
  decide

theorem every_runtime_data_emission_is_encrypted (port : String × Config)
    (member : port ∈ ports) (association : Option Nat) (body : Nat) (wire : WireFrame Nat)
    (emitted : transmit port.2 association body = some wire) : FullyEncrypted wire := by
  obtain ⟨protect, encrypt, zero⟩ := local_settings port member
  exact every_emitted_frame_is_encrypted port.2 protect encrypt zero association body wire emitted

theorem every_runtime_data_port_blocks_absent_sa (port : String × Config)
    (member : port ∈ ports) (body : Nat) : transmit port.2 none body = none :=
  absent_sa_blocks_data port.2 (local_settings port member).1 body

lemma runtime_ports_enabled : ∀ port ∈ ports, port.2.controlledPortEnabled = true := by
  unfold ports
  decide

theorem runtime_ports_permit_encrypted_emission (port : String × Config)
    (member : port ∈ ports) (association body : Nat) :
    transmit port.2 (some association) body =
      some (.encrypted association port.2.confidentialityOffset body) :=
  enabled_sa_emits_encryption port.2 (runtime_ports_enabled port member)
    (local_settings port member).1 (local_settings port member).2.1 association body

theorem observed_sa_allows_data (port : String × Config) (member : port ∈ ports) (body : Nat) :
    ∃ binding ∈ installedAssociations, binding.1 = port.1 ∧
      transmit port.2 (some binding.2) body =
        some (.encrypted binding.2 port.2.confidentialityOffset body) := by
  obtain ⟨binding, installed, identity⟩ := installed_association_coverage port member
  exact ⟨binding, installed, identity,
    runtime_ports_permit_encrypted_emission port member binding.2 body⟩

tdn_data negotiatedSuite : Targets.AlgorithmSuite from "../../evidence/lean/FinalMACsecRuntime.json" ["TDN.Imported.FinalMACsecRuntime.negotiatedSuite"]

lemma negotiated_suite_cnsa2 : Targets.CNSA2 negotiatedSuite := by
  unfold Targets.CNSA2 Targets.ApprovedIntegrity negotiatedSuite
  decide

theorem observed_algorithms_satisfy_cnsa_choice :
    Targets.msc_cnss_algorithm_policy [negotiatedSuite] := by
  intro suite member
  have same : suite = negotiatedSuite := by simpa using member
  subst suite
  exact Or.inr negotiated_suite_cnsa2

end TDN.Imported.FinalMACsecRuntime
