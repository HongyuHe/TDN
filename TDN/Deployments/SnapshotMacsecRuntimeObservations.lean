import TDN.Import.SnapshotLoader
import TDN.Models.MacsecPortProtection

namespace TDN.Deployments.SnapshotMacsecRuntimeObservations
open LinkProtection

def ifaces : List (String × Config) := [("eap-tls-forward-v14/P0", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 }), ("eap-tls-forward-v14/P1", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 }), ("eap-tls-reverse-v14/P0", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 }), ("eap-tls-reverse-v14/P1", { controlledPortEnabled := true, protectFrames := true, encryptFrames := true, confidentialityOffset := 0 })]
load_network_records installedAssociations : List (String × Nat) from "../../data/evidence/SnapshotMacsecRuntimeObservations.json" ["TDN.Deployments.SnapshotMacsecRuntimeObservations.installedAssociations"]

lemma installed_association_coverage : ∀ iface ∈ ifaces,
    ∃ binding ∈ installedAssociations, binding.1 = iface.1 := by
  unfold ifaces installedAssociations
  native_decide
lemma local_settings : ∀ iface ∈ ifaces, iface.2.protectFrames = true ∧
    iface.2.encryptFrames = true ∧ iface.2.confidentialityOffset = 0 := by
  unfold ifaces
  native_decide
theorem every_runtime_data_emission_is_encrypted (iface : String × Config)
    (member : iface ∈ ifaces) (association : Option Nat) (body : Nat) (wire : WireFrame Nat)
    (emitted : transmit iface.2 association body = some wire) : FullyEncrypted wire := by
  obtain ⟨protect, encrypt, zero⟩ := local_settings iface member
  exact every_emitted_frame_is_encrypted iface.2 protect encrypt zero association body wire emitted

theorem every_runtime_data_iface_blocks_absent_sa (iface : String × Config)
    (member : iface ∈ ifaces) (body : Nat) : transmit iface.2 none body = none :=
  absent_sa_blocks_data iface.2 (local_settings iface member).1 body

lemma runtime_ifaces_enabled : ∀ iface ∈ ifaces, iface.2.controlledPortEnabled = true := by
  unfold ifaces
  native_decide
theorem runtime_ifaces_permit_encrypted_emission (iface : String × Config)
    (member : iface ∈ ifaces) (association body : Nat) :
    transmit iface.2 (some association) body =
      some (.encrypted association iface.2.confidentialityOffset body) :=
  enabled_sa_emits_encryption iface.2 (runtime_ifaces_enabled iface member)
    (local_settings iface member).1 (local_settings iface member).2.1 association body

theorem observed_sa_allows_data (iface : String × Config) (member : iface ∈ ifaces) (body : Nat) :
    ∃ binding ∈ installedAssociations, binding.1 = iface.1 ∧
      transmit iface.2 (some binding.2) body =
        some (.encrypted binding.2 iface.2.confidentialityOffset body) := by
  obtain ⟨binding, installed, identity⟩ := installed_association_coverage iface member
  exact ⟨binding, installed, identity,
    runtime_ifaces_permit_encrypted_emission iface member binding.2 body⟩

end TDN.Deployments.SnapshotMacsecRuntimeObservations
