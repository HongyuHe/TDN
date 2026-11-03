import TDN.Targets.CompleteMACsecKeyGeneration

namespace TDN.Imported.CompleteMACsecKeyGeneration
open Targets.Complete Compliance

def key : MACsecKey :=
  ⟨"CAK-A-B", .generated "KGS", List.replicate 16 1, "KGS", false⟩

def tunnel : Tunnel :=
  ⟨"tunnel-A-B", .inner, .macsec, "INNER-A", "INNER-B", "CAK-A-B", false, false⟩

def pair : MACsecServerPair :=
  ⟨"INNER-A", "INNER-B", 0, 1, none⟩

def provisioning : KeyProvisioning :=
  ⟨"security-admin", "CAK-A-B", "KGS", 1, [("INNER-A", 2), ("INNER-B", 3)]⟩

def records : KeyGenerationRecords :=
  ⟨["KGS"], ["security-admin"], []⟩

def configured (d : Deployment) : Deployment :=
  { d with tunnels := [tunnel], centralManagementSite := none }

lemma pair_and_provisioning_checks (d : Deployment) :
    keyGenerationChecked (configured d) [key] [pair] [provisioning] records = true := by
  rfl

lemma complete_RG027_under_named_approvals (d : Deployment)
    (generator : d.authority.nsaApprovedGenerator "KGS")
    (administrator : d.authority.securityAdministrator "security-admin") :
    msc_macsec_key_generation_and_server (configured d) [key] [pair] [provisioning]
      (fun _ _ => False) := by
  apply macsec_key_generation_from_checked_records
    (configured d) [key] [pair] [provisioning] records
    (fun _ _ => False) (pair_and_provisioning_checks d)
  · simpa [records, configured] using generator
  · simpa [records, configured] using administrator
  · simp [records]

lemma short_ckn_rejected (d : Deployment) :
    keyGenerationChecked (configured d) [{ key with ckn := List.replicate 15 1 }]
      [pair] [provisioning] records = false := by
  rfl

lemma fallback_rejected (d : Deployment) :
    keyGenerationChecked (configured d) [{ key with fallbackEnabled := true }]
      [pair] [provisioning] records = false := by
  rfl

lemma premature_application_rejected (d : Deployment) :
    keyGenerationChecked (configured d) [key] [pair]
      [{ provisioning with applications := [("INNER-A", 0), ("INNER-B", 3)] }]
      records = false := by
  rfl

lemma missing_peer_pair_rejected (d : Deployment) :
    keyGenerationChecked (configured d) [key] [] [provisioning] records = false := by
  rfl

lemma duplicate_server_priority_rejected (d : Deployment) :
    keyGenerationChecked (configured d) [key] [{ pair with secondValue := 0 }]
      [provisioning] records = false := by
  rfl

lemma eap_derivation_record_checked (d : Deployment) :
    keyGenerationChecked (configured d) [{ key with cakOrigin := .eapDerived "MSK" }]
      [pair] [] { records with eapDerivations := [("CAK-A-B", "KGS")] } = true := by
  rfl

lemma empty_master_session_rejected (d : Deployment) :
    keyGenerationChecked (configured d) [{ key with cakOrigin := .eapDerived "" }]
      [pair] [] { records with eapDerivations := [("CAK-A-B", "KGS")] } = false := by
  rfl

end TDN.Imported.CompleteMACsecKeyGeneration
