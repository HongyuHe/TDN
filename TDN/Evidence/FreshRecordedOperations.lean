import TDN.Import.Command
import TDN.Targets.RecordedOperations

namespace TDN.Imported.FreshRecordedOperations
open RecordedOperations

/-- Actual configured assignments, with positive authenticated management attempts. -/
tdn_data assignments : List Assignment from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.assignments"]

def partition (aw : String) : Bool := aw == "NM_AW_A1" || aw == "NM_AW_A2" || aw == "NM_AW_B1" || aw == "NM_AW_B2"
lemma assignments_checked : AssignmentChecks assignments partition := by
  unfold AssignmentChecks assignments partition; decide
theorem assigned_workstations_do_not_cross_layers (a b : Assignment)
    (ha : a ∈ assignments) (hb : b ∈ assignments) (different : a.inner ≠ b.inner) :
    a.workstation ≠ b.workstation :=
  administrative_assignments_do_not_share_layers assignments partition assignments_checked a b ha hb different

tdn_data tlsVersions : List String from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.tlsVersions"]

lemma tls_versions_checked : ∀ v ∈ tlsVersions, tlsProtection v = some .tls13 := by
  unfold tlsVersions tlsProtection; decide
theorem observed_management_uses_allowed_protocol (v : String) (member : v ∈ tlsVersions) :
    ∃ p, tlsProtection v = some p ∧ Targets.ApprovedManagementProtocol p :=
  ⟨.tls13, tls_versions_checked v member, recognized_tls_is_allowed v .tls13 (tls_versions_checked v member)⟩

/-- Use windows are declarations from the recorded experiment; power state is observed. -/
tdn_data powerStates : List PowerState from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.powerStates"]

lemma power_transitions_checked : PowerStep (powerStates[0]!) (powerStates[1]!) ∧
    PowerStep (powerStates[1]!) (powerStates[2]!) ∧ PowerStep (powerStates[2]!) (powerStates[3]!) := by
  unfold PowerStep powerStates; decide
theorem recorded_use_finishes_powered_off : UnusedIsOff (powerStates[3]!) := by
  apply power_trace_keeps_unused_guest_off (first := powerStates[0]!)
  · unfold UnusedIsOff powerStates; decide
  · exact ((Relation.ReflTransGen.single power_transitions_checked.1).tail
      power_transitions_checked.2.1).tail power_transitions_checked.2.2
lemma final_guest_is_unused : (powerStates[3]!).inUse = false := by decide
theorem final_guest_is_off : (powerStates[3]!).poweredOn = false :=
  recorded_use_finishes_powered_off final_guest_is_unused

def auditorResponse : ConfigurationResponse := ⟨"Auditor", 200, ["-N EVA3_INPUT", "-A EVA3_INPUT -s 192.0.2.253/32 -p icmp -j DROP", "-A EVA3_INPUT -j RETURN"]⟩
tdn_data auditorConfiguration : List String from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.auditorConfiguration"]

lemma auditor_readback_checked : auditorResponse.settings = auditorConfiguration := by decide
theorem auditor_obtained_configuration : AvailableThrough auditorResponse "Auditor" auditorConfiguration :=
  successful_readback_makes_settings_available _ _ _ rfl rfl auditor_readback_checked

def administratorResponse : ConfigurationResponse := ⟨"SecurityAdministrator", 200, ["-N EVA3_INPUT", "-A EVA3_INPUT -j RETURN"]⟩
tdn_data administratorConfiguration : List String from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.administratorConfiguration"]

lemma administrator_readback_checked : administratorResponse.settings = administratorConfiguration := by decide
theorem administrator_obtained_configuration : AvailableThrough administratorResponse "SecurityAdministrator" administratorConfiguration :=
  successful_readback_makes_settings_available _ _ _ rfl rfl administrator_readback_checked

tdn_data issuances : List Issuance from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.issuances"]

lemma issuance_checks : ∀ i ∈ issuances, IssuanceChecked i := by unfold issuances IssuanceChecked; decide
theorem loaded_credentials_follow_signed_requests (i : Issuance) (member : i ∈ issuances) :
    i.requestOutput = i.signedRequest ∧ i.certificateOutput = i.configuredCertificate ∧ i.requestOrder < i.useOrder ∧
    i.signer ∈ i.loadedAuthorities ∧ i.trustAnchor ∈ i.loadedAuthorities :=
  issued_credential_follows_request i (issuance_checks i member)

tdn_data selectedTests : List String from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.selectedTests"]

tdn_data savedResults : List (String × String) from "../../evidence/lean/FreshRecordedOperations.json" ["TDN.Imported.FreshRecordedOperations.savedResults"]

def resultPath (id : String) : String := if id = "probe-obs-00690" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00690.json" else if id = "probe-obs-00691" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00691.json" else if id = "probe-obs-00692" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00692.json" else if id = "probe-obs-00693" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00693.json" else if id = "probe-obs-00694" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00694.json" else if id = "probe-obs-00695" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00695.json" else if id = "probe-obs-00696" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00696.json" else if id = "probe-obs-00697" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00697.json" else if id = "probe-obs-00698" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00698.json" else if id = "probe-obs-00699" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00699.json" else if id = "probe-obs-00700" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00700.json" else if id = "probe-obs-00701" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00701.json" else ""
lemma result_lookup_checked : ∀ id ∈ selectedTests, (id, resultPath id) ∈ savedResults ∧ resultPath id ≠ "" := by
  unfold selectedTests savedResults resultPath; decide
theorem selected_network_test_results_are_retained : ResultsRetained selectedTests savedResults :=
  retained_table_covers_selected_tests selectedTests savedResults resultPath
    (fun id member => (result_lookup_checked id member).1)
    (fun id member => (result_lookup_checked id member).2)

end TDN.Imported.FreshRecordedOperations
