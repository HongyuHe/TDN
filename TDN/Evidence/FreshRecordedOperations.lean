import TDN.Targets.RecordedOperations

namespace TDN.Imported.FreshRecordedOperations
open RecordedOperations

/-- Actual configured assignments, with positive authenticated management attempts. -/
def assignments : List Assignment := [⟨"NM_GF_A", "NM_AW_A99", false⟩, ⟨"NM_I_A1", "NM_AW_A1", true⟩, ⟨"NM_O_A1", "NM_AW_A99", false⟩, ⟨"NM_I_A2", "NM_AW_A2", true⟩, ⟨"NM_O_A2", "NM_AW_A99", false⟩, ⟨"NM_GF_B", "NM_AW_B99", false⟩, ⟨"NM_I_B1", "NM_AW_B1", true⟩, ⟨"NM_O_B1", "NM_AW_B99", false⟩, ⟨"NM_I_B2", "NM_AW_B2", true⟩, ⟨"NM_O_B2", "NM_AW_B99", false⟩]
def partition (aw : String) : Bool := aw == "NM_AW_A1" || aw == "NM_AW_A2" || aw == "NM_AW_B1" || aw == "NM_AW_B2"
lemma assignments_checked : AssignmentChecks assignments partition := by
  unfold AssignmentChecks assignments partition; decide
theorem assigned_workstations_do_not_cross_layers (a b : Assignment)
    (ha : a ∈ assignments) (hb : b ∈ assignments) (different : a.inner ≠ b.inner) :
    a.workstation ≠ b.workstation :=
  administrative_assignments_do_not_share_layers assignments partition assignments_checked a b ha hb different

def tlsVersions : List String := ["TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3"]
lemma tls_versions_checked : ∀ v ∈ tlsVersions, tlsProtection v = some .tls13 := by
  unfold tlsVersions tlsProtection; decide
theorem observed_management_uses_allowed_protocol (v : String) (member : v ∈ tlsVersions) :
    ∃ p, tlsProtection v = some p ∧ Targets.ApprovedManagementProtocol p :=
  ⟨.tls13, tls_versions_checked v member, recognized_tls_is_allowed v .tls13 (tls_versions_checked v member)⟩

/-- Use windows are declarations from the recorded experiment; power state is observed. -/
def powerStates : List PowerState := [⟨true, true⟩, ⟨false, false⟩, ⟨true, true⟩, ⟨false, false⟩]
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
def auditorConfiguration : List String := ["-N EVA3_INPUT", "-A EVA3_INPUT -s 192.0.2.253/32 -p icmp -j DROP", "-A EVA3_INPUT -j RETURN"]
lemma auditor_readback_checked : auditorResponse.settings = auditorConfiguration := by decide
theorem auditor_obtained_configuration : AvailableThrough auditorResponse "Auditor" auditorConfiguration :=
  successful_readback_makes_settings_available _ _ _ rfl rfl auditor_readback_checked

def administratorResponse : ConfigurationResponse := ⟨"SecurityAdministrator", 200, ["-N EVA3_INPUT", "-A EVA3_INPUT -j RETURN"]⟩
def administratorConfiguration : List String := ["-N EVA3_INPUT", "-A EVA3_INPUT -j RETURN"]
lemma administrator_readback_checked : administratorResponse.settings = administratorConfiguration := by decide
theorem administrator_obtained_configuration : AvailableThrough administratorResponse "SecurityAdministrator" administratorConfiguration :=
  successful_readback_makes_settings_available _ _ _ rfl rfl administrator_readback_checked

def issuances : List Issuance := [⟨"/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-a/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-a/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-a/x509/cert.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-a/x509/cert.pem", 35, 36, 54, "enterprise-inner-a", "enterprise-inner-root", ["enterprise-inner-b", "enterprise-inner-root", "enterprise-inner-a"]⟩,
  ⟨"/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-b/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-b/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-b/x509/cert.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/inner-b/x509/cert.pem", 39, 40, 58, "enterprise-inner-b", "enterprise-inner-root", ["enterprise-inner-b", "enterprise-inner-root", "enterprise-inner-a"]⟩,
  ⟨"/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-a/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-a/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-a/x509/cert.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-a/x509/cert.pem", 43, 44, 62, "enterprise-outer-a", "enterprise-outer-root", ["enterprise-outer-b", "enterprise-outer-a", "enterprise-outer-root"]⟩,
  ⟨"/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-b/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-b/request.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-b/x509/cert.pem", "/users/hy/tdn-continuation-2026-10-24T014455Z/private/ca-enterprise-v2/outer-b/x509/cert.pem", 47, 48, 66, "enterprise-outer-b", "enterprise-outer-root", ["enterprise-outer-b", "enterprise-outer-a", "enterprise-outer-root"]⟩]
lemma issuance_checks : ∀ i ∈ issuances, IssuanceChecked i := by unfold issuances IssuanceChecked; decide
theorem loaded_credentials_follow_signed_requests (i : Issuance) (member : i ∈ issuances) :
    i.requestOutput = i.signedRequest ∧ i.certificateOutput = i.configuredCertificate ∧ i.requestOrder < i.useOrder ∧
    i.signer ∈ i.loadedAuthorities ∧ i.trustAnchor ∈ i.loadedAuthorities :=
  issued_credential_follows_request i (issuance_checks i member)

def selectedTests : List String := ["probe-obs-00690", "probe-obs-00691", "probe-obs-00692", "probe-obs-00693", "probe-obs-00694", "probe-obs-00695", "probe-obs-00696", "probe-obs-00697", "probe-obs-00698", "probe-obs-00699", "probe-obs-00700", "probe-obs-00701"]
def savedResults : List (String × String) := [("probe-obs-00690", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00690.json"), ("probe-obs-00691", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00691.json"), ("probe-obs-00692", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00692.json"), ("probe-obs-00693", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00693.json"), ("probe-obs-00694", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00694.json"), ("probe-obs-00695", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00695.json"), ("probe-obs-00696", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00696.json"), ("probe-obs-00697", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00697.json"), ("probe-obs-00698", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00698.json"), ("probe-obs-00699", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00699.json"), ("probe-obs-00700", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00700.json"), ("probe-obs-00701", "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00701.json")]
def resultPath (id : String) : String := if id = "probe-obs-00690" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00690.json" else if id = "probe-obs-00691" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00691.json" else if id = "probe-obs-00692" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00692.json" else if id = "probe-obs-00693" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00693.json" else if id = "probe-obs-00694" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00694.json" else if id = "probe-obs-00695" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00695.json" else if id = "probe-obs-00696" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00696.json" else if id = "probe-obs-00697" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00697.json" else if id = "probe-obs-00698" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00698.json" else if id = "probe-obs-00699" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00699.json" else if id = "probe-obs-00700" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00700.json" else if id = "probe-obs-00701" then "artifacts/snapshots/2026-10-24T014455Z/native-management-20261024T015900Z/raw/obs-00701.json" else ""
lemma result_lookup_checked : ∀ id ∈ selectedTests, (id, resultPath id) ∈ savedResults ∧ resultPath id ≠ "" := by
  unfold selectedTests savedResults resultPath; decide
theorem selected_network_test_results_are_retained : ResultsRetained selectedTests savedResults :=
  retained_table_covers_selected_tests selectedTests savedResults resultPath
    (fun id member => (result_lookup_checked id member).1)
    (fun id member => (result_lookup_checked id member).2)

end TDN.Imported.FreshRecordedOperations
