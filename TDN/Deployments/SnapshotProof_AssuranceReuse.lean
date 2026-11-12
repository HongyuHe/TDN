import TDN.Deployments.SnapshotProof_MacsecKeyGen
import TDN.Deployments.SnapshotProof_Administration
import TDN.Deployments.SnapshotProof_Addressing

namespace TDN.Deployments.SnapshotProof_AssuranceReuse
open Compliance Requirements Requirements.Msc

def centralKey : MACsecKey :=
  { SnapshotProof_MacsecKeyGen.key with cakOrigin := .eapDerived "MSK-session-central" }

def centralPair : MACsecServerPair :=
  { SnapshotProof_MacsecKeyGen.pair with
    firstValue := 1, secondValue := 0,
    centralSite := some "central-site" }

def centralRecords : KeyGenerationRecords :=
  ⟨["KGS"], [], [("CAK-A-B", "KGS")]⟩

def centralDeployment (base : Deployment) : Deployment :=
  { SnapshotProof_MacsecKeyGen.configured base with
    centralManagementSite := some "central-site"
    devices := [⟨"INNER-A", "remote-site", .macsec, some .inner,
      SnapshotProof_Addressing.level, true⟩,
      ⟨"INNER-B", "central-site", .macsec, some .inner,
      SnapshotProof_Addressing.level, true⟩] }

theorem central_EAP_model_RG027 (base : Deployment)
    (derivation : String → String → Prop)
    (generator : base.authority.nsaApprovedGenerator "KGS")
    (boundDerivation : derivation "CAK-A-B" "KGS") :
    msc_macsec_key_generation_and_server (centralDeployment base)
      [centralKey] [centralPair] [] derivation := by
  apply macsec_key_generation_from_checked_records
    (centralDeployment base) [centralKey] [centralPair] [] centralRecords derivation
  · rfl
  · simpa [centralRecords, centralDeployment, SnapshotProof_MacsecKeyGen.configured] using generator
  · simp [centralRecords]
  · simpa [centralRecords] using boundDerivation

lemma central_server_and_EAP_origin_are_actual :
    centralPair.secondValue = 0 ∧ centralPair.centralSite = some "central-site" ∧
    centralKey.cakOrigin = .eapDerived "MSK-session-central" := by
  native_decide
lemma wrong_central_server_is_rejected (base : Deployment) :
    keyGenerationChecked (centralDeployment base) [centralKey]
      [{centralPair with firstValue := 0, secondValue := 1}] [] centralRecords = false := by
  rfl

def account : AdministrativeAccount :=
  ⟨7, 42, "AW-person-7-certificate", false, true, 0⟩

def session : AdministrativeSession :=
  ⟨"AW-TLS-channel", 7, 42, 1, "AW-person-7-certificate", "AW-TLS-channel"⟩

def authentication : AdminEvent :=
  ⟨.authentication, 7, 42, 1, "AW-person-7-certificate", true, true, "AW-TLS-channel"⟩

def operation : AdminEvent :=
  ⟨.operation, 7, 42, 3, "AW-TLS-channel", false, false, "AW-TLS-channel"⟩

def events : List AdminEvent := [operation, authentication]

lemma assurance_admission_run :
    (Admission.lts (fun event : AdminEvent => event.kind = .operation)
      (MatchingAdministratorAuthentication true true events [account] [session])).MTr
      [] [authentication, operation] events := by
  refine .stepL (.record [] authentication (by simp [authentication])) ?_
  refine .single _ (.record [authentication] operation ?_)
  intro _
  refine ⟨authentication, by simp, ?_⟩
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    events, authentication, operation, account, session]

theorem selected_assurance_AW_model_RG047 (base : Deployment)
    (certificate : base.authority.certificateCNSACompliant "AW-person-7-certificate")
    (nist : base.authority.authenticationConformsToNIST80063 "AW-person-7-certificate") :
    msc_administrator_authentication base true true events [account] [session] [7] := by
  apply administrator_authentication_from_local_admission_and_credential_checks
    base true true events [authentication, operation] [account] [session] [7] (fun _ => 7)
  · exact assurance_admission_run
  · native_decide
  · native_decide
  · simpa [events, authentication, operation] using certificate
  · simpa [events, authentication, operation] using nist

lemma nonempty_AW_and_performed_operation :
    account.workstationAccount = true ∧ operation ∈ events ∧
    MatchingAdministratorAuthentication true true events [account] [session]
      authentication operation := by
  refine ⟨rfl, by simp [events], ?_⟩
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    events, authentication, operation, account, session]

lemma missing_selected_assurance_is_rejected :
    ¬ MatchingAdministratorAuthentication true true events [account] [session]
      {authentication with certificateCNSA := false} operation := by
  simp [MatchingAdministratorAuthentication]

end TDN.Deployments.SnapshotProof_AssuranceReuse
