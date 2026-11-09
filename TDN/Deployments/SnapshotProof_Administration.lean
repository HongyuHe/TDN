import TDN.Requirements.VerifiedAdminAuthentication
import TDN.Deployments.SnapshotAdminSessions

namespace TDN.Deployments.SnapshotProof_Administration
open Requirements Requirements.Msc Compliance

lemma retained_complete_RG047 (d : Deployment) :
    Requirements.Msc.msc_administrator_authentication d false false
      SnapshotAdminSessions.events SnapshotAdminSessions.accounts
      SnapshotAdminSessions.sessions [] := by
  apply administrator_authentication_from_local_admission_and_credential_checks
    d false false SnapshotAdminSessions.events SnapshotAdminSessions.actions
    SnapshotAdminSessions.accounts SnapshotAdminSessions.sessions [] (fun _ => 0)
  · exact SnapshotAdminSessions.admitted_history
  · decide
  · simp
  · simp
  · simp

def account : AdministrativeAccount :=
  ⟨7, 42, "person-7-certificate", false, true, 0⟩

def session : AdministrativeSession :=
  ⟨"tls-channel-7", 7, 42, 1, "person-7-certificate", "tls-channel-7"⟩

def authentication : AdminEvent :=
  ⟨.authentication, 7, 42, 1, "person-7-certificate", false, false, "tls-channel-7"⟩

def operation : AdminEvent :=
  ⟨.operation, 7, 42, 3, "tls-channel-7", false, false, "tls-channel-7"⟩

def revocation : AdminEvent :=
  ⟨.credentialRevocation, 7, 42, 2, "person-7-certificate", false, false, "tls-channel-7"⟩

lemma live_channel_authentication_matches :
    MatchingAdministratorAuthentication false false [operation, authentication]
      [account] [session] authentication operation := by
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    account, session, authentication, operation]

lemma missing_authentication_rejected :
    ¬ ∃ prior ∈ [operation],
      MatchingAdministratorAuthentication false false [operation]
        [account] [session] prior operation := by
  simp [MatchingAdministratorAuthentication, operation]

lemma revoked_channel_rejected :
    ¬ MatchingAdministratorAuthentication false false
      [operation, revocation, authentication] [account] [session] authentication operation := by
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    account, session, authentication, operation, revocation]

lemma another_person_rejected :
    ¬ MatchingAdministratorAuthentication false false
      [operation, authentication] [account] [session] authentication
      { operation with person := 8 } := by
  simp [MatchingAdministratorAuthentication, authentication, operation]

lemma shared_workstation_credential_rejected (d : Deployment) :
    ¬ Requirements.Msc.msc_administrator_authentication d false false []
      [account, { account with person := 8 }] [] [] := by
  intro valid
  have separates := valid.1.2.2.2 account (by simp) (by rfl)
    { account with person := 8 } (by simp) (by rfl) (by decide)
  exact separates rfl

end TDN.Deployments.SnapshotProof_Administration
