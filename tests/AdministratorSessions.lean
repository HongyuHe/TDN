import TDN.Requirements.ManagementPlaneRequirements

open TDN.Requirements
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def account : AdministrativeAccount := ⟨1, 7, "certificate-fingerprint", false, true, 0⟩
def session : AdministrativeSession := ⟨"connection-1", 1, 7, 10, "certificate-fingerprint", "request-token"⟩
def authenticated : AdminEvent := ⟨.authentication, 1, 7, 10, "certificate-fingerprint", true, true, "connection-1"⟩
def operation : AdminEvent := ⟨.operation, 1, 7, 20, "request-token", false, false, "connection-1"⟩
def logout : AdminEvent := ⟨.logout, 1, 7, 15, "", false, false, "connection-1"⟩
def revoked : AdminEvent := ⟨.credentialRevocation, 1, 7, 15, "certificate-fingerprint", false, false, ""⟩

-- A certificate and request token can differ when their actual session binds them.
example : msc_administrator_authentication true true [authenticated, operation]
    [account] [session] [1] := by
  simp [msc_administrator_authentication, MatchingAdministratorAuthentication,
    AdministrativeSessionActive, authenticated, operation, account, session]

example : ¬ MatchingAdministratorAuthentication false false [authenticated, operation]
    [] [session] authenticated operation := by
  simp [MatchingAdministratorAuthentication]

example : ¬ MatchingAdministratorAuthentication false false [authenticated, operation]
    [account] [session] authenticated { operation with credential := "unrelated-token" } := by
  simp [MatchingAdministratorAuthentication, account, session, authenticated, operation]

example : ¬ MatchingAdministratorAuthentication false false [authenticated, operation]
    [account] [session] authenticated { operation with session := "another-session" } := by
  simp [MatchingAdministratorAuthentication, account, session, authenticated, operation]

example : ¬ MatchingAdministratorAuthentication false false [authenticated, logout, operation]
    [account] [session] authenticated operation := by
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    account, session, authenticated, operation, logout]

example : ¬ MatchingAdministratorAuthentication false false [authenticated, revoked, operation]
    [account] [session] authenticated operation := by
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    account, session, authenticated, operation, revoked]

-- Every declared AW administrator needs an account even without an observed request.
example : ¬ msc_administrator_authentication false false [] [account] [session] [1, 2] := by
  simp [msc_administrator_authentication, account]

-- A logout after an operation does not retroactively invalidate the operation.
example : MatchingAdministratorAuthentication false false
    [authenticated, operation, { logout with order := 21 }]
    [account] [session] authenticated operation := by
  simp [MatchingAdministratorAuthentication, AdministrativeSessionActive,
    account, session, authenticated, operation, logout]
