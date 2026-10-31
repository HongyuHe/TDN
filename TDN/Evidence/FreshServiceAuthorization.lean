import TDN.Semantics.AccessControl

namespace TDN.Imported.FreshServiceAuthorization

def roles (fingerprint : String) : Option String :=
  if fingerprint = "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138" then some "Auditor" else
  if fingerprint = "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02" then some "SecurityAdministrator" else
  none

def permissions : List AccessControl.Permission := [⟨"SecurityAdministrator", "GET", "/state"⟩, ⟨"SecurityAdministrator", "GET", "/audit"⟩, ⟨"SecurityAdministrator", "POST", "/filter"⟩, ⟨"SecurityAdministrator", "POST", "/audit/rotate"⟩, ⟨"Auditor", "GET", "/state"⟩, ⟨"Auditor", "GET", "/audit"⟩, ⟨"Auditor", "POST", "/audit/rotate"⟩]

def security_admin : String := "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02"

def auditor : String := "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138"

def unmapped : String := "2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2"

theorem all_private_key_paths_denied (fingerprint method : String) :
    AccessControl.authorize roles permissions ⟨fingerprint, method, "/private-key"⟩ = false := by
  apply AccessControl.absent_path_is_denied
  simp [permissions]

theorem every_unmapped_fingerprint_denied (fingerprint method path : String)
    (unmappedPeer : roles fingerprint = none) :
    AccessControl.authorize roles permissions ⟨fingerprint, method, path⟩ = false :=
  AccessControl.unmapped_peer_is_denied roles permissions _ unmappedPeer

def AuditorOperation (method path : String) : Prop :=
  (method = "GET" ∧ path ∈ ["/state", "/audit"]) ∨
  (method = "POST" ∧ path = "/audit/rotate")

theorem every_accepted_auditor_request_is_within_scope (request : AccessControl.Request)
    (role : roles request.authenticatedFingerprint = some "Auditor")
    (accepted : AccessControl.authorize roles permissions request = true) :
    AuditorOperation request.method request.normalizedPath := by
  apply AccessControl.role_permission_restricts_operations roles permissions request "Auditor"
    role accepted AuditorOperation
  simp [permissions, AuditorOperation]

theorem auditor_filter_change_denied :
    AccessControl.authorize roles permissions ⟨auditor, "POST", "/filter"⟩ = false := by decide

theorem administrator_filter_change_permitted :
    AccessControl.authorize roles permissions ⟨security_admin, "POST", "/filter"⟩ = true := by decide

def observed : List (AccessControl.Request × Bool) := [
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "GET", "/state"⟩, true),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "GET", "/audit"⟩, true),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "POST", "/filter"⟩, true),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "POST", "/audit/rotate"⟩, true),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "GET", "/private-key"⟩, false),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "GET", "/unknown"⟩, false),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "HEAD", "/state"⟩, false),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "GET", "/state"⟩, true),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "GET", "/audit"⟩, true),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "POST", "/filter"⟩, false),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "POST", "/audit/rotate"⟩, true),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "GET", "/private-key"⟩, false),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "GET", "/unknown"⟩, false),
  (⟨"d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138", "HEAD", "/state"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "GET", "/state"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "GET", "/audit"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "POST", "/filter"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "POST", "/audit/rotate"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "GET", "/private-key"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "GET", "/unknown"⟩, false),
  (⟨"2480aea56119150415b78a77a6a59ec61287385c7c5c1b0ab29c176c5fc00ac2", "HEAD", "/state"⟩, false),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "GET", "/state"⟩, true),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "POST", "/filter"⟩, true),
  (⟨"f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02", "GET", "/audit"⟩, true)]

theorem retained_http_results_match_model : ∀ pair ∈ observed,
    AccessControl.authorize roles permissions pair.1 = pair.2 := by decide

end TDN.Imported.FreshServiceAuthorization
