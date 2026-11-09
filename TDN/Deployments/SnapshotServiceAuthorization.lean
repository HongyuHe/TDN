import TDN.Import.SnapshotLoader
import TDN.Models.RoleBasedAccessControl

namespace TDN.Deployments.SnapshotServiceAuthorization

def roles (fingerprint : String) : Option String :=
  if fingerprint = "d243f5b8d35b58ef429754284737dbefd01e9e3c6e68040045e7a5d7ed42d138" then some "Auditor" else
  if fingerprint = "f59c6e8d8e00309ee63c86dd54833eeced859d7575436a69533c5817b3fc7d02" then some "SecurityAdministrator" else
  none

load_network_records permissions : List AccessControl.Permission from "../../data/evidence/SnapshotServiceAuthorization.json" ["TDN.Deployments.SnapshotServiceAuthorization.permissions"]

load_network_records security_admin : String from "../../data/evidence/SnapshotServiceAuthorization.json" ["TDN.Deployments.SnapshotServiceAuthorization.security_admin"]

load_network_records auditor : String from "../../data/evidence/SnapshotServiceAuthorization.json" ["TDN.Deployments.SnapshotServiceAuthorization.auditor"]

load_network_records unmapped : String from "../../data/evidence/SnapshotServiceAuthorization.json" ["TDN.Deployments.SnapshotServiceAuthorization.unmapped"]

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

load_network_records observed : List (AccessControl.Request × Bool) from "../../data/evidence/SnapshotServiceAuthorization.json" ["TDN.Deployments.SnapshotServiceAuthorization.observed"]

theorem retained_http_results_match_model : ∀ pair ∈ observed,
    AccessControl.authorize roles permissions pair.1 = pair.2 := by decide

end TDN.Deployments.SnapshotServiceAuthorization
