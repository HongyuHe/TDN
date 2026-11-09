import Mathlib.Data.List.Basic

namespace TDN.AccessControl

structure Permission where
  role : String
  method : String
  path : String
  deriving DecidableEq, Repr

structure Request where
  authenticatedFingerprint : String
  method : String
  normalizedPath : String
  deriving DecidableEq, Repr

def authorize (roles : String → Option String) (permissions : List Permission) (request : Request) : Bool :=
  match roles request.authenticatedFingerprint with
  | none => false
  | some role => permissions.any (fun permission =>
      permission.role == role && permission.method == request.method &&
        permission.path == request.normalizedPath)

lemma authorized_request_has_permission (roles : String → Option String)
    (permissions : List Permission) (request : Request)
    (allowed : authorize roles permissions request = true) :
    ∃ role, roles request.authenticatedFingerprint = some role ∧
      ∃ permission ∈ permissions, permission.role = role ∧
        permission.method = request.method ∧ permission.path = request.normalizedPath := by
  unfold authorize at allowed
  split at allowed
  next absent => cases allowed
  next role present =>
    obtain ⟨permission, member, matched⟩ := List.any_eq_true.mp allowed
    exact ⟨role, present, permission, member, by simpa [and_assoc] using matched⟩

theorem unmapped_peer_is_denied (roles : String → Option String)
    (permissions : List Permission) (request : Request)
    (unmapped : roles request.authenticatedFingerprint = none) :
    authorize roles permissions request = false := by
  simp [authorize, unmapped]

theorem absent_path_is_denied (roles : String → Option String)
    (permissions : List Permission) (request : Request)
    (excluded : ∀ permission ∈ permissions, permission.path ≠ request.normalizedPath) :
    authorize roles permissions request = false := by
  cases decision : authorize roles permissions request with
  | false => rfl
  | true =>
    obtain ⟨role, _, permission, member, _, _, same⟩ :=
      authorized_request_has_permission roles permissions request decision
    exact False.elim (excluded permission member same)

theorem role_permission_restricts_operations (roles : String → Option String)
    (permissions : List Permission) (request : Request) (role : String)
    (bound : roles request.authenticatedFingerprint = some role)
    (allowed : authorize roles permissions request = true)
    (permitted : String → String → Prop)
    (checked : ∀ permission ∈ permissions, permission.role = role →
      permitted permission.method permission.path) :
    permitted request.method request.normalizedPath := by
  obtain ⟨actualRole, actualBinding, permission, member, actual, method, path⟩ :=
    authorized_request_has_permission roles permissions request allowed
  have same : actualRole = role := Option.some.inj (actualBinding.symm.trans bound)
  simpa [method, path] using checked permission member (actual.trans same)

end TDN.AccessControl
