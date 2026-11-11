import TDN.Deployments.MacsecAuthentication_ProfileData
import TDN.Requirements.MacsecAuthenticationConfigChecks

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc

set_option maxRecDepth 200000
set_option maxHeartbeats 2000000

lemma reverse_handshake_input_differs : reverse.tlsInput ≠ forward.tlsInput := by
  intro same
  have session := congrArg TLSHandshakeInput.session same
  exact (by decide : reverse.tlsInput.session ≠ forward.tlsInput.session) session

lemma forward_handshake_is_accepted :
    tlsPrimitive.mutuallyAuthenticate forward.tlsInput = some forward.exchange.verified := by
  classical
  change (@ite (Option TLSVerifiedSession) (forward.tlsInput = forward.tlsInput) (Classical.propDecidable _) (some forward.exchange.verified) _) = _
  rw [if_pos rfl]

lemma reverse_handshake_is_accepted :
    tlsPrimitive.mutuallyAuthenticate reverse.tlsInput = some reverse.exchange.verified := by
  classical
  change (@ite (Option TLSVerifiedSession) (reverse.tlsInput = forward.tlsInput) (Classical.propDecidable _)
    (some forward.exchange.verified) (@ite (Option TLSVerifiedSession) (reverse.tlsInput = reverse.tlsInput)
      (Classical.propDecidable _) (some reverse.exchange.verified) none)) = _
  rw [if_neg reverse_handshake_input_differs, if_pos rfl]

lemma forward_backend_is_accepted :
    tlsPrimitive.authenticateBackendDelivery forward.backendInput = some forward.backend.verified := by
  classical
  change (@ite (Option EAPBackendVerified) (forward.backendInput = forward.backendInput) (Classical.propDecidable _) (some forward.backend.verified) _) = _
  rw [if_pos rfl]

lemma reverse_backend_is_accepted :
    tlsPrimitive.authenticateBackendDelivery reverse.backendInput = some reverse.backend.verified := by
  classical
  have different : reverse.backendInput ≠ forward.backendInput := by
    intro same
    have session := congrArg EAPBackendInput.session same
    exact (by decide : reverse.backendInput.session ≠ forward.backendInput.session) session
  change (@ite (Option EAPBackendVerified) (reverse.backendInput = forward.backendInput) (Classical.propDecidable _)
    (some forward.backend.verified) (@ite (Option EAPBackendVerified) (reverse.backendInput = reverse.backendInput)
      (Classical.propDecidable _) (some reverse.backend.verified) none)) = _
  rw [if_neg different, if_pos rfl]

lemma capture_exchange_is_successful (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.exchange.Successful tlsPrimitive := by
  have accepted : tlsPrimitive.mutuallyAuthenticate capture.tlsInput = some capture.exchange.verified := by
    rcases supported with rfl | rfl
    · exact forward_handshake_is_accepted
    · exact reverse_handshake_is_accepted
  refine ⟨?_, ?_, ?_, ?_, accepted, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_⟩
  all_goals rcases supported with rfl | rfl
  all_goals first | decide | { unfold Trust.MutuallyAdmits Trust.Admits; decide }

lemma capture_backend_is_successful (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.backend.Successful tlsPrimitive := by
  have accepted : tlsPrimitive.authenticateBackendDelivery capture.backendInput = some capture.backend.verified := by
    rcases supported with rfl | rfl
    · exact forward_backend_is_accepted
    · exact reverse_backend_is_accepted
  refine ⟨?_, ?_, ?_, accepted, rfl, rfl, rfl, rfl, rfl⟩
  all_goals rcases supported with rfl | rfl <;> decide

lemma capture_cak_is_derived (capture : CaptureData) (supported : SupportedCapture capture) :
    tlsPrimitive.deriveCAK capture.masterSessionKey = capture.cak := by
  rcases supported with rfl | rfl
  · change (if forward.masterSessionKey = forward.masterSessionKey then forward.cak
      else if forward.masterSessionKey = reverse.masterSessionKey then reverse.cak else "") = _
    rw [if_pos rfl]
  · have different : reverse.masterSessionKey ≠ forward.masterSessionKey := by decide
    change (if reverse.masterSessionKey = forward.masterSessionKey then forward.cak
      else if reverse.masterSessionKey = reverse.masterSessionKey then reverse.cak else "") = _
    rw [if_neg different, if_pos rfl]

lemma profile_selected_exchange (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ selected ∈ capture.authentication, EAPSelectedExchange tlsPrimitive selected capture.exchange := by
  have successful := capture_exchange_is_successful capture supported
  rcases supported with rfl | rfl
  all_goals
    intro selected member
    simp only [CaptureData.authentication, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    all_goals
      refine ⟨rfl, ?_⟩
      first
      | refine Or.inl ⟨by decide, by decide, successful, by decide, by decide, by decide,
          by decide, by decide, by decide, rfl⟩
      | refine Or.inr ⟨by decide, by decide, successful, by decide, by decide, by decide,
          by decide, by decide, by decide, rfl⟩

lemma profile_session_binding (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ selected ∈ capture.authentication, EAPSessionBinding tlsPrimitive selected capture.exchange := by
  intro selected member
  have exchange := profile_selected_exchange capture supported selected member
  have backend := capture_backend_is_successful capture supported
  have cak := capture_cak_is_derived capture supported
  rcases supported with rfl | rfl
  all_goals
    simp only [CaptureData.authentication, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    all_goals exact ⟨exchange, backend, rfl, rfl, rfl, rfl, rfl, rfl, rfl, cak.symm, cak.symm, rfl⟩

lemma profile_endpoint_roles (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ selected ∈ capture.authentication, EAPEndpointRoleEvidence tlsPrimitive selected := by
  rcases supported with rfl | rfl
  all_goals
    intro selected selectedMember
    simp only [CaptureData.authentication, List.mem_cons, List.not_mem_nil, or_false] at selectedMember
    rcases selectedMember with rfl | rfl
    all_goals
      intro endpoint endpointMember
      simp only [CaptureData.authenticationFor, List.mem_cons, List.not_mem_nil, or_false] at endpointMember
      rcases endpointMember with rfl | rfl
      all_goals
        refine ⟨by decide, ?_⟩
        first
        | exact ⟨forward.exchange, List.mem_cons_self, by decide, by decide, rfl, by decide, by decide,
            by decide, by decide, capture_exchange_is_successful forward (Or.inl rfl)⟩
        | exact ⟨reverse.exchange, List.mem_cons.mpr (Or.inr List.mem_cons_self), by decide, by decide,
            rfl, by decide, by decide, by decide, by decide,
            capture_exchange_is_successful reverse (Or.inr rfl)⟩

lemma unlisted_handshake_input_is_rejected (input : TLSHandshakeInput)
    (first : input ≠ forward.tlsInput) (second : input ≠ reverse.tlsInput) :
    tlsPrimitive.mutuallyAuthenticate input = none := by
  classical
  change (@ite (Option TLSVerifiedSession) (input = forward.tlsInput) (Classical.propDecidable _)
    (some forward.exchange.verified) (@ite (Option TLSVerifiedSession) (input = reverse.tlsInput)
      (Classical.propDecidable _) (some reverse.exchange.verified) none)) = none
  rw [if_neg first, if_neg second]

lemma unlisted_backend_input_is_rejected (input : EAPBackendInput)
    (first : input ≠ forward.backendInput) (second : input ≠ reverse.backendInput) :
    tlsPrimitive.authenticateBackendDelivery input = none := by
  classical
  change (@ite (Option EAPBackendVerified) (input = forward.backendInput) (Classical.propDecidable _)
    (some forward.backend.verified) (@ite (Option EAPBackendVerified) (input = reverse.backendInput)
      (Classical.propDecidable _) (some reverse.backend.verified) none)) = none
  rw [if_neg first, if_neg second]

end TDN.Deployments.MacsecAuthentication
