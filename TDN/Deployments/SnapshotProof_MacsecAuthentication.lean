import TDN.Deployments.MacsecAuthentication_TrafficExamples

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

theorem snapshot_RG024_forward_eap_tls_authentication :
    msc_macsec_authentication_choice_and_as forward.deployment forward.model tlsPrimitive forward.authentication := by
  exact macsec_authentication_from_local_checks forward.deployment forward.model tlsPrimitive
    forward.authentication forward.setupRecords (profile_deployment_is_covered forward (Or.inl rfl)).2.1
    (profile_macsec_names_separate forward (Or.inl rfl)) (profile_tunnel_names_unique forward (Or.inl rfl))
    (profile_setup_checks forward (Or.inl rfl)) (profile_authentication_inventory forward (Or.inl rfl))
    (profile_authentication_settings forward (Or.inl rfl))

theorem snapshot_RG024_reverse_eap_tls_authentication :
    msc_macsec_authentication_choice_and_as reverse.deployment reverse.model tlsPrimitive reverse.authentication := by
  exact macsec_authentication_from_local_checks reverse.deployment reverse.model tlsPrimitive
    reverse.authentication reverse.setupRecords (profile_deployment_is_covered reverse (Or.inr rfl)).2.1
    (profile_macsec_names_separate reverse (Or.inr rfl)) (profile_tunnel_names_unique reverse (Or.inr rfl))
    (profile_setup_checks reverse (Or.inr rfl)) (profile_authentication_inventory reverse (Or.inr rfl))
    (profile_authentication_settings reverse (Or.inr rfl))

theorem snapshot_RG024_forward_nonempty_delivery :
    ∃ start actions finish, forward.model.initial start ∧ forward.model.system.MTr start actions finish ∧
      (forward.model.native.state finish).datapathStage = .delivered ∧
      (forward.model.native.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (forward.model.native.state finish).frame.body = forward.trafficDatagram.body :=
  profile_nonempty_payload_is_delivered forward (Or.inl rfl)

theorem snapshot_RG024_reverse_nonempty_delivery :
    ∃ start actions finish, reverse.model.initial start ∧ reverse.model.system.MTr start actions finish ∧
      (reverse.model.native.state finish).datapathStage = .delivered ∧
      (reverse.model.native.state finish).frame.payload = LinkAdmission.payloadCode [7, 8] ∧
      (reverse.model.native.state finish).frame.body = reverse.trafficDatagram.body :=
  profile_nonempty_payload_is_delivered reverse (Or.inr rfl)

lemma profile_as_attachment_matches_interfaces (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ site zone, capture.deployment.networkAttachment "AS" site zone ↔
      ∃ device ∈ capture.profile.devices, device.id = "AS" ∧ device.site = site ∧
        ∃ iface ∈ capture.profile.interfaces, iface.device = device.id ∧ iface.physical = true ∧ iface.zone = zone := by
  have devices : ∀ device ∈ capture.profile.devices, device.id = "AS" → device.site = "central-site" := by
    rcases supported with rfl | rfl <;> native_decide
  have interfaces : ∀ iface ∈ capture.profile.interfaces, iface.device = "AS" → iface.zone = .gray := by
    rcases supported with rfl | rfl <;> native_decide
  have attached : ∃ device ∈ capture.profile.devices, device.id = "AS" ∧ device.site = "central-site" ∧
      ∃ iface ∈ capture.profile.interfaces, iface.device = device.id ∧ iface.physical = true ∧ iface.zone = .gray := by
    rcases supported with rfl | rfl <;> native_decide
  intro site zone
  constructor
  · intro bound
    change "AS" = "AS" ∧ site = "central-site" ∧ zone = .gray at bound
    simpa only [bound.2.1, bound.2.2] using attached
  · rintro ⟨device, member, name, location, iface, present, owner, physical, securityZone⟩
    change "AS" = "AS" ∧ site = "central-site" ∧ zone = .gray
    exact ⟨rfl, location.symm.trans (devices device member name),
      securityZone.symm.trans (interfaces iface present (owner.trans name))⟩

lemma role_reversed_sessions_are_distinct :
    forward.session ≠ reverse.session ∧ forward.masterSessionKey ≠ reverse.masterSessionKey ∧
      forward.cak ≠ reverse.cak ∧ forward.sak ≠ reverse.sak := by native_decide

lemma cross_session_backend_is_rejected :
    ¬ EAPSessionBinding tlsPrimitive (forward.authenticationFor "P0" "P1") reverse.exchange := by
  intro binding
  have same := binding.2.2.1
  have different : forward.backendInput.session ≠ reverse.tlsInput.session := by native_decide
  exact different same

def crossedKeySetup : MACsecSetupRecord :=
  let first := forward.setupRecords[0]'(by native_decide)
  { first with installation := { first.installation with keyReference := reverse.sak } }

lemma cross_capture_sak_is_rejected : ¬ crossedKeySetup.InstallationChecked forward.model := by
  intro checked
  have key := checked.2.2.2.2.2.1
  change forward.sak = reverse.sak at key
  exact (by native_decide : forward.sak ≠ reverse.sak) key

def changedTranscriptInput : TLSHandshakeInput := {forward.tlsInput with transcript := []}

lemma changed_transcript_with_same_session_is_rejected :
    tlsPrimitive.mutuallyAuthenticate changedTranscriptInput = none := by
  apply unlisted_handshake_input_is_rejected
  · intro same
    have transcript := congrArg TLSHandshakeInput.transcript same
    exact (by native_decide : forward.tlsInput.transcript ≠ []) transcript.symm
  · intro same
    have session := congrArg TLSHandshakeInput.session same
    exact (by native_decide : forward.tlsInput.session ≠ reverse.tlsInput.session) session

def changedBackendInput : EAPBackendInput := {forward.backendInput with protectedRecord := []}

lemma changed_backend_record_with_same_session_is_rejected :
    tlsPrimitive.authenticateBackendDelivery changedBackendInput = none := by
  apply unlisted_backend_input_is_rejected
  · intro same
    have record := congrArg EAPBackendInput.protectedRecord same
    exact (by native_decide : forward.backendInput.protectedRecord ≠ []) record.symm
  · intro same
    have session := congrArg EAPBackendInput.session same
    exact (by native_decide : forward.backendInput.session ≠ reverse.backendInput.session) session

end TDN.Deployments.MacsecAuthentication
