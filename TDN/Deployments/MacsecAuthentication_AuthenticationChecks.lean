import TDN.Deployments.MacsecAuthentication_ProfileData
import TDN.Requirements.ObservedHistoryChecks
import TDN.Requirements.MacsecAuthenticationConfigChecks
import TDN.Deployments.MacsecAuthentication_ExchangeChecks

namespace TDN.Deployments.MacsecAuthentication
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

deriving instance DecidableEq for EAPExchange
deriving instance DecidableEq for EAPBackendDelivery
deriving instance DecidableEq for MACsecAuthentication
deriving instance DecidableEq for MACsecSetupRecord

lemma profile_history_valid (capture : CaptureData) (supported : SupportedCapture capture) :
    capture.history.Valid := by
  apply observed_history_checks_sound
  rcases supported with rfl | rfl <;> native_decide

lemma profile_setup_checks (capture : CaptureData) (supported : SupportedCapture capture) :
    MACsecSetupChecks {capture.deployment with focus := none} capture.model tlsPrimitive
      capture.authentication capture.setupRecords := by
  refine ⟨profile_history_valid capture supported, ?_, ?_⟩
  · rcases supported with rfl | rfl
    all_goals
      intro record member
      first
      | change record ∈ [forward.setupRecords[0]'(by native_decide), forward.setupRecords[1]'(by native_decide)] at member
      | change record ∈ [reverse.setupRecords[0]'(by native_decide), reverse.setupRecords[1]'(by native_decide)] at member
      simp only [List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl
      all_goals
        refine ⟨by native_decide, by native_decide, ?_⟩
        dsimp only [MACsecSetupRecord.AuthenticationChecked, CaptureData.authentication,
          CaptureData.deployment, MacsecProtection.ProfileRecords.deployment]
        refine ⟨by native_decide, by native_decide, by native_decide, by native_decide, by native_decide,
          by native_decide, by native_decide, by native_decide, by native_decide, by native_decide, ?_⟩
        dsimp only [MACsecSetupRecord.EAPChecked, CaptureData.authenticationFor]
        refine ⟨?_, by native_decide, by native_decide, by native_decide, by native_decide, by native_decide,
          by native_decide, by native_decide, by native_decide, by native_decide, by native_decide⟩
        first
        | apply profile_session_binding forward (Or.inl rfl)
        | apply profile_session_binding reverse (Or.inr rfl)
        simp only [CaptureData.authentication, List.mem_cons, List.not_mem_nil, or_false]
        first | exact Or.inl rfl | exact Or.inr rfl
  · have checked : ∀ iface ∈ capture.profile.macIfaces,
        ∀ association ∈ iface.transmitAssociation.toList,
        ∃ record ∈ capture.setupRecords,
          record.installation.device = capture.profile.configuration.ip.owner iface.physicalIface ∧
          record.installation.association = association := by
      rcases supported with rfl | rfl <;> native_decide
    intro iface member
    cases transmitted : iface.transmitAssociation with
    | none => trivial
    | some association => exact checked iface member association (by simp [transmitted])

lemma profile_authentication_inventory (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ device ∈ capture.deployment.devices, device.kind = .macsec →
      ∃ selected ∈ capture.authentication, selected.device = device.id := by
  rcases supported with rfl | rfl <;> native_decide

lemma profile_authentication_settings (capture : CaptureData) (supported : SupportedCapture capture) :
    ∀ selected ∈ capture.authentication,
      MACsecAuthenticationConfigChecked {capture.deployment with focus := none} tlsPrimitive selected := by
  intro selected member
  have roles := profile_endpoint_roles capture supported selected member
  have binding := profile_session_binding capture supported selected member
  have exchangeMember : capture.exchange ∈ [forward.exchange, reverse.exchange] := by
    rcases supported with rfl | rfl
    · exact List.mem_cons_self
    · exact List.mem_cons.mpr (Or.inr List.mem_cons_self)
  rcases supported with rfl | rfl
  all_goals
    simp only [CaptureData.authentication, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    all_goals
      refine ⟨by unfold Deployment.IsDevice; native_decide, by unfold Deployment.IsDevice; native_decide,
        by native_decide, by native_decide, by native_decide, by native_decide, ?_⟩
      refine ⟨by unfold Deployment.IsDevice; native_decide, rfl, by native_decide, by native_decide, by native_decide, roles, ?_, ?_, ?_, ?_⟩
      · exact ⟨_, exchangeMember, binding⟩
      · intro site zone
        simp [CaptureData.authenticationFor, CaptureData.deployment]
      · exact ⟨"central-site", .gray, by native_decide, by native_decide⟩
      · native_decide
lemma profile_tunnel_names_unique (capture : CaptureData) (supported : SupportedCapture capture) :
    TunnelNamesUnique {capture.deployment with focus := none} := by
  unfold TunnelNamesUnique
  rcases supported with rfl | rfl <;> native_decide

lemma profile_macsec_names_separate (capture : CaptureData) (supported : SupportedCapture capture) :
    MACsecTunnelNamesSeparate {capture.deployment with focus := none} capture.model.native := by
  intro tunnel member mechanism authentication
  change "no-IPsec" ≠ tunnel.id
  have checked : ∀ tunnel ∈ capture.profile.tunnels, "no-IPsec" ≠ tunnel.id := by
    rcases supported with rfl | rfl <;> native_decide
  exact checked tunnel member

end TDN.Deployments.MacsecAuthentication
