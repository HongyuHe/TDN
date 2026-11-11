import TDN.Deployments.MacsecProtection_DeploymentCoverage

namespace TDN.Deployments.MacsecProtection
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

lemma profile_external_iface_checks (records : ProfileRecords) (supported : SupportedProfile records) :
    MACsecExternalIfaceChecks records.deployment records.model.native := by
  refine ⟨profile_output_checks records supported, ?_⟩
  have checked : ∀ edge ∈ records.links, ∀ interface ∈ records.interfaces,
      interface.id = records.ifaceName edge.1 → ∀ device ∈ records.devices,
      device.id = interface.device → device.kind = .macsec →
      (device.layer = some .inner ∧ interface.zone = .gray ∨
        device.layer = some .outer ∧ interface.zone = .black) →
      ∃ mac ∈ records.macIfaces, mac.physicalIface = edge.1 ∧
        records.componentName (records.configuration.ip.owner mac.physicalIface) = device.id := by
    rcases supported with rfl | rfl <;> decide
  intro iface next linked interface member name device configured owner kind external
  exact checked (iface, next) linked interface member name device configured owner kind external

lemma observed_parameter_settings :
    ∀ parameter ∈ parameters, parameter.dataDelayProtection = true ∧
      parameter.lifetimeMilliseconds = 6000 ∧ parameter.normalHelloMilliseconds = 2000 ∧
      0 < parameter.activeHelloMilliseconds ∧ parameter.activeHelloMilliseconds ≤ 2000 ∧
      (parameter.replayWindow = 2 ∨ (parameter.feasibleReplayWindow parameter.replayWindow ∧
        ∀ feasible, parameter.feasibleReplayWindow feasible → parameter.replayWindow ≤ feasible)) ∧
      parameter.confidentialityOffset = 0 ∧ parameter.mustSecure = true := by
  simp [parameters, observedParameters, ObservedParameters.parameter]

lemma observed_public_configuration_requests_encryption :
    ∀ record ∈ observedParameters, record.configuredMacsecPolicy = some 1 ∧
      record.configuredIntegrityOnly = some 0 ∧ record.protectFrames = true ∧
      record.encryptFrames = true ∧ record.controlledPortEnabled = true ∧
      record.receiveValidation = "strict" := by
  decide

lemma profile_parameter_inventory (records : ProfileRecords) (supported : SupportedProfile records) :
    ∀ device ∈ records.deployment.devices, device.kind = .macsec →
      ∃ parameter ∈ parameters, parameter.device = device.id := by
  rcases supported with rfl | rfl <;> decide

lemma profile_parameters_bound (records : ProfileRecords) (supported : SupportedProfile records) :
    MACsecParametersBound records.deployment records.model parameters := by
  unfold MACsecParametersBound
  simp only [Deployment.Relevant, ProfileRecords.deployment]
  rcases supported with rfl | rfl <;> decide

theorem profile_macsec_protection_parameters (records : ProfileRecords) (supported : SupportedProfile records) :
    msc_macsec_protection_parameters records.deployment records.model parameters := by
  apply macsec_protection_from_local_checks records.deployment records.model parameters
  · exact profile_deployment_is_covered records supported
  · exact profile_parameters_bound records supported
  · exact profile_parameter_inventory records supported
  · exact observed_parameter_settings
  · exact profile_external_iface_checks records supported
  · intro state initialized
    exact (profile_initial_wire_safe records supported state initialized).1

theorem snapshot_RG028_direct_macsec_protection_parameters :
    msc_macsec_protection_parameters direct.deployment direct.model parameters :=
  profile_macsec_protection_parameters direct (Or.inl rfl)

theorem snapshot_RG028_routed_macsec_protection_parameters :
    msc_macsec_protection_parameters routed.deployment routed.model parameters :=
  profile_macsec_protection_parameters routed (Or.inr rfl)

end TDN.Deployments.MacsecProtection
