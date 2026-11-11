import TDN.Requirements.CoreMscRequirements

namespace TDN.Requirements.Msc
open Compliance

structure CertificateAuthoritySetting where
  component : String
  authority : String
  certificateAuthenticated : Bool
  preSharedCAKAuthenticated : Bool
  authorityIsCA : Bool
  authorityKeyCertSign : Bool

def CertificateAuthoritySetting.Check (setting : CertificateAuthoritySetting) : Prop :=
  (setting.certificateAuthenticated = true →
    setting.authorityIsCA = true ∧ setting.authorityKeyCertSign = true ∧ setting.authority ≠ "") ∧
  setting.preSharedCAKAuthenticated = false

def CertificateAuthoritySetting.authorityDevice (setting : CertificateAuthoritySetting) : Device :=
  { id := setting.authority,
    kind := if setting.authorityIsCA && setting.authorityKeyCertSign then .certificationAuthority else .other,
    site := "logical-ca-reference", layer := none, infrastructure := false,
    level := { classification := "public-ca-metadata", compartments := {}, dissemination := {}, otherControls := {} } }

def certificateAuthorityView (settings : List CertificateAuthoritySetting) (d : Deployment) : Deployment :=
  { d with
    devices := d.devices ++ settings.map CertificateAuthoritySetting.authorityDevice
    certificateAuthenticated := fun component =>
      ((settings.find? (fun setting => setting.component == component)).map
        CertificateAuthoritySetting.certificateAuthenticated).getD false
    preSharedCAKAuthenticated := fun component =>
      ((settings.find? (fun setting => setting.component == component)).map
        CertificateAuthoritySetting.preSharedCAKAuthenticated).getD false
    keyManagementCA := fun component authority => ∃ setting ∈ settings,
      setting.component = component ∧ setting.authority = authority }

lemma checked_certificate_settings_supply_services (settings : List CertificateAuthoritySetting)
    (d : Deployment) (checked : ∀ setting ∈ settings, setting.Check) :
    AuthenticationServices (certificateAuthorityView settings d) := by
  constructor
  · intro component member relevant authenticated
    change ((settings.find? (fun setting => setting.component == component.id)).map
      CertificateAuthoritySetting.certificateAuthenticated).getD false = true at authenticated
    cases found : settings.find? (fun setting => setting.component == component.id) with
    | none => simp [found] at authenticated
    | some setting =>
      have stored := List.mem_of_find?_eq_some found
      have name : setting.component = component.id := beq_iff_eq.mp (List.find?_some (p := fun setting : CertificateAuthoritySetting => setting.component == component.id) found)
      have enabled : setting.certificateAuthenticated = true := by simpa [found] using authenticated
      have supported := (checked setting stored).1 enabled
      refine ⟨setting.authorityDevice, List.mem_append_right _ (List.mem_map.mpr ⟨setting, stored, rfl⟩), ?_, ?_⟩
      · simp [CertificateAuthoritySetting.authorityDevice, supported.1, supported.2.1]
      · exact ⟨setting, stored, name, rfl⟩
  · intro component member relevant authenticated
    change ((settings.find? (fun setting => setting.component == component.id)).map
      CertificateAuthoritySetting.preSharedCAKAuthenticated).getD false = true at authenticated
    cases found : settings.find? (fun setting => setting.component == component.id) with
    | none => simp [found] at authenticated
    | some setting =>
      have disabled := (checked setting (List.mem_of_find?_eq_some found)).2
      simp [found, disabled] at authenticated

end TDN.Requirements.Msc
