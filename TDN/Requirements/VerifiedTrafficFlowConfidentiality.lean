import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc

def coverInstallationChecked (installation : CoverInstallation) : Bool :=
  decide (installation.use.enabled = installation.active ∧
    installation.sender.headerBytes ≤ installation.sender.recordBytes ∧
    0 < installation.sender.queueLimit ∧
    0 < installation.sender.intervalNs ∧
    ((installation.use.publicInternet = true ∨
      (installation.use.objectiveSelected = true ∧
        installation.use.externalMACsec = true ∧
        installation.use.outerFirewallAttached = true)) → installation.active = true))

lemma cover_installation_check_sound {installation : CoverInstallation}
    (checked : coverInstallationChecked installation = true) :
    installation.use.enabled = installation.active ∧ installation.sender.Valid ∧
    ((installation.use.publicInternet = true ∨
      (installation.use.objectiveSelected = true ∧
        installation.use.externalMACsec = true ∧
        installation.use.outerFirewallAttached = true)) → installation.active = true) := by
  have facts := of_decide_eq_true checked
  exact ⟨facts.1, ⟨facts.2.1, facts.2.2.1, facts.2.2.2.1⟩, facts.2.2.2.2⟩

theorem transec_conditions_from_checked_installations
    (installations : List CoverInstallation)
    (checked : installations.all coverInstallationChecked = true) :
    msc_transec_conditions installations := by
  have facts (installation : CoverInstallation) (member : installation ∈ installations) :=
    cover_installation_check_sound (List.all_eq_true.mp checked installation member)
  have binding : ∀ installation ∈ installations,
      installation.use.enabled = installation.active :=
    fun installation member => (facts installation member).1
  have configured : ∀ installation ∈ installations,
      (installation.use.publicInternet = true ∨
        (installation.use.objectiveSelected = true ∧
          installation.use.externalMACsec = true ∧
          installation.use.outerFirewallAttached = true)) →
        installation.active = true ∧ installation.sender.Valid :=
    fun installation member applicable =>
      ⟨(facts installation member).2.2 applicable, (facts installation member).2.1⟩
  refine ⟨(transec_conditions_from_cover_installations installations binding configured).1,
    binding, ?_⟩
  intro installation member applicable
  exact ⟨(configured installation member applicable).1,
    scheduled_cover_guarantee_from_parameters installation.sender
      (configured installation member applicable).2⟩

end TDN.Requirements.Msc
