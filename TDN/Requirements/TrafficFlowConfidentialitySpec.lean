import TDN.Models.ConstantRateCoverTraffic

namespace TDN.Requirements

structure TransecUse where
  publicInternet : Bool
  externalMACsec : Bool
  outerFirewallAttached : Bool
  objectiveSelected : Bool
  enabled : Bool
  deriving DecidableEq, Repr

def msc_transec_conditions (uses : List TransecUse) : Prop :=
  ∀ use ∈ uses,
    (use.publicInternet = true → use.enabled = true) ∧
    (use.objectiveSelected = true → use.externalMACsec = true →
      use.outerFirewallAttached = true → use.enabled = true)

def ScheduledCoverGuarantee (config : CoverTraffic.Config) : Prop :=
  config.Valid ∧
  ∀ firstDeadline actions finish,
    (CoverTraffic.system config).MTr (CoverTraffic.initial firstDeadline) actions finish →
      CoverTraffic.Safe config finish

theorem scheduled_cover_guarantee_from_parameters (config : CoverTraffic.Config)
    (checked : config.Valid) : ScheduledCoverGuarantee config :=
  ⟨checked, fun _ _ _ run =>
    CoverTraffic.all_traces_have_bounded_queues_and_fixed_records checked run⟩

structure CoverInstallation where
  device : String
  use : TransecUse
  sender : CoverTraffic.Config
  active : Bool
  deriving DecidableEq, Repr

theorem transec_conditions_from_cover_installations (installations : List CoverInstallation)
    (binding : ∀ i ∈ installations, i.use.enabled = i.active)
    (checked : ∀ i ∈ installations,
      (i.use.publicInternet = true ∨
        (i.use.objectiveSelected = true ∧ i.use.externalMACsec = true ∧
          i.use.outerFirewallAttached = true)) → i.active = true ∧ i.sender.Valid) :
    msc_transec_conditions (installations.map CoverInstallation.use) ∧
    ∀ i ∈ installations,
      (i.use.publicInternet = true ∨
        (i.use.objectiveSelected = true ∧ i.use.externalMACsec = true ∧
          i.use.outerFirewallAttached = true)) → ScheduledCoverGuarantee i.sender := by
  constructor
  · intro use member
    obtain ⟨i, present, same⟩ := List.mem_map.mp member
    subst use
    constructor
    · intro internet
      exact (binding i present).trans (checked i present (Or.inl internet)).1
    · intro objective macsec firewall
      exact (binding i present).trans
        (checked i present (Or.inr ⟨objective, macsec, firewall⟩)).1
  · intro i present applicable
    exact scheduled_cover_guarantee_from_parameters i.sender (checked i present applicable).2

end TDN.Requirements
